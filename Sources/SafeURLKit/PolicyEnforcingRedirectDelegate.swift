//
//  PolicyEnforcingRedirectDelegate.swift
//  SafeURLKit
//
//  Re-checking the policy on every redirect hop.
//
//  Validating the URL a caller supplied and then following redirects unchecked is the most
//  common way a correct string check ends up not protecting anything: the attacker gives a
//  URL that passes, and the server they control answers `302 Location: http://169.254.169.254/`.
//  OWASP calls out revalidating redirects for exactly this reason, and it is the one part
//  of the resolve-then-connect defence that `URLSession` does let a caller implement.
//

import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// A `URLSessionTaskDelegate` that applies a ``URLPolicy`` to every redirect hop, and
/// cancels the redirect when a hop fails.
///
/// ```swift
/// let policy = URLPolicy.publicHTTPS
/// let validated = try policy.validate(urlString)
/// let delegate = PolicyEnforcingRedirectDelegate(policy: policy)
/// let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
/// let (data, response) = try await session.data(from: validated.url)
/// ```
///
/// Refusing a redirect does not fail the task: `URLSession` returns the redirect response
/// itself, so the caller sees a 3xx rather than an error. Check the status code, or use
/// ``onRejection`` to observe refusals.
///
/// - Note: Retain the delegate for the session's lifetime. `URLSession` holds a strong
///   reference to its delegate until the session is invalidated, so also call
///   `finishTasksAndInvalidate()` when done, as with any delegate-based session.
public final class PolicyEnforcingRedirectDelegate: NSObject, URLSessionTaskDelegate,
    @unchecked Sendable {
    /// The policy applied to each redirect target.
    public let policy: URLPolicy

    /// Called when a redirect is refused, with the rejected URL and the reason.
    ///
    /// Useful for logging, since the refusal is otherwise invisible - the caller just sees
    /// the 3xx response. Called on whichever queue `URLSession` delivers delegate messages
    /// on, so it must be safe to call from any thread.
    public let onRejection: (@Sendable (URL, URLValidationError) -> Void)?

    /// Header fields removed when a redirect changes origin, compared case-insensitively.
    /// Pass an empty set only when the caller deliberately permits credential forwarding.
    public let sensitiveHeaderFields: Set<String>

    /// Create a delegate.
    ///
    /// - Parameters:
    ///   - policy: The policy to apply to each redirect target. Usually the same policy the
    ///     original URL was validated against.
    ///   - onRejection: An optional observer for refused redirects.
    ///   - sensitiveHeaderFields: Fields to strip on cross-origin redirects. Names are
    ///     compared case-insensitively.
    public init(
        policy: URLPolicy,
        onRejection: (@Sendable (URL, URLValidationError) -> Void)? = nil,
        sensitiveHeaderFields: Set<String> = [
            "authorization", "proxy-authorization", "cookie", "cookie2", "api-key",
            "x-api-key", "x-auth-token"
        ]
    ) {
        self.policy = policy
        self.onRejection = onRejection
        self.sensitiveHeaderFields = Set(sensitiveHeaderFields.map(\.lowercasedASCII))
        super.init()
    }

    /// The `@unchecked Sendable` conformance is sound because all stored properties are
    /// immutable `let`s of `Sendable` type; the annotation is only needed because `NSObject`
    /// is not itself `Sendable`.
    public func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url else {
            completionHandler(nil)
            return
        }
        do {
            let validated = try validateRedirect(response: response, generatedURL: url)
            guard validated.url.absoluteString == url.absoluteString else {
                throw URLValidationError.parserDisagreement(
                    safeURLKit: validated.url.absoluteString,
                    foundation: url.absoluteString
                )
            }
            completionHandler(sanitized(request, redirectingFrom: response.url))
        } catch let error as URLValidationError {
            onRejection?(url, error)
            completionHandler(nil)
        } catch {
            onRejection?(
                url,
                .malformedURL(reason: "unexpected redirect validation failure: \(error)")
            )
            completionHandler(nil)
        }
    }

    private func validateRedirect(
        response: HTTPURLResponse,
        generatedURL: URL
    ) throws(URLValidationError) -> ValidatedURL {
        guard let location = response.value(forHTTPHeaderField: "Location") else {
            throw .malformedURL(reason: "the redirect response has no Location header")
        }

        // Absolute and relative Location values both get the ambiguous-character pre-scan:
        // otherwise an absolute Location could carry a backslash or control that relative
        // ones would have refused, creating an asymmetric bypass.
        if let scalar = location.unicodeScalars.first(where: Self.isAmbiguousInLocation) {
            throw .malformedURL(
                reason: "the raw Location header contains ambiguous character \(Character(scalar).debugDescription)"
            )
        }

        if Self.isAbsolute(location) {
            return try policy.validate(location)
        }

        guard
            let base = response.url,
            let resolved = URL(string: location, relativeTo: base)?.absoluteURL
        else {
            throw .malformedURL(reason: "the relative Location header cannot be resolved")
        }

        let validated = try policy.validate(resolved.absoluteString)
        guard resolved.absoluteString == generatedURL.absoluteString else {
            throw .parserDisagreement(
                safeURLKit: resolved.absoluteString,
                foundation: generatedURL.absoluteString
            )
        }
        return validated
    }

    private static func isAbsolute(_ location: String) -> Bool {
        guard let colon = location.firstIndex(of: ":") else { return false }
        let firstDelimiter = location.firstIndex { "/?#".contains($0) }
        return firstDelimiter.map { colon < $0 } ?? true
    }

    private static func isAmbiguousInLocation(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "\\" || scalar == " " || scalar.isC0Control
            || (0x7F ... 0x9F).contains(scalar.value)
            || scalar.properties.generalCategory == .format
    }

    private func sanitized(_ request: URLRequest, redirectingFrom source: URL?) -> URLRequest {
        guard
            let source,
            let target = request.url,
            !Self.sameOrigin(source, target)
        else {
            return request
        }

        var result = request
        for name in request.allHTTPHeaderFields.map({ Array($0.keys) }) ?? [] where
            sensitiveHeaderFields.contains(name.lowercasedASCII) {
            result.setValue(nil, forHTTPHeaderField: name)
        }
        return result
    }

    private static func sameOrigin(_ lhs: URL, _ rhs: URL) -> Bool {
        guard
            let leftScheme = lhs.scheme?.lowercasedASCII,
            let rightScheme = rhs.scheme?.lowercasedASCII,
            let leftHost = lhs.host?.lowercasedASCII,
            let rightHost = rhs.host?.lowercasedASCII
        else {
            return false
        }

        let leftPort = lhs.port ?? URLPolicy.defaultPort(forScheme: leftScheme)
        let rightPort = rhs.port ?? URLPolicy.defaultPort(forScheme: rightScheme)
        return leftScheme == rightScheme && leftHost == rightHost && leftPort == rightPort
    }
}

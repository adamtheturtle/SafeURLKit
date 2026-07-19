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

    /// Create a delegate.
    ///
    /// - Parameters:
    ///   - policy: The policy to apply to each redirect target. Usually the same policy the
    ///     original URL was validated against.
    ///   - onRejection: An optional observer for refused redirects.
    public init(
        policy: URLPolicy,
        onRejection: (@Sendable (URL, URLValidationError) -> Void)? = nil
    ) {
        self.policy = policy
        self.onRejection = onRejection
        super.init()
    }

    /// The `@unchecked Sendable` conformance is sound because both stored properties are
    /// immutable `let`s of `Sendable` type; the annotation is only needed because `NSObject`
    /// is not itself `Sendable`.
    public func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url else {
            completionHandler(nil)
            return
        }
        do {
            _ = try policy.validate(url)
            completionHandler(request)
        } catch {
            onRejection?(url, error)
            completionHandler(nil)
        }
    }
}

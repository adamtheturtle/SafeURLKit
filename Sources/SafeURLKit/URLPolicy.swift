//
//  URLPolicy.swift
//  SafeURLKit
//
//  The policy type, and the validation that applies it.
//
//  Everything in this package exists to make this one function trustworthy. The shape is
//  taken from the OWASP SSRF prevention guidance and from doyensec/safeurl: a value
//  describing what is acceptable, kept separate from the transport, so a call site states
//  its policy in one readable place and the mechanism is shared and tested once.
//
//  Defaults are the strict end of every axis. A call site that needs to allow an IP
//  literal, a plaintext scheme, or a non-standard port has to say so, which turns each
//  loosening into a visible decision in a diff rather than an omission.
//

import Foundation

/// Which ports a URL may use.
public enum PortRule: Sendable, Hashable {
    /// Only the scheme's default port, whether written explicitly or left out. This is the
    /// strict default: an allowed host reached on an unexpected port is usually a different
    /// service than the one that was approved.
    case defaultForScheme
    /// Any port. Combine with an origin allow-list rather than using it alone.
    case any
    /// Only these ports, in addition to nothing else. Include the scheme's default port
    /// explicitly if it should still be allowed.
    case allowed(Set<Int>)
}

/// A description of which URLs are acceptable, applied by ``validate(_:)-(String)``.
///
/// ## Scope
///
/// This validates a URL *string*. It cannot address DNS rebinding: a name that passes the
/// check can resolve to `127.0.0.1` a moment later, and `URLSession` exposes no hook
/// between resolution and connection at which the resolved address could be re-checked.
/// The mitigations that do work live at other layers - resolving first and connecting to a
/// vetted address (as `ssrf_filter` does in Ruby), or an egress proxy such as Smokescreen -
/// and neither is buildable on `URLSession` alone. What this package does cover is the
/// string-level half: exotic address spellings, origin confusion, and - via
/// ``PolicyEnforcingRedirectDelegate`` - re-checking every redirect hop, which is where
/// a string check most often gets bypassed in practice.
///
/// ## Example
///
/// ```swift
/// let policy = URLPolicy(
///     allowedSchemes: ["https"],
///     allowedOrigins: [.hostSuffix("coderpad.io")],
///     allowsQuery: true
/// )
/// let validated = try policy.validate(urlString)
/// ```
public struct URLPolicy: Sendable, Hashable {
    /// The permitted schemes, ASCII-lowercased. Defaults to `["https"]`.
    public var allowedSchemes: Set<String> {
        get { normalizedAllowedSchemes }
        set { normalizedAllowedSchemes = Set(newValue.map(\.lowercasedASCII)) }
    }

    private var normalizedAllowedSchemes: Set<String>

    /// The permitted origins, or `nil` to accept any host that passes the other checks.
    ///
    /// A URL passes if it matches any rule. `nil` and `[]` are meaningfully different:
    /// `nil` means "no host restriction", `[]` means "no host is acceptable" and rejects
    /// everything, so a configuration that produced an empty list fails closed.
    public var allowedOrigins: [OriginRule]?

    /// Which ports are permitted. Defaults to ``PortRule/defaultForScheme``.
    ///
    /// - Important: This is checked *before* ``allowedOrigins``, and the two are not
    ///   combined. An ``OriginRule/origin(scheme:host:port:)`` naming a non-default port
    ///   therefore needs a port rule that admits that port as well, or nothing will match:
    ///
    ///   ```swift
    ///   URLPolicy(
    ///       allowedOrigins: [.origin(scheme: "https", host: .domain("a.example"), port: 8443)],
    ///       portRule: .allowed([8443])  // without this, everything is rejected
    ///   )
    ///   ```
    ///
    ///   They are kept separate rather than inferred so that a policy states its port
    ///   surface in one place, instead of it being an emergent property of the origin list.
    public var portRule: PortRule

    /// Whether the URL may embed a username or password. Defaults to `false`.
    ///
    /// `https://trusted.com@evil.com/` is a request to `evil.com`, and reads to a human as
    /// a request to `trusted.com`. Since a URL that needs credentials in it is vanishingly
    /// rare outside that trick, rejecting them is both safe and cheap.
    public var allowsCredentials: Bool

    /// Whether the URL may carry a fragment. Defaults to `false`.
    ///
    /// A fragment is never sent to the server, so its only effect on a fetched URL is to
    /// change what a human reading it believes the URL points at.
    public var allowsFragment: Bool

    /// Whether the URL may carry a query. Defaults to `true`, since most real endpoints
    /// need one.
    public var allowsQuery: Bool

    /// Whether the host may be an IP literal rather than a name. Defaults to `false`.
    public var allowsIPLiteralHosts: Bool

    /// Whether the host may fall under a reserved domain suffix such as `localhost`,
    /// `.local`, or `.internal`. Defaults to `false`. See ``SpecialUseDomains``.
    public var allowsSpecialUseHostNames: Bool

    /// Whether an IP-literal host may be in a reserved range - loopback, RFC 1918, the
    /// link-local space holding the cloud metadata endpoint, and the rest. Defaults to
    /// `false`. See ``SpecialPurposeAddresses``.
    ///
    /// Only meaningful alongside ``allowsIPLiteralHosts``, since otherwise no literal gets
    /// this far.
    public var allowsSpecialPurposeAddresses: Bool

    /// The greatest acceptable UTF-8 byte count for the URL string, or `nil` for no
    /// limit. Defaults to 2048, the conventional interoperable ceiling.
    public var maximumLength: Int?

    /// The greatest number of non-empty path segments accepted, or `nil` for no limit.
    /// Defaults to 256 so disabling ``maximumLength`` does not also permit structurally
    /// unbounded paths.
    public var maximumPathSegments: Int?

    /// Create a policy. Every parameter defaults to its strict setting except
    /// ``allowsQuery``.
    public init(
        allowedSchemes: Set<String> = ["https"],
        allowedOrigins: [OriginRule]? = nil,
        portRule: PortRule = .defaultForScheme,
        allowsCredentials: Bool = false,
        allowsFragment: Bool = false,
        allowsQuery: Bool = true,
        allowsIPLiteralHosts: Bool = false,
        allowsSpecialUseHostNames: Bool = false,
        allowsSpecialPurposeAddresses: Bool = false,
        maximumLength: Int? = 2048,
        maximumPathSegments: Int? = 256
    ) {
        normalizedAllowedSchemes = Set(allowedSchemes.map(\.lowercasedASCII))
        self.allowedOrigins = allowedOrigins
        self.portRule = portRule
        self.allowsCredentials = allowsCredentials
        self.allowsFragment = allowsFragment
        self.allowsQuery = allowsQuery
        self.allowsIPLiteralHosts = allowsIPLiteralHosts
        self.allowsSpecialUseHostNames = allowsSpecialUseHostNames
        self.allowsSpecialPurposeAddresses = allowsSpecialPurposeAddresses
        self.maximumLength = maximumLength
        self.maximumPathSegments = maximumPathSegments
    }
}

// MARK: - Presets

extension URLPolicy {
    /// HTTPS-only, on port 443, to any public named host: no credentials, no fragment, no
    /// IP literals, no reserved names or addresses.
    ///
    /// A sensible starting point for fetching a URL a user typed. Add
    /// ``allowedOrigins`` whenever the set of acceptable hosts is actually known, since an
    /// allow-list is a stronger property than any amount of block-listing.
    public static let publicHTTPS = URLPolicy()

    /// HTTPS-only to the given origins, otherwise as strict as ``publicHTTPS``.
    ///
    /// - Parameter origins: The acceptable origins. An empty array rejects everything.
    public static func https(origins: [OriginRule]) -> URLPolicy {
        URLPolicy(allowedOrigins: origins)
    }
}

// MARK: - Validation

extension URLPolicy {
    /// The default port for a scheme, or `nil` for schemes with no default.
    public static func defaultPort(forScheme scheme: String) -> Int? {
        switch scheme.lowercasedASCII {
        case "http", "ws": 80
        case "https", "wss": 443
        case "ftp": 21
        default: nil
        }
    }

    /// Validate a URL string against this policy.
    ///
    /// Prefer this over ``validate(_:)-(URL)`` when the URL arrives as text, because it
    /// checks the text that was actually written rather than a `URL` that has already
    /// normalized some of it away.
    ///
    /// - Parameter urlString: The URL as written.
    /// - Returns: A ``ValidatedURL`` carrying the parsed host, effective port, and a `URL`
    ///   safe to hand to `URLSession`.
    /// - Throws: A ``URLValidationError`` naming the first check that failed.
    public func validate(_ urlString: String) throws(URLValidationError) -> ValidatedURL {
        if let maximumLength {
            let byteCount = urlString.utf8.count
            if byteCount > maximumLength {
                throw .tooLong(length: byteCount, limit: maximumLength)
            }
        }

        let parsed: ParsedURLString
        do {
            parsed = try ParsedURLString.parse(urlString)
        } catch {
            throw .malformedURL(reason: error.description)
        }

        if let maximumPathSegments {
            let count = parsed.path.split(separator: "/", omittingEmptySubsequences: true).count
            if count > maximumPathSegments {
                throw .tooManyPathSegments(count: count, limit: maximumPathSegments)
            }
        }

        guard allowedSchemes.contains(parsed.scheme) else {
            throw .disallowedScheme(parsed.scheme)
        }
        if !allowsCredentials, let userinfo = parsed.userinfo, !userinfo.isEmpty {
            throw .credentialsPresent
        }
        if !allowsQuery {
            if parsed.query != nil {
                throw .queryPresent
            }
            if let fragment = parsed.fragment, fragment.contains("?") {
                throw .queryPresent
            }
        }
        if !allowsFragment, let fragment = parsed.fragment, !fragment.isEmpty {
            throw .fragmentPresent
        }

        let host: URLHost
        do {
            host = try URLHost.parse(parsed.hostText)
        } catch {
            throw .invalidHost(error)
        }

        try checkHost(host)

        // A scheme with no default port and no port written names no destination port at
        // all, so there is nothing a port rule could approve. Reject rather than let a
        // placeholder port stand in for one - only reachable via a custom allowed scheme.
        guard let port = parsed.port ?? Self.defaultPort(forScheme: parsed.scheme) else {
            throw .malformedURL(
                reason: "the scheme \(parsed.scheme.debugDescription) has no default port "
                    + "and the URL does not give one"
            )
        }

        // Port 0 is reserved and never a usable destination; reject it under every port
        // rule so `.any` cannot accidentally admit it.
        if port == 0 {
            throw .disallowedPort(0)
        }

        switch portRule {
        case .defaultForScheme:
            guard port == Self.defaultPort(forScheme: parsed.scheme) else {
                throw .disallowedPort(port)
            }
        case .any:
            break
        case let .allowed(ports):
            guard ports.contains(port) else {
                throw .disallowedPort(port)
            }
        }

        if let allowedOrigins {
            guard
                allowedOrigins.contains(where: {
                    $0.matches(scheme: parsed.scheme, host: host, port: port)
                })
            else {
                throw .originNotAllowed(origin: "\(parsed.scheme)://\(host):\(port)")
            }
        }

        // Last, because it is the only check that depends on Foundation agreeing with us
        // and it is the most useful failure to report against a URL that is otherwise fine.
        let url = try crossCheckedURL(urlString, scheme: parsed.scheme, host: host, port: parsed.port)

        return ValidatedURL(url: url, scheme: parsed.scheme, host: host, port: port)
    }

    /// Validate a `URL` against this policy.
    ///
    /// - Parameter url: The URL to check. Relative URLs and other authority-less values are
    ///   rejected as malformed before any string normalization can hide that fact.
    /// - Returns: A ``ValidatedURL``.
    /// - Throws: A ``URLValidationError`` naming the first check that failed.
    public func validate(_ url: URL) throws(URLValidationError) -> ValidatedURL {
        guard url.scheme != nil, url.host != nil else {
            throw .malformedURL(reason: "relative URLs cannot be validated")
        }
        return try validate(url.absoluteString)
    }

    /// Whether `urlString` satisfies this policy, discarding the reason it does not.
    public func allows(_ urlString: String) -> Bool {
        (try? validate(urlString)) != nil
    }

    /// Whether `url` satisfies this policy, discarding the reason it does not.
    public func allows(_ url: URL) -> Bool {
        (try? validate(url)) != nil
    }

    /// Re-check an address obtained from DNS (or another resolver) against this policy's
    /// IP-literal and reserved-address rules.
    ///
    /// String validation alone cannot stop DNS rebinding: a name that passes
    /// ``validate(_:)-(String)`` can later resolve to `127.0.0.1`. Call this with each
    /// resolved address *before* connecting, and refuse the request if it throws.
    ///
    /// - Parameter address: A resolved IPv4 address.
    /// - Throws: ``URLValidationError/specialPurposeAddress(_:)`` or
    ///   ``URLValidationError/ipLiteralHost(_:)`` when the address is not permitted.
    public func validate(resolvedAddress address: IPv4Address) throws(URLValidationError) {
        try checkHost(.ipv4(address))
    }

    /// Re-check a resolved IPv6 address against this policy.
    ///
    /// - Parameter address: A resolved IPv6 address.
    /// - Throws: ``URLValidationError/specialPurposeAddress(_:)`` or
    ///   ``URLValidationError/ipLiteralHost(_:)`` when the address is not permitted.
    public func validate(resolvedAddress address: IPv6Address) throws(URLValidationError) {
        try checkHost(.ipv6(address))
    }

    /// Re-check a resolved host against this policy's host rules.
    ///
    /// - Parameter host: Typically an ``URLHost/ipv4(_:)`` or ``URLHost/ipv6(_:)`` produced
    ///   from DNS results.
    /// - Throws: A ``URLValidationError`` when the host is not permitted.
    public func validate(resolvedHost host: URLHost) throws(URLValidationError) {
        try checkHost(host)
    }

    /// The host and reserved-range checks, which are shared with redirect revalidation.
    /// The reserved-address check runs before the blanket IP-literal check so that the more
    /// specific reason is the one reported. Both reject `https://169.254.169.254/` under the
    /// default policy, but "reserved address: link-local / cloud metadata" tells whoever
    /// reads the log that they are looking at an SSRF attempt, where "is an IP address
    /// literal" does not.
    func checkHost(_ host: URLHost) throws(URLValidationError) {
        if !allowsSpecialUseHostNames, let suffix = SpecialUseDomains.matches(host) {
            throw .specialUseHostName(host: host.description, suffix: suffix)
        }
        if !allowsSpecialPurposeAddresses, let match = SpecialPurposeAddresses.match(host) {
            throw .specialPurposeAddress(match)
        }
        if !allowsIPLiteralHosts, host.isIPAddress {
            throw .ipLiteralHost(host)
        }
    }

    /// Build the `URL` to return, and confirm Foundation reads the same host and port out
    /// of the string that this package did.
    ///
    /// The check is semantic rather than textual: Foundation's host is run back through
    /// ``URLHost/parse(_:)`` and the two ``URLHost`` values are compared, so `[::1]` versus
    /// `::1` and `0x7f.1` versus `127.0.0.1` are agreements, while a genuinely different
    /// destination is not.
    private func crossCheckedURL(
        _ urlString: String,
        scheme: String,
        host: URLHost,
        port: Int?
    ) throws(URLValidationError) -> URL {
        guard
            let url = URL(string: urlString),
            var components = URLComponents(string: urlString)
        else {
            throw .malformedURL(reason: "Foundation cannot parse the URL")
        }

        // Foundation may preserve scheme casing from the input; normalize so
        // ``ValidatedURL/scheme`` and ``ValidatedURL/url`` agree.
        components.scheme = scheme

        guard let foundationHost = components.percentEncodedHost, !foundationHost.isEmpty else {
            throw .parserDisagreement(safeURLKit: host.description, foundation: "none")
        }

        // Foundation drops the brackets from IPv6 literals in some versions and keeps them
        // in others; put them back so the host parser sees a literal either way.
        let bracketed =
            foundationHost.contains(":") && !foundationHost.hasPrefix("[")
                ? "[\(foundationHost)]"
                : foundationHost

        if let parsedFoundationHost = try? URLHost.parse(bracketed) {
            guard parsedFoundationHost == host else {
                throw .parserDisagreement(
                    safeURLKit: host.description,
                    foundation: parsedFoundationHost.description
                )
            }
        } else {
            // Foundation reports an internationalized host in its *decoded* Unicode form:
            // `xn--e1afmkfd.xn--p1ai` comes back as `пример.рф`, which this package's parser
            // rejects by design. Rather than implement IDNA to undo that, ask Foundation to
            // render our own canonical host and check the two renderings agree. That is the
            // same property - one reading of the host - established through the parser that
            // will actually issue the request.
            guard
                let ourRendering = URLComponents(string: "https://\(host)/")?.percentEncodedHost,
                ourRendering == foundationHost
            else {
                throw .parserDisagreement(safeURLKit: host.description, foundation: foundationHost)
            }
        }
        guard components.port == port else {
            throw .parserDisagreement(
                safeURLKit: port.map(String.init) ?? "default",
                foundation: components.port.map(String.init) ?? "default"
            )
        }

        return components.url ?? url
    }
}

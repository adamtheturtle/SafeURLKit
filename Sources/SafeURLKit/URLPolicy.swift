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
    ///   ``URLPolicy/init`` traps when an exact-origin rule's effective port is incompatible
    ///   with `portRule`, so a deny-all misconfiguration fails at setup rather than at every
    ///   request.
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

    /// Whether an IP-literal host may be in *any* reserved range - loopback, RFC 1918, the
    /// link-local space holding the cloud metadata endpoint, multicast, and the rest.
    /// Defaults to `false`. See ``SpecialPurposeAddresses``.
    ///
    /// Only meaningful alongside ``allowsIPLiteralHosts``, since otherwise no literal gets
    /// this far. Prefer ``permittedSpecialPurposeAddressNames`` when only a subset of the
    /// registry (for example `"loopback"`) should be admitted: flipping this flag to `true`
    /// unlocks the entire IANA table at once.
    public var allowsSpecialPurposeAddresses: Bool

    /// Registry entry names from ``SpecialPurposeAddresses`` that are permitted even when
    /// ``allowsSpecialPurposeAddresses`` is `false`. Empty by default.
    ///
    /// Names are the human-readable strings on each registry entry, such as `"loopback"` or
    /// `"private-use (RFC 1918)"`. Use this to allow a local test server without also
    /// admitting multicast, `0.0.0.0`, or cloud-metadata link-local space.
    public var permittedSpecialPurposeAddressNames: Set<String>

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
        permittedSpecialPurposeAddressNames: Set<String> = [],
        maximumLength: Int? = 2048,
        maximumPathSegments: Int? = 256
    ) {
        if let maximumLength, maximumLength < 1 {
            preconditionFailure(
                "maximumLength must be at least 1, or nil for no limit; 0 rejects every non-empty URL"
            )
        }
        if let maximumPathSegments, maximumPathSegments < 1 {
            preconditionFailure(
                """
                maximumPathSegments must be at least 1, or nil for no limit; 0 rejects every \
                non-empty path
                """
            )
        }
        Self.checkPortRuleCompatible(with: allowedOrigins, portRule: portRule)
        normalizedAllowedSchemes = Set(allowedSchemes.map(\.lowercasedASCII))
        self.allowedOrigins = allowedOrigins
        self.portRule = portRule
        self.allowsCredentials = allowsCredentials
        self.allowsFragment = allowsFragment
        self.allowsQuery = allowsQuery
        self.allowsIPLiteralHosts = allowsIPLiteralHosts
        self.allowsSpecialUseHostNames = allowsSpecialUseHostNames
        self.allowsSpecialPurposeAddresses = allowsSpecialPurposeAddresses
        self.permittedSpecialPurposeAddressNames = permittedSpecialPurposeAddressNames
        self.maximumLength = maximumLength
        self.maximumPathSegments = maximumPathSegments
    }

    /// Trap when an exact-origin rule names a port that ``portRule`` can never admit.
    ///
    /// ``portRule`` and ``allowedOrigins`` are separate checks and both must pass. An
    /// ``OriginRule/origin(scheme:host:port:)`` on port 8443 under ``PortRule/defaultForScheme``
    /// therefore rejects every URL — catch that at configuration time rather than as a
    /// silent deny-all in production.
    private static func checkPortRuleCompatible(
        with origins: [OriginRule]?,
        portRule: PortRule
    ) {
        guard let origins else { return }
        for rule in origins {
            guard case let .origin(scheme, _, port) = rule else { continue }
            let effective = port ?? defaultPort(forScheme: scheme)
            guard let effective else {
                preconditionFailure(
                    """
                    OriginRule.origin(scheme: \(scheme.debugDescription), …) names a scheme \
                    with no default port and no explicit port, so it can never match under \
                    any PortRule; give the origin an explicit port
                    """
                )
            }
            switch portRule {
            case .any:
                break
            case .defaultForScheme:
                guard effective == defaultPort(forScheme: scheme) else {
                    preconditionFailure(
                        """
                        OriginRule.origin(… port: \(effective)) can never match under \
                        portRule: .defaultForScheme; use portRule: .allowed([\(effective)]) \
                        or .any (see URLPolicy.portRule)
                        """
                    )
                }
            case let .allowed(ports):
                guard ports.contains(effective) else {
                    preconditionFailure(
                        """
                        OriginRule.origin(… port: \(effective)) can never match under \
                        portRule: .allowed(\(ports.sorted())); include \(effective) in the \
                        allowed set (see URLPolicy.portRule)
                        """
                    )
                }
            }
        }
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
    /// - Parameter origins: The acceptable origins. Must not be empty; use `nil`
    ///   ``allowedOrigins`` on ``URLPolicy/init`` when no host restriction is intended.
    public static func https(origins: [OriginRule]) -> URLPolicy {
        guard !origins.isEmpty else {
            preconditionFailure(
                """
                URLPolicy.https(origins:) requires at least one origin. Pass allowedOrigins: nil \
                on URLPolicy.init for no host restriction, or allowedOrigins: [] to reject every host.
                """
            )
        }
        return URLPolicy(allowedOrigins: origins)
    }
}

// MARK: - Validation

extension URLPolicy {
    /// The default port for a scheme, or `nil` for schemes with no default.
    ///
    /// This table is independent of ``allowedSchemes``. The default policy permits only
    /// `https`, but `ftp` (and `http` / `ws` / `wss`) still have well-known defaults so a
    /// caller that *does* add those schemes to ``allowedSchemes`` — or that builds an
    /// ``OriginRule/origin(scheme:host:port:)`` — gets the correct effective port without
    /// a second lookup table. Presence here is not permission to use the scheme.
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
            let count = Self.normalizedPathSegmentCount(parsed.path)
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

        let port = try checkedPort(scheme: parsed.scheme, parsedPort: parsed.port)

        try checkHost(host, scheme: parsed.scheme, port: port)

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
        let url = try crossCheckedURL(urlString, host: host, port: parsed.port)

        return ValidatedURL(url: url, scheme: parsed.scheme, host: host, port: port)
    }

    /// Resolve the effective port and enforce ``portRule``, including rejecting port 0.
    /// A scheme with no default port and no written port names no destination, so it fails.
    func checkedPort(scheme: String, parsedPort: Int?) throws(URLValidationError) -> Int {
        let port: Int
        if let parsedPort {
            port = parsedPort
        } else if let defaultPort = Self.defaultPort(forScheme: scheme) {
            port = defaultPort
        } else if case .any = portRule {
            // Custom schemes often omit a port; under `.any`, accept the authority without one.
            port = 0
        } else {
            throw .malformedURL(
                reason: "the scheme \(scheme.debugDescription) has no default port "
                    + "and the URL does not give one"
            )
        }

        // Port 0 is reserved when written explicitly or implied by a known scheme.
        if port == 0, parsedPort != nil || Self.defaultPort(forScheme: scheme) != nil {
            throw .disallowedPort(0)
        }

        switch portRule {
        case .defaultForScheme:
            guard port == Self.defaultPort(forScheme: scheme) else {
                throw .disallowedPort(port)
            }
        case .any:
            break
        case let .allowed(ports):
            guard port == 0 || ports.contains(port) else {
                throw .disallowedPort(port)
            }
        }
        return port
    }

    /// Validate a `URL` against this policy.
    ///
    /// This overload validates Foundation's ``URL/absoluteString``, not whatever text the
    /// caller used to construct `url`. Foundation may have already lowercased the scheme,
    /// decoded or re-encoded percent-escapes, dropped a default port, or otherwise
    /// normalized the value — so the string that is checked can differ from the original
    /// input. Prefer ``validate(_:)-(String)`` when the URL arrives as text and the
    /// as-written form must be what the policy sees.
    ///
    /// - Parameter url: The URL to check. Relative URLs and other authority-less values are
    ///   rejected as malformed before any string normalization can hide that fact.
    /// - Returns: A ``ValidatedURL`` whose ``ValidatedURL/url`` is derived from that
    ///   `absoluteString` path (see ``validate(_:)-(String)``).
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

    /// Count path segments after removing `.` and resolving `..`, matching the logical path
    /// depth rather than raw slash splits.
    static func normalizedPathSegmentCount(_ path: String) -> Int {
        var stack: [Substring] = []
        for segment in path.split(separator: "/", omittingEmptySubsequences: true) {
            if segment == "." {
                continue
            }
            if segment == ".." {
                if !stack.isEmpty {
                    stack.removeLast()
                }
                continue
            }
            stack.append(segment)
        }
        return stack.count
    }

    /// The error `urlString` is rejected with, or `nil` if it passes.
    ///
    /// Prefer this over ``allows(_:)-(String)`` when logging or metrics need the reason a
    /// URL failed.
    public func rejection(for urlString: String) -> URLValidationError? {
        do {
            _ = try validate(urlString)
            return nil
        } catch {
            return error
        }
    }

    /// The error `url` is rejected with, or `nil` if it passes.
    public func rejection(for url: URL) -> URLValidationError? {
        do {
            _ = try validate(url)
            return nil
        } catch {
            return error
        }
    }

    /// Re-check an address obtained from DNS (or another resolver) against this policy's
    /// reserved-address rules.
    ///
    /// String validation alone cannot stop DNS rebinding: a name that passes
    /// ``validate(_:)-(String)`` can later resolve to `127.0.0.1`. Call this with each
    /// resolved address *before* connecting, and refuse the request if it throws.
    ///
    /// Unlike string-level validation, this does **not** apply ``allowsIPLiteralHosts``:
    /// a DNS result is always an address. Only reserved-range (and special-use name) policy
    /// applies here, so public A/AAAA records are accepted under ``publicHTTPS`` without
    /// also permitting IP literals in URL strings.
    ///
    /// - Parameter address: A resolved IPv4 address.
    /// - Throws: ``URLValidationError/specialPurposeAddress(_:)`` when the address is not
    ///   permitted.
    public func validate(resolvedAddress address: IPv4Address) throws(URLValidationError) {
        try checkResolvedHost(.ipv4(address))
    }

    /// Re-check a resolved IPv6 address against this policy's reserved-address rules.
    ///
    /// - Parameter address: A resolved IPv6 address.
    /// - Throws: ``URLValidationError/specialPurposeAddress(_:)`` when the address is not
    ///   permitted.
    public func validate(resolvedAddress address: IPv6Address) throws(URLValidationError) {
        try checkResolvedHost(.ipv6(address))
    }

    /// Re-check a resolved host against this policy's post-DNS host rules.
    ///
    /// - Parameter host: Typically an ``URLHost/ipv4(_:)`` or ``URLHost/ipv6(_:)`` produced
    ///   from DNS results.
    /// - Throws: A ``URLValidationError`` when the host is not permitted.
    public func validate(resolvedHost host: URLHost) throws(URLValidationError) {
        try checkResolvedHost(host)
    }

    /// Validate every address a resolver returned before opening a connection.
    ///
    /// Call this after DNS (or another resolver) with each A/AAAA result. Refuse the request
    /// when any address fails, which closes the DNS-rebinding gap that string validation alone
    /// cannot address.
    ///
    /// - Parameter addresses: Resolved hosts, typically ``URLHost/ipv4(_:)`` or
    ///   ``URLHost/ipv6(_:)`` values.
    /// - Throws: The first ``URLValidationError`` from ``validate(resolvedHost:)``.
    public func validate(resolvedAddresses addresses: [URLHost]) throws(URLValidationError) {
        guard !addresses.isEmpty else {
            throw .malformedURL(reason: "DNS returned no addresses")
        }
        for address in addresses {
            try validate(resolvedHost: address)
        }
    }

    /// The host and reserved-range checks, which are shared with redirect revalidation.
    /// The reserved-address check runs before the blanket IP-literal check so that the more
    /// specific reason is the one reported. Both reject `https://169.254.169.254/` under the
    /// default policy, but "reserved address: link-local / cloud metadata" tells whoever
    /// reads the log that they are looking at an SSRF attempt, where "is an IP address
    /// literal" does not.
    func checkHost(_ host: URLHost) throws(URLValidationError) {
        try checkResolvedHost(host)
        if !allowsIPLiteralHosts, host.isIPAddress {
            throw .ipLiteralHost(host)
        }
    }

    /// Post-DNS host checks: special-use names and reserved addresses only.
    /// Deliberately omits ``allowsIPLiteralHosts`` so a public A/AAAA result is not rejected
    /// merely for being an address.
    func checkResolvedHost(_ host: URLHost) throws(URLValidationError) {
        if !allowsSpecialUseHostNames, let suffix = SpecialUseDomains.matches(host) {
            throw .specialUseHostName(host: host.description, suffix: suffix)
        }
        if let match = SpecialPurposeAddresses.match(host), !permitsSpecialPurpose(match) {
            throw .specialPurposeAddress(match)
        }
    }

    /// Whether a special-purpose match is admitted by ``allowsSpecialPurposeAddresses`` or
    /// ``permittedSpecialPurposeAddressNames``.
    func permitsSpecialPurpose(_ match: SpecialPurposeMatch) -> Bool {
        allowsSpecialPurposeAddresses
            || permittedSpecialPurposeAddressNames.contains(match.name)
    }

    /// Like ``checkHost(_:)``, but skips the special-use host name block when the host is
    /// explicitly named by ``allowedOrigins``: an allow-list entry for `localhost` must be
    /// able to override the reserved-name block, otherwise the entry can never match.
    func checkHost(
        _ host: URLHost,
        scheme: String,
        port: Int
    ) throws(URLValidationError) {
        let explicitlyAllowed = allowedOrigins?.contains {
            $0.matches(scheme: scheme, host: host, port: port)
        } ?? false

        if !allowsSpecialUseHostNames, !explicitlyAllowed, let suffix = SpecialUseDomains.matches(host) {
            throw .specialUseHostName(host: host.description, suffix: suffix)
        }
        if let match = SpecialPurposeAddresses.match(host), !permitsSpecialPurpose(match) {
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
    ///
    /// Foundation's `URL` / `URLComponents` behaviour can differ across OS and toolchain
    /// versions. Disagreement is always a rejection (fail closed): a URL that parses one
    /// way here and another way in the networking stack must not be fetched. CI runs the
    /// same suite on macOS and Linux; treat a new ``URLValidationError/parserDisagreement``
    /// on an upgraded Foundation as a signal to tighten the string rules, not to loosen
    /// this cross-check.
    private func crossCheckedURL(
        _ urlString: String,
        host: URLHost,
        port: Int?
    ) throws(URLValidationError) -> URL {
        guard
            let url = URL(string: urlString),
            let components = URLComponents(string: urlString)
        else {
            throw .malformedURL(reason: "Foundation cannot parse the URL")
        }

        // Do not assign `components.scheme` (or otherwise rebuild from parts): that
        // invalidates Foundation's parse cache and can rewrite percent-encoding, so the
        // returned `URL` would no longer match `URL(string:)` / redirect `newRequest`s.
        // ``ValidatedURL/scheme`` already carries the ASCII-lowercased scheme.

        guard let foundationHost = components.percentEncodedHost, !foundationHost.isEmpty else {
            throw .parserDisagreement(field: "host", safeURLKit: host.description, foundation: "none")
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
                    field: "host",
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
                throw .parserDisagreement(
                    field: "host",
                    safeURLKit: host.description,
                    foundation: foundationHost
                )
            }
        }
        guard components.port == port else {
            throw .parserDisagreement(
                field: "port",
                safeURLKit: port.map(String.init) ?? "default",
                foundation: components.port.map(String.init) ?? "default"
            )
        }

        return url
    }
}

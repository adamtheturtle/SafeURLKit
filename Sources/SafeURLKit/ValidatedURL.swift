//
//  ValidatedURL.swift
//  SafeURLKit
//
//  Proof that a URL passed a policy.
//
//  The type exists so that "this URL was checked" can be a fact the compiler tracks rather
//  than a convention someone has to remember. A function that takes a `ValidatedURL`
//  cannot be handed an unchecked one by accident, which is the failure mode where a new
//  call path is added months later and quietly skips the check.
//

import Foundation

/// A URL that satisfied a ``URLPolicy``, together with what the policy resolved it to.
///
/// Only ``URLPolicy/validate(_:)-(String)`` creates these. Prefer passing this around, and
/// reaching for ``url`` only at the point of use, so that the checked-ness travels with
/// the value.
public struct ValidatedURL: Sendable, Hashable {
    /// The URL, safe to hand to `URLSession` - subject to the redirect and DNS-rebinding
    /// caveats described on ``URLPolicy``.
    public let url: URL

    /// The ASCII-lowercased scheme.
    public let scheme: String

    /// The parsed host. Reserved-range and reserved-name checks were run against this
    /// value, not against the host's textual spelling.
    public let host: URLHost

    /// The effective port, with the scheme's default filled in when none was written.
    public let port: Int

    /// Created only by ``URLPolicy/validate(_:)-(String)``.
    init(url: URL, scheme: String, host: URLHost, port: Int) {
        self.url = url
        self.scheme = scheme
        self.host = host
        self.port = port
    }

    /// The canonical origin in RFC 6454 serialization: default ports are omitted, and IPv6
    /// literals keep their square brackets.
    public var origin: String {
        let hostText = originHost
        if port == URLPolicy.defaultPort(forScheme: scheme) {
            return "\(scheme)://\(hostText)"
        }
        return "\(scheme)://\(hostText):\(port)"
    }

    /// The host component of ``origin``, serialized the way browsers emit the Origin header.
    private var originHost: String {
        switch host {
        case .domain, .ipv4:
            host.description
        case let .ipv6(address):
            "[\(address)]"
        }
    }
}

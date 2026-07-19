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

    /// The canonical origin, with the port always written out: `https://example.com:443`.
    ///
    /// Always including the port makes two origins comparable as strings without anyone
    /// having to remember which schemes have which defaults - the omission that
    /// same-host-different-port bugs are made of.
    public var origin: String {
        "\(scheme)://\(host):\(port)"
    }
}

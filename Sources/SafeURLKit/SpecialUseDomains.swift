//
//  SpecialUseDomains.swift
//  SafeURLKit
//
//  Domain names that never denote a public internet host.
//
//  These are the name-shaped counterpart to the reserved address ranges: `localhost` and
//  `metadata.google.internal` are not IP literals, so an IP-literal check does not see
//  them, and they resolve to exactly the destinations an SSRF check exists to keep a
//  request away from.
//
//  Source: IANA Special-Use Domain Names registry (see ``registryLastChecked``), plus
//  conservative vendor-conventional suffixes such as `.internal` used by cloud metadata
//  services. To refresh: compare IANA's CSV registry, strip trailing root dots, update
//  ``suffixes``, update the fixture in ReservedAddressTests, and bump ``registryLastChecked``.
//  https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.csv
//

import Foundation

/// Domain suffixes that are reserved, locally resolved, or otherwise never public.
public enum SpecialUseDomains {
    /// The calendar date on which ``suffixes`` was last checked against the IANA
    /// Special-Use Domain Names registry, as `yyyy-MM-dd` (UTC).
    ///
    /// Bump this whenever the table is refreshed. There is no automatic fetch at runtime —
    /// stale registries are a release-engineering concern — but exposing the date makes
    /// drift visible to callers and to the suite that pins it.
    public static let registryLastChecked = "2026-05-22"

    /// The reserved suffixes.
    ///
    /// Each entry matches the name itself and any subdomain of it, anchored at a label
    /// boundary - see ``matches(_:)``. `.local` is here because multicast DNS resolves it
    /// to whatever is on the local link; `.internal` because that is where cloud providers
    /// put metadata services; `.onion` because resolving it either fails or leaves through
    /// a proxy the caller did not choose.
    public static let suffixes: [String] = [
        "localhost",
        "local",
        "internal",
        "intranet",
        "private",
        "corp",
        "home",
        "lan",
        "home.arpa",
        "in-addr.arpa",
        "ip6.arpa",
        "6tisch.arpa",
        "eap.arpa",
        "eap-noob.arpa",
        "ipv4only.arpa",
        "resolver.arpa",
        "service.arpa",
        "test",
        "invalid",
        "example",
        "example.com",
        "example.net",
        "example.org",
        "onion",
        "alt",
        // DNS rebinding / "point this name at any IP" services. A hostname under these
        // suffixes is a public DNS name that resolves to whatever address the registrant
        // chose, including loopback and link-local, so string-level validation alone cannot
        // treat it as a safe public host.
        "nip.io",
        "sslip.io",
        "xip.io",
        "localtest.me",
        "vcap.me",
        "lvh.me"
    ]

    /// The reserved suffix `host` falls under, or `nil` if it is an ordinary public name.
    ///
    /// Matching is anchored at a label boundary, so `notlocalhost.com` and `mylocal` do not
    /// match. Only ``URLHost/domain(_:)`` can match; IP literals are the other check's job.
    public static func matches(_ host: URLHost) -> String? {
        guard case let .domain(name) = host else {
            return nil
        }
        return suffixes.first { name == $0 || name.hasSuffix(".\($0)") }
    }
}

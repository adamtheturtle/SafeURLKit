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
//  Source: IANA Special-Use Domain Names registry, last checked 2026-05-22, plus
//  conservative vendor-conventional suffixes such as `.internal` used by cloud metadata
//  services. To refresh this table, compare IANA's CSV registry, strip its trailing root
//  dots, update the registry fixture in ReservedAddressTests, and update this date.
//  https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.csv
//

import Foundation

/// Domain suffixes that are reserved, locally resolved, or otherwise never public.
public enum SpecialUseDomains {
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
        "alt"
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

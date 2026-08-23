//
//  ReservedAddressTests.swift
//  SafeURLKitTests
//
//  The IANA registry tables, and the reserved-name list.
//
//  The range coverage below is adapted from the regression suites of frenchbread/private-ip
//  and JordanMilne/Advocate, which between them cover both the ranges themselves and the
//  encodings that were historically used to reach them.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("Reserved IPv4 ranges")
struct ReservedIPv4RangeTests {
    @Test(
        "Reserved addresses are matched and named",
        arguments: [
            ("0.0.0.0", "this network"),
            ("0.255.255.255", "this network"),
            ("10.0.0.1", "private-use (RFC 1918)"),
            ("10.255.255.255", "private-use (RFC 1918)"),
            ("100.64.0.1", "shared address space / CGNAT"),
            ("100.127.255.255", "shared address space / CGNAT"),
            ("127.0.0.1", "loopback"),
            ("127.255.255.254", "loopback"),
            ("169.254.169.254", "link-local / cloud metadata"),
            ("169.254.0.1", "link-local / cloud metadata"),
            ("172.16.0.1", "private-use (RFC 1918)"),
            ("172.31.255.255", "private-use (RFC 1918)"),
            ("192.0.0.1", "IETF protocol assignments"),
            ("192.0.2.1", "documentation (TEST-NET-1)"),
            ("192.168.0.1", "private-use (RFC 1918)"),
            ("192.168.255.255", "private-use (RFC 1918)"),
            ("198.18.0.1", "benchmarking"),
            ("198.51.100.1", "documentation (TEST-NET-2)"),
            ("203.0.113.1", "documentation (TEST-NET-3)"),
            ("224.0.0.1", "multicast"),
            ("239.255.255.255", "multicast"),
            ("240.0.0.1", "reserved, including limited broadcast"),
            ("255.255.255.255", "reserved, including limited broadcast")
        ]
    )
    func reserved(_ input: String, _ name: String) throws {
        let match = try #require(SpecialPurposeAddresses.match(IPv4Address.parse(input)))
        #expect(match.name == name)
    }

    @Test(
        "Addresses just outside each range are public",
        arguments: [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.20.0.0",
            "223.255.255.255",
            "8.8.8.8",
            "93.184.216.34"
        ]
    )
    func publicAddresses(_ input: String) throws {
        #expect(try SpecialPurposeAddresses.match(IPv4Address.parse(input)) == nil)
    }

    @Test("Reserved ranges are matched through their exotic spellings too")
    func exoticSpellings() throws {
        // This is the whole point of parsing before matching: none of these is a string a
        // block list would recognise, and all three reach the metadata endpoint.
        for spelling in ["0xa9fea9fe", "2852039166", "0251.0376.0251.0376"] {
            let match = try #require(SpecialPurposeAddresses.match(URLHost.parse(spelling)))
            #expect(match.name == "link-local / cloud metadata")
        }
    }

    @Test("Prefix masking ignores host bits set in the base address")
    func prefixMasking() throws {
        let prefix = try #require(IPv4Prefix(IPv4Address(10, 1, 2, 3), 8))
        #expect(prefix.description == "10.0.0.0/8")
        #expect(prefix.contains(IPv4Address(10, 255, 255, 255)))
        #expect(!prefix.contains(IPv4Address(11, 0, 0, 0)))
    }

    @Test("A zero-length prefix contains everything and a full-length one contains itself")
    func prefixEdges() throws {
        let zero = try #require(IPv4Prefix(IPv4Address(0, 0, 0, 0), 0))
        #expect(zero.contains(IPv4Address(8, 8, 8, 8)))
        let host = try #require(IPv4Prefix(IPv4Address(8, 8, 8, 8), 32))
        #expect(host.contains(IPv4Address(8, 8, 8, 8)))
        #expect(!host.contains(IPv4Address(8, 8, 8, 9)))
    }

    @Test("Out-of-range prefix lengths fail without trapping", arguments: [33, 255])
    func invalidPrefixLengths(_ bits: UInt8) {
        #expect(IPv4Prefix(IPv4Address(10, 0, 0, 0), bits) == nil)
    }
}

@Suite("Reserved IPv6 ranges")
struct ReservedIPv6RangeTests {
    @Test(
        "Reserved addresses are matched and named",
        arguments: [
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("fc00::1", "unique-local"),
            ("fd12:3456::1", "unique-local"),
            ("fe80::1", "link-local"),
            ("febf:ffff::1", "link-local"),
            ("ff02::1", "multicast"),
            ("2001:db8::1", "documentation"),
            ("100::1", "discard-only"),
            ("3fff::1", "documentation"),
            ("5f00::1", "segment routing (SRv6) SIDs"),
            // Covered by the 2001::/23 registration rather than by an entry of their own:
            // PCP anycast, AMT, and AS112-v6 all live inside it.
            ("2001:1::1", "IETF protocol assignments"),
            ("2001:1::2", "IETF protocol assignments"),
            ("2001:3::1", "IETF protocol assignments"),
            ("2001:4:112::1", "IETF protocol assignments"),
            // The IPv6 counterpart of 192.175.48.0/24.
            ("2620:4f:8000::1", "direct delegation AS112 service")
        ]
    )
    func reserved(_ input: String, _ name: String) throws {
        let match = try #require(SpecialPurposeAddresses.match(IPv6Address.parse(input)))
        #expect(match.name == name)
    }

    @Test(
        "An IPv4 destination smuggled inside an IPv6 form is reported as that IPv4 match",
        arguments: [
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::169.254.169.254",
            "2002:a9fe:a9fe::",
            "2001:0:a9fe:a9fe::"
        ]
    )
    func smuggled(_ input: String) throws {
        let match = try #require(SpecialPurposeAddresses.match(IPv6Address.parse(input)))
        #expect(match.name == "link-local / cloud metadata")
        guard case let .ipv4(_, address) = match else {
            Issue.record("expected an IPv4 match, got \(match)")
            return
        }
        #expect(address == IPv4Address(169, 254, 169, 254))
    }

    @Test("A mapped address with a public payload unwraps to that public IPv4 destination")
    func mappedPublicPayload() throws {
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("::ffff:8.8.8.8")) == nil)
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("::ffff:93.184.216.34")) == nil)

        let policy = URLPolicy(allowsIPLiteralHosts: true)
        #expect(policy.allows("https://[::ffff:8.8.8.8]/"))
        #expect(!policy.allows("https://[::ffff:127.0.0.1]/"))
    }

    @Test("Ordinary global unicast addresses are public")
    func publicAddresses() throws {
        for input in ["2606:4700::1111", "2a00:1450:4009:81f::200e", "fb00::1"] {
            #expect(try SpecialPurposeAddresses.match(IPv6Address.parse(input)) == nil)
        }
    }

    @Test("A covering registration does not mask its more specific children's names")
    func specificityOrdering() throws {
        // 2001::/23 covers Teredo and the benchmarking range, but the narrower name is the
        // useful one, so the lookup must report it.
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("2001:0::1"))?.name
            == "Teredo tunnelling")
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("2001:2::1"))?.name
            == "benchmarking")
        // 2001:db8::/32 lies outside 2001::/23 and is a separate entry.
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("2001:db8::1"))?.name
            == "documentation")
        // Just past the /23, and not in any other entry.
        #expect(try SpecialPurposeAddresses.match(IPv6Address.parse("2001:200::1")) == nil)
    }

    @Test("Prefix masking works across piece boundaries")
    func prefixMasking() throws {
        // fc00::/7 splits inside the first piece, and fe80::/10 splits inside it too.
        let uniqueLocal = try #require(IPv6Prefix(IPv6Address.parse("fc00::"), 7))
        #expect(try uniqueLocal.contains(IPv6Address.parse("fdff:ffff::1")))
        #expect(try !uniqueLocal.contains(IPv6Address.parse("fe00::1")))

        let linkLocal = try #require(IPv6Prefix(IPv6Address.parse("fe80::"), 10))
        #expect(try linkLocal.contains(IPv6Address.parse("febf:ffff::1")))
        #expect(try !linkLocal.contains(IPv6Address.parse("fec0::1")))
    }

    @Test("Out-of-range prefix lengths fail without trapping", arguments: [129, 255])
    func invalidPrefixLengths(_ bits: UInt8) throws {
        let address = try IPv6Address.parse("2001:db8::")
        #expect(IPv6Prefix(address, bits) == nil)
    }
}

@Suite("Reserved domain names")
struct ReservedDomainTests {
    @Test(
        "Every current IANA special-use domain is covered",
        arguments: [
            "alt", "6tisch.arpa", "eap.arpa", "eap-noob.arpa", "home.arpa",
            "10.in-addr.arpa", "254.169.in-addr.arpa", "16.172.in-addr.arpa",
            "17.172.in-addr.arpa", "18.172.in-addr.arpa", "19.172.in-addr.arpa",
            "20.172.in-addr.arpa", "21.172.in-addr.arpa", "22.172.in-addr.arpa",
            "23.172.in-addr.arpa", "24.172.in-addr.arpa", "25.172.in-addr.arpa",
            "26.172.in-addr.arpa", "27.172.in-addr.arpa", "28.172.in-addr.arpa",
            "29.172.in-addr.arpa", "30.172.in-addr.arpa", "31.172.in-addr.arpa",
            "170.0.0.192.in-addr.arpa", "171.0.0.192.in-addr.arpa",
            "168.192.in-addr.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa",
            "a.e.f.ip6.arpa", "b.e.f.ip6.arpa", "ipv4only.arpa", "resolver.arpa",
            "service.arpa", "example", "example.com", "example.net", "example.org",
            "invalid", "local", "localhost", "onion", "test"
        ]
    )
    func currentIANARegistry(_ host: String) throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse(host)) != nil)
    }

    @Test(
        "Reserved suffixes match the name itself and any subdomain",
        arguments: [
            ("localhost", "localhost"),
            ("api.localhost", "localhost"),
            ("a.b.localhost", "localhost"),
            ("printer.local", "local"),
            ("metadata.google.internal", "internal"),
            ("db.corp", "corp"),
            ("host.home.arpa", "home.arpa"),
            ("1.0.0.127.in-addr.arpa", "in-addr.arpa"),
            ("something.onion", "onion"),
            ("foo.invalid", "invalid"),
            ("foo.test", "test")
        ]
    )
    func reserved(_ host: String, _ suffix: String) throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse(host)) == suffix)
    }

    @Test(
        "Matching is anchored at a label boundary",
        arguments: [
            "notlocalhost",
            "notlocalhost.com",
            "mylocal",
            "example.notlocal",
            "internalthings.com",
            "localhost.coderpad.io"
        ]
    )
    func notReserved(_ host: String) throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse(host)) == nil)
    }

    @Test("A trailing root dot does not evade a suffix match")
    func trailingDot() throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse("localhost.")) == "localhost")
        #expect(
            try SpecialUseDomains.matches(URLHost.parse("metadata.google.internal.")) == "internal"
        )
    }

    @Test(
        "DNS rebinding wildcard services are treated as reserved host names",
        arguments: [
            ("127.0.0.1.nip.io", "nip.io"),
            ("8.8.8.8.sslip.io", "sslip.io"),
            ("127.0.0.1.xip.io", "xip.io"),
            ("localtest.me", "localtest.me"),
            ("app.vcap.me", "vcap.me"),
            ("foo.lvh.me", "lvh.me")
        ]
    )
    func dnsRebindingServices(_ host: String, _ suffix: String) throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse(host)) == suffix)
        #expect(!URLPolicy.publicHTTPS.allows("https://\(host)/"))
    }

    @Test("IP literals never match a name rule")
    func literals() throws {
        #expect(try SpecialUseDomains.matches(URLHost.parse("127.0.0.1")) == nil)
        #expect(try SpecialUseDomains.matches(URLHost.parse("[::1]")) == nil)
    }
}

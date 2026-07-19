//
//  HostParsingTests.swift
//  SafeURLKitTests
//
//  The host parser as a whole: which spellings become domains, which become addresses,
//  and which are refused.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("Host parsing")
struct HostParsingTests {
    @Test(
        "Ordinary names parse as domains, lowercased",
        arguments: [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("ExAmPlE.CoM", "example.com"),
            ("app.coderpad.io", "app.coderpad.io"),
            ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
            // A single trailing root dot is stripped, so `localhost.` cannot dodge a
            // suffix rule that `localhost` would have hit.
            ("example.com.", "example.com"),
            ("LOCALHOST.", "localhost")
        ]
    )
    func domains(_ input: String, _ expected: String) throws {
        #expect(try URLHost.parse(input) == .domain(expected))
    }

    @Test("Percent-encoding is decoded before anything else looks at the host")
    func percentDecoding() throws {
        #expect(try URLHost.parse("example%2ecom") == .domain("example.com"))
        // `127%2e0%2e0%2e1` must not slip past as a name: after decoding it ends in a
        // number and becomes an address.
        #expect(try URLHost.parse("127%2e0%2e0%2e1") == .ipv4(IPv4Address(127, 0, 0, 1)))
        #expect(try URLHost.parse("%6c%6f%63%61%6c%68%6f%73%74") == .domain("localhost"))
    }

    @Test(
        "Forbidden code points are rejected rather than normalized",
        arguments: ["exam ple.com", "a<b.com", "a>b.com", "a|b.com", "a^b.com", "a\u{0000}b.com"]
    )
    func forbiddenCodePoints(_ input: String) {
        #expect(throws: HostParsingError.self) {
            try URLHost.parse(input)
        }
    }

    @Test("A decoded percent escape that reintroduces a forbidden code point is rejected")
    func decodedForbiddenCodePoint() {
        // `%00` and `%2f` are how a null or a slash gets carried into a host.
        for input in ["example%00.com", "example%2fpath.com", "a%20b.com"] {
            #expect(throws: HostParsingError.self) {
                try URLHost.parse(input)
            }
        }
    }

    @Test(
        "C0 controls and DEL are forbidden in a domain, including via percent-encoding",
        arguments: ["exam%01ple.com", "exam%7fple.com", "a%1fb.example.com", "%08.example.com"]
    )
    func controlCharacters(_ input: String) {
        // The forbidden set is "forbidden host code point, plus C0 controls and U+007F".
        // Percent-decoding runs first, so leaving the control half out would let `%01`
        // decode straight into a domain - and then be handed back as a "validated" host
        // containing a control character.
        #expect(throws: HostParsingError.self) {
            try URLHost.parse(input)
        }
    }

    @Test("A control character cannot be smuggled into an allow-listed suffix")
    func controlCharacterInSuffix() {
        let policy = URLPolicy(allowedOrigins: [.hostSuffix("example.com")])
        #expect(!policy.allows("https://evil.com%01.example.com/"))
    }

    @Test(
        "A CR-LF pair is two forbidden controls, not one harmless grapheme cluster",
        arguments: [
            "169.254.169.254%0d%0a",
            "127.0.0.1%0d%0a",
            "localhost%0d%0a",
            "metadata.google.internal%0d%0a",
            "%0d%0aexample.com",
            "exam%0d%0aple.com"
        ]
    )
    func carriageReturnLineFeed(_ host: String) {
        // The subtlest bug in this file's history. `"\r\n"` is a single `Character`, so a
        // grapheme-level scan matched neither the CR nor the LF entry, and `Character.isASCII`
        // reports true for the pair. A host ending `%0d%0a` decoded to a trailing `\r\n`,
        // passed both gates, and - its last label now being non-numeric - was classified as a
        // *domain*, defeating the IP-literal, reserved-address and reserved-name checks at
        // once. Every scan is over `Unicode.Scalar` now.
        #expect(throws: HostParsingError.self) {
            try URLHost.parse(host)
        }
        #expect(!URLPolicy.publicHTTPS.allows("https://\(host)/"))
    }

    @Test("A decoded CR-LF host is not silently reclassified as a domain")
    func carriageReturnLineFeedIsNotADomain() throws {
        // Pinning the mechanism rather than just the outcome: if this ever parses again, it
        // must at least still be seen as the address it is.
        let error = try #require(URLPolicy.publicHTTPS.rejection(for: "https://127.0.0.1%0d%0a/"))
        #expect(!error.description.contains("allow-list"))
    }

    @Test(
        "Empty labels and empty hosts are rejected",
        arguments: ["", ".", "..", "a..b", ".example.com", "example..com", "example.com.."]
    )
    func emptyLabels(_ input: String) {
        #expect(throws: HostParsingError.self) {
            try URLHost.parse(input)
        }
    }

    @Test("Malformed percent-encoding is rejected")
    func malformedPercentEncoding() {
        for input in ["example%.com", "example%2.com", "example%zz.com", "%ff%fe.com"] {
            #expect(throws: HostParsingError.self) {
                try URLHost.parse(input)
            }
        }
    }

    @Test("Non-ASCII hosts are refused rather than transcoded")
    func nonASCII() {
        // Foundation exposes no IDNA entry point, and guessing at UTS-46 would produce a
        // host that differs from the one the network stack uses - the exact condition this
        // package exists to prevent. Callers punycode first.
        #expect(throws: HostParsingError.nonASCII("пример.рф")) {
            try URLHost.parse("пример.рф")
        }
        #expect(throws: HostParsingError.self) {
            try URLHost.parse("%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84")
        }
    }

    @Test("IPv6 literals must be bracketed, and brackets must close")
    func ipv6Brackets() throws {
        #expect(try URLHost.parse("[::1]") == .ipv6(IPv6Address(pieces: [0, 0, 0, 0, 0, 0, 0, 1])))
        #expect(throws: HostParsingError.unclosedIPv6Bracket) {
            try URLHost.parse("[::1")
        }
        // Unbracketed, the colons are forbidden host code points.
        #expect(throws: HostParsingError.self) {
            try URLHost.parse("::1")
        }
    }

    @Test("Host descriptions are canonical and round-trip through the parser")
    func canonicalization() throws {
        for input in ["EXAMPLE.com.", "0x7f.1", "[0:0:0:0:0:0:0:1]", "2130706433"] {
            let host = try URLHost.parse(input)
            #expect(try URLHost.parse(host.description) == host)
        }
        #expect(try URLHost.parse("0x7f.1").description == "127.0.0.1")
        #expect(try URLHost.parse("[0:0:0:0:0:0:0:1]").description == "[::1]")
    }

    @Test("isIPAddress distinguishes names from addresses however they are spelled")
    func isIPAddress() throws {
        #expect(try !URLHost.parse("example.com").isIPAddress)
        #expect(try URLHost.parse("2130706433").isIPAddress)
        #expect(try URLHost.parse("0x7f.1").isIPAddress)
        #expect(try URLHost.parse("[::1]").isIPAddress)
    }
}

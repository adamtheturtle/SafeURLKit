//
//  IPv6ParsingTests.swift
//  SafeURLKitTests
//
//  The WHATWG IPv6 parser and serializer, including the embedded-IPv4 forms that let an
//  IPv4 destination be written as an IPv6 literal.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("IPv6 parsing")
struct IPv6ParsingTests {
    @Test(
        "Valid literals parse to the expected pieces",
        arguments: [
            ("::1", [0, 0, 0, 0, 0, 0, 0, 1] as [UInt16]),
            ("::", [0, 0, 0, 0, 0, 0, 0, 0]),
            ("0:0:0:0:0:0:0:1", [0, 0, 0, 0, 0, 0, 0, 1]),
            ("2001:db8::1", [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1]),
            ("fe80::1", [0xFE80, 0, 0, 0, 0, 0, 0, 1]),
            ("1:2:3:4:5:6:7:8", [1, 2, 3, 4, 5, 6, 7, 8]),
            ("1::8", [1, 0, 0, 0, 0, 0, 0, 8]),
            ("1:2:3:4:5:6::8", [1, 2, 3, 4, 5, 6, 0, 8]),
            ("::ffff:127.0.0.1", [0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1]),
            ("::127.0.0.1", [0, 0, 0, 0, 0, 0, 0x7F00, 1]),
            ("64:ff9b::169.254.169.254", [0x64, 0xFF9B, 0, 0, 0, 0, 0xA9FE, 0xA9FE]),
            ("2002:a9fe:a9fe::", [0x2002, 0xA9FE, 0xA9FE, 0, 0, 0, 0, 0]),
            ("ABCD::", [0xABCD, 0, 0, 0, 0, 0, 0, 0])
        ]
    )
    func validLiterals(_ input: String, _ pieces: [UInt16]) throws {
        #expect(try IPv6Address.parse(input) == #require(IPv6Address(pieces: pieces)))
    }

    @Test("The collection initializer rejects non-eight-piece addresses")
    func collectionInitializerLength() {
        #expect(IPv6Address(pieces: [0, 0, 0, 0, 0, 0, 0]) == nil)
        #expect(IPv6Address(pieces: [0, 0, 0, 0, 0, 0, 0, 0, 0]) == nil)
    }

    @Test(
        "Malformed literals are rejected",
        arguments: [
            "",
            ":",
            ":1",
            "1:",
            "1:2:3:",
            "::1::2",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7",
            "12345::",
            "::ffff:127.0.0.256",
            "::ffff:127.0.0",
            "::ffff:127.0.0.1.2",
            // Leading zeros in the embedded dotted-quad: there is no octal escape hatch
            // here, so this is invalid rather than a second spelling of loopback.
            "::ffff:0177.0.0.1",
            "::ffff:01.0.0.1",
            "1.2.3.4",
            "::ffff:127.0.0.1:",
            "gggg::",
            // Zone identifiers have no place in a URL, in either spelling.
            "fe80::1%eth0",
            "fe80::1%25eth0"
        ]
    )
    func malformedLiterals(_ input: String) {
        #expect(throws: HostParsingError.self) {
            try IPv6Address.parse(input)
        }
    }

    @Test(
        "Serialization is the canonical compressed form",
        arguments: [
            ("0:0:0:0:0:0:0:1", "::1"),
            ("0:0:0:0:0:0:0:0", "::"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
            ("ABCD::1", "abcd::1"),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("::ffff:127.0.0.1", "::ffff:7f00:1"),
            ("1:0:0:0:0:0:0:0", "1::")
        ]
    )
    func serialization(_ input: String, _ expected: String) throws {
        #expect(try IPv6Address.parse(input).description == expected)
    }

    @Test("A single zero piece is not compressed, but the first longest run is")
    func compressionTieBreaking() throws {
        #expect(try IPv6Address.parse("1:0:2:3:4:5:6:7").description == "1:0:2:3:4:5:6:7")
        // Two runs of length two: the standard compresses the first.
        #expect(try IPv6Address.parse("1:0:0:2:0:0:3:4").description == "1::2:0:0:3:4")
    }

    @Test("Bytes expose the address most significant first")
    func bytes() throws {
        let address = try IPv6Address.parse("::ffff:127.0.0.1")
        #expect(address.bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1])
    }
}

@Suite("IPv4 embedded in IPv6")
struct EmbeddedIPv4Tests {
    @Test(
        "Each transition mechanism's embedded address is extracted",
        arguments: [
            // IPv4-mapped.
            ("::ffff:169.254.169.254", IPv4Address(169, 254, 169, 254)),
            // IPv4-compatible, deprecated but still parsed by everything.
            ("::169.254.169.254", IPv4Address(169, 254, 169, 254)),
            // NAT64.
            ("64:ff9b::169.254.169.254", IPv4Address(169, 254, 169, 254)),
            // 6to4: the address sits in the second and third pieces.
            ("2002:a9fe:a9fe::", IPv4Address(169, 254, 169, 254)),
            // Teredo: the server address sits in the third and fourth pieces.
            ("2001:0:a9fe:a9fe::", IPv4Address(169, 254, 169, 254))
        ]
    )
    func extraction(_ input: String, _ expected: IPv4Address) throws {
        let address = try IPv6Address.parse(input)
        #expect(address.embeddedIPv4Addresses.contains(expected))
    }

    @Test("Teredo's obfuscated client field is decoded into the embedded address list")
    func teredoClientDecoded() throws {
        // Server 8.8.8.8 is public; client 5601:5601 XOR ffff:ffff = 169.254.169.254.
        // Decoding the client field is what surfaces the metadata endpoint.
        let address = try IPv6Address.parse("2001:0:808:808:3:4:5601:5601")
        #expect(
            address.embeddedIPv4Addresses
                == [IPv4Address(8, 8, 8, 8), IPv4Address(169, 254, 169, 254)]
        )
        let match = try #require(SpecialPurposeAddresses.match(address))
        #expect(match.name == "link-local / cloud metadata")
    }

    @Test("An all-zero 6to4 field is a placeholder, not the address 0.0.0.0")
    func zero6to4Field() throws {
        #expect(try IPv6Address.parse("2002::1").embeddedIPv4Addresses.isEmpty)
    }

    @Test("A Teredo address with a zero server still decodes a non-zero client field")
    func teredoZeroServerNonZeroClient() throws {
        // 2001:0::1 has server 0.0.0.0 (ignored) and client raw 0.0.0.1 → XOR → 255.255.255.254.
        let address = try IPv6Address.parse("2001:0::1")
        #expect(address.embeddedIPv4Addresses == [IPv4Address(255, 255, 255, 254)])
    }

    @Test(
        "The unspecified and loopback addresses are not read as embedded IPv4",
        arguments: ["::", "::1"]
    )
    func notEmbedded(_ input: String) throws {
        // They are those addresses in their own right, and the IPv6 registry covers them.
        #expect(try IPv6Address.parse(input).embeddedIPv4Addresses.isEmpty)
    }

    @Test("An ordinary IPv6 address embeds nothing")
    func ordinary() throws {
        #expect(try IPv6Address.parse("2606:4700::1111").embeddedIPv4Addresses.isEmpty)
    }
}

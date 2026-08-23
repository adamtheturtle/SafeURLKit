//
//  IPv4ParsingTests.swift
//  SafeURLKitTests
//
//  The WHATWG IPv4 parser, against the spellings that block lists historically missed.
//
//  The `0177.0.0.1` / `0x7f.1` / `2130706433` cases are the CVE-2020-28360 corpus from
//  frenchbread/private-ip: a checker that read every dotted part as decimal treated all
//  three as public addresses.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("IPv4 parsing")
struct IPv4ParsingTests {
    @Test(
        "Every accepted spelling of loopback parses to 127.0.0.1",
        arguments: [
            "127.0.0.1",
            "127.0.1",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0177.0.0.01",
            "0x7f.0.0.1",
            "0x7f.1",
            "0x7f000001",
            "0X7F000001",
            "017700000001",
            "127.0.0.1.",
            "0x7f.0x0.0x0.0x1"
        ]
    )
    func loopbackSpellings(_ input: String) throws {
        #expect(IPv4Address.endsInANumber(input), "\(input) must route to the IPv4 parser")
        #expect(try IPv4Address.parse(input) == IPv4Address(127, 0, 0, 1))
    }

    @Test(
        "Mixed-radix and short forms compose the expected address",
        arguments: [
            ("192.168.0.1", IPv4Address(192, 168, 0, 1)),
            ("192.168.1", IPv4Address(192, 168, 0, 1)),
            ("192.11010049", IPv4Address(192, 168, 0, 1)),
            ("0xc0.0250.0.1", IPv4Address(192, 168, 0, 1)),
            ("169.254.169.254", IPv4Address(169, 254, 169, 254)),
            ("0xa9fea9fe", IPv4Address(169, 254, 169, 254)),
            ("2852039166", IPv4Address(169, 254, 169, 254)),
            ("0", IPv4Address(0, 0, 0, 0)),
            ("0x0", IPv4Address(0, 0, 0, 0)),
            ("00", IPv4Address(0, 0, 0, 0)),
            ("255.255.255.255", IPv4Address(255, 255, 255, 255)),
            ("4294967295", IPv4Address(255, 255, 255, 255)),
            // A bare radix prefix is zero, per the standard's IPv4 number parser.
            ("192.168.0.0x", IPv4Address(192, 168, 0, 0))
        ]
    )
    func spellings(_ input: String, _ expected: IPv4Address) throws {
        #expect(try IPv4Address.parse(input) == expected)
    }

    @Test(
        "Out-of-range, over-long, and malformed numeric hosts are rejected",
        arguments: [
            "256.0.0.1",
            "1.2.3.4.5",
            "127.0.0.256",
            "4294967296",
            "0x100000000",
            "127.0.0.1..",
            "127..0.1",
            ".127.0.0.1",
            "0779.0.0.1",
            "0xg.1",
            "1.2.3.-4"
        ]
    )
    func invalidNumericHosts(_ input: String) {
        #expect(throws: HostParsingError.self) {
            try IPv4Address.parse(input)
        }
    }

    @Test("A part may not exceed the octets left for it")
    func lastPartRange() throws {
        // In `1.2.3`, the final part supplies the low two octets, so 65535 fits and 65536
        // does not.
        #expect(try IPv4Address.parse("1.2.65535") == IPv4Address(1, 2, 255, 255))
        #expect(throws: HostParsingError.self) {
            try IPv4Address.parse("1.2.65536")
        }
        #expect(try IPv4Address.parse("1.16777215") == IPv4Address(1, 255, 255, 255))
        #expect(throws: HostParsingError.self) {
            try IPv4Address.parse("1.16777216")
        }
    }

    @Test(
        "An overflowing numeric host is an invalid address, not a domain name",
        arguments: [
            "0x100000000",
            "0xffffffffffff",
            "1.2.3.0x100000000",
            "0777777777777777",
            "99999999999999999999"
        ]
    )
    func overflow(_ input: String) {
        // The standard's *number* parser has no upper bound; the range check belongs to the
        // address parser. Enforcing the bound too early would make `endsInANumber` answer
        // "not a number" and route these to the domain branch, so `https://0x100000000/`
        // would be accepted as a name rather than rejected as the invalid host it is.
        #expect(IPv4Address.endsInANumber(input), "\(input) must route to the IPv4 parser")
        #expect(throws: HostParsingError.self) {
            try IPv4Address.parse(input)
        }
        #expect(throws: HostParsingError.self) {
            try URLHost.parse(input)
        }
        #expect(!URLPolicy.publicHTTPS.allows("https://\(input)/"))
    }

    @Test(
        "Hosts that do not end in a number are left to the domain path",
        arguments: [
            "example.com",
            "1.2.3.4.example.com",
            "127.0.0.1.example.com",
            "0x7f.example",
            "",
            "com",
            "1e2.com"
        ]
    )
    func notNumeric(_ input: String) {
        #expect(!IPv4Address.endsInANumber(input))
    }

    @Test(
        "Hosts with alphabetic labels and a numeric suffix parse as domains",
        arguments: ["example.1", "example.0x1"]
    )
    func alphabeticNumericSuffix(_ input: String) throws {
        #expect(try URLHost.parse(input) == .domain(input.lowercasedASCII))
    }

    @Test(
        "Hosts whose last label is numeric always route to the IPv4 parser",
        arguments: ["a.b.c.0777", "1"]
    )
    func numeric(_ input: String) {
        // Purely numeric hosts still route to the IPv4 parser.
        #expect(IPv4Address.endsInANumber(input))
    }

    @Test("Octets and description round-trip")
    func serialization() {
        let address = IPv4Address(169, 254, 169, 254)
        #expect(address.octets == [169, 254, 169, 254])
        #expect(address.description == "169.254.169.254")
        #expect(address.rawValue == 0xA9FE_A9FE)
        #expect(IPv4Address(rawValue: 0x7F00_0001).description == "127.0.0.1")
    }
}

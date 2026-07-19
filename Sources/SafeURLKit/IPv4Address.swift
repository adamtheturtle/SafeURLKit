//
//  IPv4Address.swift
//  SafeURLKit
//
//  A 32-bit IPv4 address, plus the WHATWG IPv4 parser that produces one.
//
//  The parser is the reason this package exists. `127.0.0.1` is the spelling everybody
//  blocks; `0177.0.0.1`, `0x7f.1`, and `2130706433` are the same address written in forms
//  that a naive string check waves through and that URLSession happily connects to. The
//  WHATWG URL Standard defines exactly one answer for each of those spellings, so this
//  file transcribes that algorithm rather than inventing a looser one.
//
//  See https://url.spec.whatwg.org/#concept-ipv4-parser
//

import Foundation

/// An IPv4 address, stored as the 32-bit number the four octets encode.
///
/// Comparing addresses through this type rather than through their textual spelling is
/// what makes exotic encodings harmless: `0x7f.1` and `127.0.0.1` parse to the same
/// ``rawValue``, so a range check catches both.
public struct IPv4Address: Sendable, Hashable, CustomStringConvertible {
    /// The address as a single 32-bit number, most significant octet first.
    ///
    /// `127.0.0.1` is `0x7F00_0001`.
    public let rawValue: UInt32

    /// Create an address from its 32-bit numeric form.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Create an address from its four octets, most significant first.
    public init(_ octet0: UInt8, _ octet1: UInt8, _ octet2: UInt8, _ octet3: UInt8) {
        rawValue =
            UInt32(octet0) << 24 | UInt32(octet1) << 16 | UInt32(octet2) << 8 | UInt32(octet3)
    }

    /// The four octets, most significant first.
    public var octets: [UInt8] {
        [
            UInt8(truncatingIfNeeded: rawValue >> 24),
            UInt8(truncatingIfNeeded: rawValue >> 16),
            UInt8(truncatingIfNeeded: rawValue >> 8),
            UInt8(truncatingIfNeeded: rawValue)
        ]
    }

    /// The canonical dotted-quad spelling, which is what the WHATWG URL serializer emits.
    ///
    /// Always four decimal octets, whatever spelling the address was parsed from. Log this
    /// rather than the input when reporting a rejection, so `2130706433` is recorded as the
    /// `127.0.0.1` it actually is.
    public var description: String {
        octets.map(String.init).joined(separator: ".")
    }
}

// MARK: - Parsing

extension IPv4Address {
    /// Parse a host string as an IPv4 address using the WHATWG IPv4 parser.
    ///
    /// This accepts every spelling the standard accepts, which is considerably more than
    /// dotted-quad: one to four parts, each independently written in decimal, octal (a `0`
    /// prefix), or hex (an `0x` prefix), with the final part absorbing all the octets the
    /// earlier parts did not supply. So `127.0.0.1`, `127.1`, `0177.0.0.1`, `0x7f.0.0.1`,
    /// and `2130706433` all parse, all to the same address.
    ///
    /// A single trailing dot is stripped first, matching the standard: `127.0.0.1.` is the
    /// same address.
    ///
    /// - Parameter input: An ASCII, already-lowercased host string.
    /// - Returns: The parsed address.
    /// - Throws: ``HostParsingError/invalidIPv4Address(_:)`` if `input` is not a valid IPv4
    ///   address under these rules. Note that callers should only reach this parser when
    ///   ``endsInANumber(_:)`` is true; per the standard, a host that looks numeric and
    ///   fails to parse is an invalid host, not a domain name.
    public static func parse(_ input: String) throws(HostParsingError) -> IPv4Address {
        var parts = input.split(separator: ".", omittingEmptySubsequences: false)

        // A single trailing dot is the DNS root label; the standard drops it before
        // counting parts, so `127.0.0.1.` has four parts and not five.
        if parts.count > 1, parts.last?.isEmpty == true {
            parts.removeLast()
        }

        guard parts.count <= 4 else {
            throw .invalidIPv4Address(input)
        }

        var numbers: [UInt64] = []
        numbers.reserveCapacity(parts.count)
        for part in parts {
            // An empty part is a failure, not a zero: `127..1` and `.1` are invalid hosts.
            guard !part.isEmpty else {
                throw .invalidIPv4Address(input)
            }
            numbers.append(try parseNumber(part, in: input))
        }

        // Every part but the last is one octet. The last absorbs the remaining octets, so
        // in `127.1` the `1` supplies the low three and must be under 2^24.
        for number in numbers.dropLast() where number > 255 {
            throw .invalidIPv4Address(input)
        }
        guard let last = numbers.last else {
            throw .invalidIPv4Address(input)
        }
        // The last part must be under 256^(5 - count): in `127.1` it supplies three octets
        // and so must be under 2^24, and in dotted quad it supplies one and must be a byte.
        let octetsSuppliedByLastPart = 5 - numbers.count
        guard last < (UInt64(1) << (8 * UInt64(octetsSuppliedByLastPart))) else {
            throw .invalidIPv4Address(input)
        }

        var value = UInt32(last)
        for (index, number) in numbers.dropLast().enumerated() {
            value |= UInt32(number) << (8 * UInt32(3 - index))
        }
        return IPv4Address(rawValue: value)
    }

    /// Parse one dot-separated part as a number, honouring the standard's radix prefixes.
    ///
    /// `0x`/`0X` means hex, a leading `0` means octal, anything else is decimal. A part
    /// that is only a prefix (`"0"`, `"0x"`) is zero. This prefix handling is the whole
    /// CVE-2020-28360 class: a checker that reads every part as decimal sees `0177` as 177
    /// where the network stack sees 127.
    private static func parseNumber(
        _ part: Substring,
        in input: String
    ) throws(HostParsingError) -> UInt64 {
        var digits = part
        var radix: UInt64 = 10

        if digits.count >= 2, digits.hasPrefix("0") {
            let second = digits[digits.index(after: digits.startIndex)]
            if second == "x" || second == "X" {
                radix = 16
                digits = digits.dropFirst(2)
            } else {
                radix = 8
                digits = digits.dropFirst(1)
            }
        }

        // `"0"` and `"0x"` reduce to nothing, and the standard reads both as zero.
        if digits.isEmpty {
            return 0
        }

        // Saturate rather than throw on overflow. The standard's *number* parser has no
        // upper bound - the range check belongs to the address parser - and the difference
        // matters, because `endsInANumber` treats "this part parses as a number" as the
        // signal to use the IPv4 path at all. Throwing here would make `0x100000000` look
        // like a domain name and slip through as one, instead of being the invalid host it
        // is. The saturated value exceeds every allowed range, so `parse` still rejects it.
        var value: UInt64 = 0
        for character in digits {
            guard let digit = character.hexDigitValue, UInt64(digit) < radix else {
                throw .invalidIPv4Address(input)
            }
            if value < overflowSentinel {
                value = min(value * radix + UInt64(digit), overflowSentinel)
            }
        }
        return value
    }

    /// One past the largest representable IPv4 address, used as the saturating ceiling in
    /// ``parseNumber(_:in:)``. Any part at least this large fails every range check in
    /// ``parse(_:)``.
    private static let overflowSentinel = UInt64(UInt32.max) + 1

    /// Whether the WHATWG host parser would route this host to the IPv4 parser.
    ///
    /// This is the standard's "ends in a number" check, and it is the subtle half of the
    /// defence. It is not "does this look like dotted quad" - it asks whether the *last*
    /// label is numeric under any of the accepted radixes. That is what makes `0x7f.1` and
    /// the bare integer `2130706433` addresses rather than domain names, and it is why
    /// `whatwg/url#619` exists.
    ///
    /// - Parameter input: An ASCII, already-lowercased host string.
    /// - Returns: `true` if `input` must be parsed as IPv4 rather than as a domain.
    public static func endsInANumber(_ input: String) -> Bool {
        var parts = input.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count > 1, parts.last?.isEmpty == true {
            parts.removeLast()
        }
        guard let last = parts.last, !last.isEmpty else {
            return false
        }
        if last.allSatisfy(\.isASCIIDigit) {
            return true
        }
        return (try? parseNumber(last, in: input)) != nil
    }
}

extension Character {
    /// Whether this is one of `0`-`9`. `Character.isNumber` is far broader - it accepts
    /// Arabic-Indic digits and other Unicode numerics - and using it here would let those
    /// spellings take a different path than the network stack takes.
    var isASCIIDigit: Bool {
        self >= "0" && self <= "9"
    }
}

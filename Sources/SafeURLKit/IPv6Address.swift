//
//  IPv6Address.swift
//  SafeURLKit
//
//  A 128-bit IPv6 address, with the WHATWG parser and serializer.
//
//  IPv6 matters here for two reasons beyond `[::1]`. First, several IPv6 forms carry an
//  IPv4 address inside them - `::ffff:127.0.0.1`, 6to4, Teredo, NAT64 - so a block list
//  that only understands IPv6 prefixes misses the smuggled v4 destination. Second, zone
//  identifiers (`fe80::1%eth0`) are a URL-level trick the standard rejects outright, and
//  transcribing the standard gets that rejection for free.
//
//  See https://url.spec.whatwg.org/#concept-ipv6-parser
//

import Foundation

/// An IPv6 address, stored as its eight 16-bit pieces.
public struct IPv6Address: Sendable, Hashable, CustomStringConvertible {
    /// The eight 16-bit pieces, most significant first. Always exactly eight elements.
    public let pieces: [UInt16]

    /// Create an address from eight 16-bit pieces, most significant first.
    ///
    /// - Precondition: `pieces` has exactly eight elements.
    public init(pieces: [UInt16]) {
        precondition(pieces.count == 8, "An IPv6 address has exactly eight pieces")
        self.pieces = pieces
    }

    /// The 16 bytes of the address, most significant first.
    public var bytes: [UInt8] {
        pieces.flatMap { [UInt8(truncatingIfNeeded: $0 >> 8), UInt8(truncatingIfNeeded: $0)] }
    }

    /// The canonical WHATWG serialization: lowercase hex, no leading zeros in a piece, and
    /// the longest run of two or more zero pieces collapsed to `::`.
    ///
    /// This is the spelling to log, so that `[0:0:0:0:0:0:0:1]` is recorded as `::1`.
    public var description: String {
        var output = ""
        let compress = longestZeroRun()
        var ignoreZero = false

        for index in 0 ..< 8 {
            if ignoreZero, pieces[index] == 0 {
                continue
            } else if ignoreZero {
                ignoreZero = false
            }

            if compress == index {
                output += index == 0 ? "::" : ":"
                ignoreZero = true
                continue
            }

            output += String(pieces[index], radix: 16)
            if index != 7 {
                output += ":"
            }
        }
        return output
    }

    /// The index at which the longest run of two or more consecutive zero pieces starts, or
    /// `nil` when there is no such run. Ties go to the first run, as the standard requires.
    private func longestZeroRun() -> Int? {
        var best: (start: Int, length: Int)?
        var current: (start: Int, length: Int)?

        for (index, piece) in pieces.enumerated() {
            if piece == 0 {
                current = (current?.start ?? index, (current?.length ?? 0) + 1)
                if current!.length > (best?.length ?? 1) {
                    best = current
                }
            } else {
                current = nil
            }
        }
        return best?.start
    }
}

// MARK: - Parsing

extension IPv6Address {
    /// Parse the contents of an IPv6 literal - the text *between* the square brackets -
    /// using the WHATWG IPv6 parser.
    ///
    /// Accepts compression (`::`), a trailing embedded IPv4 form (`::ffff:127.0.0.1`), and
    /// nothing else. In particular it rejects zone identifiers (`fe80::1%25eth0`), leading
    /// zeros in the embedded IPv4 dotted-quad, and any piece longer than four hex digits.
    ///
    /// - Parameter input: The bracket-stripped literal, for example `"::1"`.
    /// - Returns: The parsed address.
    /// - Throws: ``HostParsingError/invalidIPv6Address(_:)`` if `input` is not a valid
    ///   literal.
    public static func parse(_ input: String) throws(HostParsingError) -> IPv6Address {
        // Work in ASCII bytes: the standard is written over code points, all of which are
        // ASCII here, and anything non-ASCII is a failure anyway.
        guard let ascii = input.asciiBytes else {
            throw .invalidIPv6Address(input)
        }

        var address = [UInt16](repeating: 0, count: 8)
        var pieceIndex = 0
        var compress: Int?
        var cursor = 0

        if ascii.first == UInt8(ascii: ":") {
            guard ascii.count > 1, ascii[1] == UInt8(ascii: ":") else {
                throw .invalidIPv6Address(input)
            }
            cursor = 2
            pieceIndex = 1
            compress = 1
        }

        while cursor < ascii.count {
            guard pieceIndex < 8 else {
                throw .invalidIPv6Address(input)
            }

            if ascii[cursor] == UInt8(ascii: ":") {
                guard compress == nil else {
                    throw .invalidIPv6Address(input)
                }
                cursor += 1
                pieceIndex += 1
                compress = pieceIndex
                continue
            }

            var value: UInt16 = 0
            var length = 0
            while length < 4, cursor < ascii.count, let digit = ascii[cursor].hexDigitValue {
                value = value << 4 | UInt16(digit)
                cursor += 1
                length += 1
            }

            if cursor < ascii.count, ascii[cursor] == UInt8(ascii: ".") {
                guard length != 0 else {
                    throw .invalidIPv6Address(input)
                }
                cursor -= length
                guard pieceIndex <= 6 else {
                    throw .invalidIPv6Address(input)
                }
                try parseEmbeddedIPv4(
                    ascii,
                    cursor: &cursor,
                    address: &address,
                    pieceIndex: &pieceIndex,
                    input: input
                )
                break
            }

            if cursor < ascii.count {
                guard ascii[cursor] == UInt8(ascii: ":") else {
                    throw .invalidIPv6Address(input)
                }
                cursor += 1
                // A literal may not end on a lone colon: `1:2:3:` is invalid.
                guard cursor < ascii.count else {
                    throw .invalidIPv6Address(input)
                }
            }

            address[pieceIndex] = value
            pieceIndex += 1
        }

        if let compress {
            // Slide the pieces written after the `::` down to the end of the address.
            var swaps = pieceIndex - compress
            var target = 7
            while target != 0, swaps > 0 {
                address.swapAt(target, compress + swaps - 1)
                target -= 1
                swaps -= 1
            }
        } else if pieceIndex != 8 {
            throw .invalidIPv6Address(input)
        }

        return IPv6Address(pieces: address)
    }

    /// Parse the trailing dotted-quad of forms like `::ffff:127.0.0.1`, writing it into the
    /// last two pieces.
    ///
    /// Leading zeros are rejected here deliberately: unlike a bare IPv4 host, the embedded
    /// form has no octal escape hatch in the standard, so `::ffff:0177.0.0.1` is simply an
    /// invalid literal rather than a second spelling of loopback.
    private static func parseEmbeddedIPv4(
        _ ascii: [UInt8],
        cursor: inout Int,
        address: inout [UInt16],
        pieceIndex: inout Int,
        input: String
    ) throws(HostParsingError) {
        var numbersSeen = 0

        while cursor < ascii.count {
            var octet: UInt16?

            if numbersSeen > 0 {
                guard ascii[cursor] == UInt8(ascii: "."), numbersSeen < 4 else {
                    throw .invalidIPv6Address(input)
                }
                cursor += 1
            }

            guard cursor < ascii.count, ascii[cursor].isASCIIDigit else {
                throw .invalidIPv6Address(input)
            }

            while cursor < ascii.count, ascii[cursor].isASCIIDigit {
                let digit = UInt16(ascii[cursor] - UInt8(ascii: "0"))
                switch octet {
                case nil:
                    octet = digit
                case 0:
                    // A second digit after a leading `0`, as in `01`.
                    throw .invalidIPv6Address(input)
                case let current?:
                    octet = current * 10 + digit
                }
                guard let octet, octet <= 255 else {
                    throw .invalidIPv6Address(input)
                }
                cursor += 1
            }

            guard let octet else {
                throw .invalidIPv6Address(input)
            }
            address[pieceIndex] = address[pieceIndex] << 8 | octet
            numbersSeen += 1
            if numbersSeen == 2 || numbersSeen == 4 {
                pieceIndex += 1
            }
        }

        guard numbersSeen == 4 else {
            throw .invalidIPv6Address(input)
        }
    }
}

// MARK: - ASCII helpers

extension String {
    /// The string's bytes if it is pure ASCII, or `nil` otherwise.
    var asciiBytes: [UInt8]? {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(utf8.count)
        for byte in utf8 {
            guard byte < 0x80 else {
                return nil
            }
            bytes.append(byte)
        }
        return bytes
    }
}

extension UInt8 {
    /// Whether this ASCII byte is one of `0`-`9`.
    var isASCIIDigit: Bool {
        self >= UInt8(ascii: "0") && self <= UInt8(ascii: "9")
    }

    /// The value of this byte read as a hex digit, or `nil` if it is not one.
    var hexDigitValue: Int? {
        switch self {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"):
            Int(self - UInt8(ascii: "0"))
        case UInt8(ascii: "a") ... UInt8(ascii: "f"):
            Int(self - UInt8(ascii: "a")) + 10
        case UInt8(ascii: "A") ... UInt8(ascii: "F"):
            Int(self - UInt8(ascii: "A")) + 10
        default:
            nil
        }
    }
}

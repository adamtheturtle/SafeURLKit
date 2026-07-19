//
//  URLHost.swift
//  SafeURLKit
//
//  The parsed host of a URL, and the WHATWG host parser that produces one.
//
//  Everything downstream - origin matching, IP-literal rejection, reserved-range checks -
//  is written against this type rather than against a host string, because a host string
//  is exactly the thing that has more than one meaning.
//
//  See https://url.spec.whatwg.org/#concept-host-parser
//

import Foundation

/// A URL's host, resolved to what it actually denotes.
///
/// The whole point of the distinction is that the textual form does not determine the case:
/// `2130706433` and `0x7f.1` are both ``ipv4(_:)``, not ``domain(_:)``, because that is how
/// a URL parser and therefore the network stack read them.
public enum URLHost: Sendable, Hashable, CustomStringConvertible {
    /// A registrable domain name, already lowercased and with any trailing root dot removed.
    case domain(String)
    /// An IPv4 address, however it was spelled.
    case ipv4(IPv4Address)
    /// An IPv6 address, written in a URL between square brackets.
    case ipv6(IPv6Address)

    /// Whether this host is an IP address rather than a name.
    ///
    /// Names still resolve to addresses, so a `false` here is not a safety property on its
    /// own - see ``URLPolicy`` on why DNS rebinding is out of scope at this layer.
    public var isIPAddress: Bool {
        switch self {
        case .domain:
            false
        case .ipv4, .ipv6:
            true
        }
    }

    /// The canonical serialization, matching the WHATWG host serializer.
    ///
    /// IPv6 addresses include their square brackets, so this value can be substituted into
    /// a URL's authority directly.
    public var description: String {
        switch self {
        case let .domain(name):
            name
        case let .ipv4(address):
            address.description
        case let .ipv6(address):
            "[\(address)]"
        }
    }
}

// MARK: - Errors

/// Why a host string could not be resolved to a ``URLHost``.
public enum HostParsingError: Error, Sendable, Hashable, CustomStringConvertible {
    /// The host was empty, or became empty after the trailing root dot was removed.
    case empty
    /// The host contained a code point a URL host may never contain, such as a space,
    /// a control character, or one of `#/:<>?@[\]^|`.
    case forbiddenCodePoint(Character)
    /// A `%` escape was malformed, or decoded to bytes that are not valid UTF-8.
    case invalidPercentEncoding
    /// The host contained non-ASCII code points after percent-decoding. See
    /// ``URLHost`` parsing notes: SafeURLKit deliberately does not implement IDNA.
    case nonASCII(String)
    /// A host that began with `[` did not end with `]`.
    case unclosedIPv6Bracket
    /// A domain label was empty, as in `a..b` or a leading dot.
    case emptyLabel
    /// The host ends in a number and so must be an IPv4 address, but is not a valid one.
    case invalidIPv4Address(String)
    /// The text between square brackets is not a valid IPv6 literal.
    case invalidIPv6Address(String)

    public var description: String {
        switch self {
        case .empty:
            "the host is empty"
        case let .forbiddenCodePoint(character):
            "the host contains the forbidden code point \(character.debugDescription)"
        case .invalidPercentEncoding:
            "the host contains invalid percent-encoding"
        case let .nonASCII(host):
            """
            the host \(host.debugDescription) contains non-ASCII code points, which \
            SafeURLKit does not transcode; supply an already punycoded host
            """
        case .unclosedIPv6Bracket:
            "the host opens an IPv6 literal with `[` but does not close it"
        case .emptyLabel:
            "the host contains an empty label"
        case let .invalidIPv4Address(host):
            "\(host.debugDescription) ends in a number but is not a valid IPv4 address"
        case let .invalidIPv6Address(host):
            "\(host.debugDescription) is not a valid IPv6 address"
        }
    }
}

// MARK: - Parsing

extension URLHost {
    /// Code points a URL host may never contain, from the WHATWG "forbidden host code
    /// point" set, plus `%` which is forbidden in a *domain* once decoding has happened.
    ///
    /// Several of these are the raw material for confusion attacks - a `@` or `:` that
    /// survives into a host means someone's parser disagreed about where the host started
    /// or ended - so encountering one is a rejection rather than something to normalize.
    /// The standard's set is "forbidden host code point, plus C0 controls and U+007F", and
    /// the control half is not decorative: because percent-decoding runs first, `%01` and
    /// `%7f` would otherwise decode straight into a domain and survive.
    /// The set is over `Unicode.Scalar`, not `Character`, and every scan below iterates
    /// scalars for the same reason. A `Character` is a grapheme cluster, and CR immediately
    /// followed by LF is *one* cluster carrying two scalars - so a `Character`-level scan
    /// never sees either control, and `Character.isASCII` reports true for the pair as well.
    /// A host ending `%0d%0a` would decode to a trailing `\r\n`, sail through both gates,
    /// and - because the last label is then non-numeric - be classified as a domain rather
    /// than an address, defeating the IP-literal, reserved-address, and reserved-name checks
    /// in one move.
    private static let forbiddenCodePoints: Set<Unicode.Scalar> = [
        " ", "#", "/", ":", "<", ">", "?", "@", "[", "\\", "]", "^", "|", "%"
    ]

    /// Whether `scalar` may never appear in a domain: one of the explicit forbidden code
    /// points, or any C0 control or DEL.
    private static func isForbidden(_ scalar: Unicode.Scalar) -> Bool {
        forbiddenCodePoints.contains(scalar) || scalar.isC0Control
    }

    /// Parse a URL host string.
    ///
    /// The algorithm is the WHATWG host parser for special (HTTP-family) schemes, with one
    /// deliberate narrowing: non-ASCII hosts are rejected rather than transcoded. Foundation
    /// exposes no IDNA/UTS-46 entry point, and an approximate implementation of IDNA in a
    /// security check is worse than no implementation, because it produces a host that
    /// differs from the one the network stack will use. Callers that need internationalized
    /// hosts should punycode them before validation.
    ///
    /// - Parameter input: A host string, with IPv6 literals still bracketed.
    /// - Returns: The parsed host.
    /// - Throws: A ``HostParsingError`` describing why the host is not usable.
    public static func parse(_ input: String) throws(HostParsingError) -> URLHost {
        if input.hasPrefix("[") {
            guard input.hasSuffix("]"), input.count >= 2 else {
                throw .unclosedIPv6Bracket
            }
            return .ipv6(try IPv6Address.parse(String(input.dropFirst().dropLast())))
        }

        let decoded = try percentDecoded(input)

        guard decoded.unicodeScalars.allSatisfy(\.isASCII) else {
            throw .nonASCII(decoded)
        }

        // ASCII-lowercase only, byte by byte. `String.lowercased()` is Unicode-aware, and
        // case folding non-ASCII would be a form of the transcoding rejected above.
        var domain = String(
            decoding: decoded.utf8.map { byte in
                (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte) ? byte + 0x20 : byte
            },
            as: UTF8.self
        )

        if let forbidden = domain.unicodeScalars.first(where: isForbidden) {
            throw .forbiddenCodePoint(Character(forbidden))
        }

        // Strip a single trailing root dot before anything else looks at the labels. This
        // is what stops `localhost.` and `metadata.google.internal.` from sidestepping a
        // suffix rule that the undotted spelling would have matched.
        if domain.hasSuffix(".") {
            domain.removeLast()
        }

        guard !domain.isEmpty else {
            throw .empty
        }

        guard !domain.split(separator: ".", omittingEmptySubsequences: false)
            .contains(where: \.isEmpty)
        else {
            throw .emptyLabel
        }

        if IPv4Address.endsInANumber(domain) {
            return .ipv4(try IPv4Address.parse(domain))
        }

        return .domain(domain)
    }

    /// Percent-decode a host, requiring that the result is valid UTF-8.
    ///
    /// Decoding happens before every other check so that `%2e` cannot hide a label
    /// separator and `%00` cannot hide a null from the forbidden-code-point test.
    private static func percentDecoded(_ input: String) throws(HostParsingError) -> String {
        guard input.contains("%") else {
            return input
        }

        var bytes: [UInt8] = []
        var iterator = Array(input.utf8)[...]

        while let byte = iterator.first {
            iterator = iterator.dropFirst()
            guard byte == UInt8(ascii: "%") else {
                bytes.append(byte)
                continue
            }
            guard
                iterator.count >= 2,
                let high = iterator.first?.hexDigitValue,
                let low = iterator.dropFirst().first?.hexDigitValue
            else {
                throw .invalidPercentEncoding
            }
            bytes.append(UInt8(high << 4 | low))
            iterator = iterator.dropFirst(2)
        }

        guard let decoded = String(bytes: bytes, encoding: .utf8) else {
            throw .invalidPercentEncoding
        }
        return decoded
    }
}

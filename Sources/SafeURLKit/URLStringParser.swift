//
//  URLStringParser.swift
//  SafeURLKit
//
//  A deliberately strict, self-contained split of a URL string into its parts.
//
//  Why not just ask `URLComponents`? Because the vulnerability *is* the disagreement. A
//  validator that reads the host one way and a network stack that reads it another way is
//  the entire class of bug catalogued in curl's "URL interop" write-up: `https://a@b/`,
//  backslash-as-separator, a stray tab in the middle of a hostname. Foundation's parser
//  has changed behaviour across releases and differs from WHATWG in places, so trusting it
//  alone means the check can drift out from under the request.
//
//  So this file does the split itself, refuses anything ambiguous rather than guessing,
//  and then `URLPolicy` cross-checks the result against Foundation and rejects on
//  disagreement. Whatever survives both is a URL that only has one reading.
//

import Foundation

/// A URL string split into the parts a policy cares about.
///
/// This is not a general URL parser: it handles authority-based absolute URLs and rejects
/// everything else, because a policy check on a URL with no authority has nothing to check.
struct ParsedURLString: Sendable, Hashable {
    /// The scheme, ASCII-lowercased.
    var scheme: String
    /// The userinfo component, without the `@`, or `nil` if there was none. An empty string
    /// means the URL contained a bare `@`.
    var userinfo: String?
    /// The host text exactly as written, IPv6 literals still bracketed.
    var hostText: String
    /// The port, or `nil` when none was written. An explicitly empty port (`https://a:/`)
    /// is treated as none, matching the URL standard.
    var port: Int?
    /// The query, without the `?`, or `nil` if there was none.
    var query: String?
    /// The fragment, without the `#`, or `nil` if there was none.
    var fragment: String?
}

/// Why a URL string could not be split.
enum URLStringParsingError: Error, Sendable, Hashable, CustomStringConvertible {
    case containsForbiddenCharacter(Character)
    case missingScheme
    case invalidScheme(String)
    case missingAuthority
    case emptyHost
    case unclosedIPv6Bracket
    case junkAfterIPv6Literal(String)
    case multipleColonsInAuthority
    case invalidPort(String)

    var description: String {
        switch self {
        case let .containsForbiddenCharacter(character):
            """
            the URL contains \(character.debugDescription), which different URL parsers \
            handle differently
            """
        case .missingScheme:
            "the URL has no scheme"
        case let .invalidScheme(scheme):
            "\(scheme.debugDescription) is not a valid URL scheme"
        case .missingAuthority:
            "the URL has no `//` authority, so it names no host"
        case .emptyHost:
            "the URL's authority contains no host"
        case .unclosedIPv6Bracket:
            "the URL opens an IPv6 literal with `[` but does not close it"
        case let .junkAfterIPv6Literal(rest):
            "the URL has \(rest.debugDescription) after its IPv6 literal, where only a port may appear"
        case .multipleColonsInAuthority:
            "the URL's authority has more than one `:`, so its port is ambiguous"
        case let .invalidPort(port):
            "\(port.debugDescription) is not a valid port"
        }
    }
}

extension ParsedURLString {
    /// Characters that are rejected outright wherever they appear in the URL.
    ///
    /// Tab, newline, and carriage return are stripped by WHATWG parsers and *not* by
    /// Foundation, which is precisely enough of a difference to hide a hostname in. A
    /// backslash is a path separator to WHATWG and an ordinary character to Foundation, so
    /// `https://evil.com\@trusted.com/` reads as two different origins. Rather than pick a
    /// side, refuse: no legitimate URL a caller should be fetching contains any of these.
    ///
    /// Over `Unicode.Scalar`, not `Character`: CR followed by LF is a single grapheme
    /// cluster, so a `Character`-level scan matches neither `"\u{000A}"` nor `"\u{000D}"`
    /// and a raw CR-LF pair would pass straight through the check that exists to stop it.
    private static let forbidden: Set<Unicode.Scalar> = [
        "\u{0009}", "\u{000A}", "\u{000D}", " ", "\\", "\u{0000}"
    ]

    private static func isForbidden(_ scalar: Unicode.Scalar) -> Bool {
        forbidden.contains(scalar)
            || scalar.isC0Control
            || (0x7F ... 0x9F).contains(scalar.value)
            || scalar.properties.generalCategory == .format
    }

    /// Split a URL string.
    ///
    /// - Parameter input: The URL as written.
    /// - Returns: The split parts.
    /// - Throws: A ``URLStringParsingError`` if the string is not an unambiguous
    ///   authority-based absolute URL.
    static func parse(_ input: String) throws(URLStringParsingError) -> ParsedURLString {
        if let bad = input.unicodeScalars.first(where: isForbidden) {
            throw .containsForbiddenCharacter(Character(bad))
        }

        guard let schemeEnd = input.firstIndex(of: ":") else {
            throw .missingScheme
        }
        let scheme = String(input[input.startIndex ..< schemeEnd]).lowercasedASCII
        guard scheme.isValidURLScheme else {
            throw .invalidScheme(scheme)
        }

        let afterScheme = input[input.index(after: schemeEnd)...]
        guard afterScheme.hasPrefix("//") else {
            throw .missingAuthority
        }
        let afterSlashes = afterScheme.dropFirst(2)

        // The authority runs to the first delimiter. `#` is included so that a fragment
        // cannot smuggle an `@` that a laxer parser would fold back into the authority.
        let authorityEnd =
            afterSlashes.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" }
                ?? afterSlashes.endIndex
        let authority = afterSlashes[..<authorityEnd]
        let remainder = afterSlashes[authorityEnd...]

        // The *last* `@` separates userinfo from host, as the URL standard requires. Using
        // the first would read `https://trusted.com@evil.com/` as pointing at trusted.com,
        // which is the single most common origin-confusion payload.
        var userinfo: String?
        var hostAndPort = authority
        if let atSign = authority.lastIndex(of: "@") {
            userinfo = String(authority[..<atSign])
            hostAndPort = authority[authority.index(after: atSign)...]
        }

        let (hostText, port) = try splitHostAndPort(hostAndPort)
        guard !hostText.isEmpty else {
            throw .emptyHost
        }

        var query: String?
        var fragment: String?
        var rest = remainder
        if let hash = rest.firstIndex(of: "#") {
            fragment = String(rest[rest.index(after: hash)...])
            rest = rest[..<hash]
        }
        if let question = rest.firstIndex(of: "?") {
            query = String(rest[rest.index(after: question)...])
        }

        return ParsedURLString(
            scheme: scheme,
            userinfo: userinfo,
            hostText: hostText,
            port: port,
            query: query,
            fragment: fragment
        )
    }

    /// Split the host-and-port half of an authority.
    ///
    /// A bracketed IPv6 literal keeps its brackets, and may be followed only by a port. An
    /// unbracketed host may contain no `:` other than the port separator - a second colon
    /// means the string has no single reading, so it is rejected rather than resolved.
    private static func splitHostAndPort(
        _ input: Substring
    ) throws(URLStringParsingError) -> (host: String, port: Int?) {
        if input.hasPrefix("[") {
            guard let close = input.firstIndex(of: "]") else {
                throw .unclosedIPv6Bracket
            }
            let host = String(input[...close])
            let rest = input[input.index(after: close)...]
            if rest.isEmpty {
                return (host, nil)
            }
            guard rest.hasPrefix(":") else {
                throw .junkAfterIPv6Literal(String(rest))
            }
            return (host, try parsePort(rest.dropFirst()))
        }

        let colons = input.filter { $0 == ":" }.count
        guard colons <= 1 else {
            throw .multipleColonsInAuthority
        }
        guard let colon = input.firstIndex(of: ":") else {
            return (String(input), nil)
        }
        return (String(input[..<colon]), try parsePort(input[input.index(after: colon)...]))
    }

    /// Parse the digits after a `:` as a port. An empty port means "the scheme's default",
    /// which the URL standard also allows, so it maps to `nil`.
    private static func parsePort(_ input: Substring) throws(URLStringParsingError) -> Int? {
        if input.isEmpty {
            return nil
        }
        guard
            input.allSatisfy(\.isASCIIDigit),
            let port = Int(input),
            (0 ... 65535).contains(port)
        else {
            throw .invalidPort(String(input))
        }
        return port
    }
}

// MARK: - Character helpers

extension Unicode.Scalar {
    /// Whether this is a C0 control character or DEL.
    ///
    /// Deliberately defined on `Unicode.Scalar` rather than `Character`: a `Character`-level
    /// version has to decide what to do about multi-scalar clusters, and the only honest
    /// answer - "this cluster is not a single control" - is exactly the answer that lets a
    /// CR-LF pair through. Scanning scalars removes the question.
    var isC0Control: Bool {
        value <= 0x1F || value == 0x7F
    }
}

extension String {
    /// This string with ASCII `A`-`Z` lowercased and everything else untouched.
    var lowercasedASCII: String {
        String(
            decoding: utf8.map { byte in
                (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte) ? byte + 0x20 : byte
            },
            as: UTF8.self
        )
    }

    /// Whether this is a syntactically valid URL scheme: `ALPHA *( ALPHA / DIGIT / "+" /
    /// "-" / "." )`.
    var isValidURLScheme: Bool {
        guard let first, first.isASCIILetter else {
            return false
        }
        return allSatisfy { $0.isASCIILetter || $0.isASCIIDigit || "+-.".contains($0) }
    }
}

extension Character {
    /// Whether this is one of `a`-`z` or `A`-`Z`.
    var isASCIILetter: Bool {
        (self >= "a" && self <= "z") || (self >= "A" && self <= "Z")
    }
}

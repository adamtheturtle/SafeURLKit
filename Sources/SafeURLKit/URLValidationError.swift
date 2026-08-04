//
//  URLValidationError.swift
//  SafeURLKit
//
//  Why a URL failed its policy.
//
//  The cases are specific because rejections get logged and read later. "Invalid URL"
//  tells an on-call engineer nothing; "2130706433 is in 127.0.0.0/8 (loopback)" tells them
//  both what was blocked and that somebody was writing loopback in a way meant to slip
//  past a check.
//

import Foundation

/// Why a URL did not satisfy a ``URLPolicy``.
public enum URLValidationError: Error, Sendable, Hashable, CustomStringConvertible {
    /// The URL string is not an unambiguous authority-based absolute URL.
    case malformedURL(reason: String)

    /// SafeURLKit and Foundation read the URL differently.
    ///
    /// This is a rejection rather than a tiebreak on purpose. Whichever reading is
    /// "right", the request would be issued by Foundation while the check was made against
    /// something else, so the check would be worthless. See ``URLPolicy`` for the
    /// reasoning.
    case parserDisagreement(safeURLKit: String, foundation: String)

    /// The URL string has more UTF-8 bytes than the policy's ``URLPolicy/maximumLength``.
    case tooLong(length: Int, limit: Int)

    /// The URL path contains more segments than ``URLPolicy/maximumPathSegments`` permits.
    case tooManyPathSegments(count: Int, limit: Int)

    /// The scheme is not in the policy's ``URLPolicy/allowedSchemes``.
    case disallowedScheme(String)

    /// The URL carries a username or password, which the policy forbids.
    case credentialsPresent

    /// The URL carries a fragment, which the policy forbids.
    case fragmentPresent

    /// The URL carries a query, which the policy forbids.
    case queryPresent

    /// The host could not be parsed.
    case invalidHost(HostParsingError)

    /// The host is an IP literal, which the policy forbids.
    case ipLiteralHost(URLHost)

    /// The host falls under a reserved domain suffix such as `localhost` or `.internal`.
    case specialUseHostName(host: String, suffix: String)

    /// The host is an address in a reserved range, such as loopback, RFC 1918 space, or
    /// link-local space where the cloud metadata endpoint lives.
    case specialPurposeAddress(SpecialPurposeMatch)

    /// The port is not permitted by the policy's ``URLPolicy/portRule``.
    case disallowedPort(Int)

    /// The origin matched none of the policy's ``URLPolicy/allowedOrigins``.
    case originNotAllowed(origin: String)

    public var description: String {
        switch self {
        case let .malformedURL(reason):
            "malformed URL: \(reason)"
        case let .parserDisagreement(safeURLKit, foundation):
            """
            URL parsers disagree: SafeURLKit reads the host as \(safeURLKit.debugDescription) \
            and Foundation reads it as \(foundation.debugDescription)
            """
        case let .tooLong(length, limit):
            "the URL is \(length) UTF-8 bytes, over the \(limit)-byte limit"
        case let .tooManyPathSegments(count, limit):
            "the URL path has \(count) segments, over the \(limit)-segment limit"
        case let .disallowedScheme(scheme):
            "the scheme \(scheme.debugDescription) is not allowed"
        case .credentialsPresent:
            "the URL contains embedded credentials"
        case .fragmentPresent:
            "the URL contains a fragment"
        case .queryPresent:
            "the URL contains a query"
        case let .invalidHost(error):
            "invalid host: \(error)"
        case let .ipLiteralHost(host):
            "the host \(host) is an IP address literal, and only named hosts are allowed"
        case let .specialUseHostName(host, suffix):
            "the host \(host.debugDescription) is under the reserved suffix \(suffix.debugDescription)"
        case let .specialPurposeAddress(match):
            "the host resolves to a reserved address: \(match)"
        case let .disallowedPort(port):
            "port \(port) is not allowed"
        case let .originNotAllowed(origin):
            "the origin \(origin.debugDescription) is not in the allow-list"
        }
    }
}

extension URLValidationError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}

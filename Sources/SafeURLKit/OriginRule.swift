//
//  OriginRule.swift
//  SafeURLKit
//
//  How a policy says which hosts are acceptable.
//
//  Suffix matching is where allow-lists go wrong. A `hasSuffix("coderpad.io")` check
//  matches `evilcoderpad.io`, and it is an easy domain to register. Every rule here is
//  anchored at a label boundary for that reason, and the three cases exist so that a call
//  site says how strict it wants to be rather than getting one answer imposed on it.
//

import Foundation

/// One clause of a policy's origin allow-list. A URL passes if it matches any rule.
public enum OriginRule: Sendable, Hashable, CustomStringConvertible {
    /// An exact origin: scheme, host, and port must all match.
    ///
    /// `port` is the *effective* port, so pass `nil` to mean the scheme's default and
    /// match both `https://example.com` and `https://example.com:443`. Passing a port
    /// makes the rule reject the same host on any other port, which is the distinction
    /// that a host-only check silently loses: an attacker who can reach
    /// `https://internal.example.com:8080` has reached a different service than the one
    /// that was approved.
    ///
    /// - Important: A non-default `port` here also needs a ``URLPolicy/portRule`` that
    ///   admits it. The two checks are separate and both must pass - see
    ///   ``URLPolicy/portRule``.
    case origin(scheme: String, host: URLHost, port: Int?)

    /// An exact host, on any port the policy's port rule permits.
    case host(URLHost)

    /// A host suffix, anchored at a label boundary: the host must equal `suffix` or end in
    /// `"." + suffix`. So `.hostSuffix("coderpad.io")` matches `coderpad.io` and
    /// `app.coderpad.io`, and does not match `evilcoderpad.io`.
    ///
    /// Only domain names can match a suffix rule. An IP literal never does, whatever it
    /// looks like.
    case hostSuffix(String)

    public var description: String {
        switch self {
        case let .origin(scheme, host, port):
            port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
        case let .host(host):
            "\(host) (any port)"
        case let .hostSuffix(suffix):
            "*.\(suffix)"
        }
    }
}

extension OriginRule {
    /// A rule matching one exact origin, written as a URL string.
    ///
    /// This is the convenient way to write configured origins that arrive as strings, such
    /// as a self-hosted instance's base URL. Throws if the string is not a URL with a
    /// parseable host, so a misconfigured value fails loudly at configuration time instead
    /// of becoming a silent `nil` that an allow-list never notices is missing.
    ///
    /// - Parameter urlString: An absolute URL, for example `"https://example.com:8443"`.
    ///   Any path, query, and fragment are ignored.
    public static func origin(matching urlString: String) throws -> OriginRule {
        guard
            let parsed = try? ParsedURLString.parse(urlString),
            let host = try? URLHost.parse(parsed.hostText)
        else {
            throw URLValidationError.malformedURL(
                reason: "cannot build an origin rule from \(urlString.debugDescription)"
            )
        }
        return .origin(scheme: parsed.scheme, host: host, port: parsed.port)
    }

    /// Whether `host` on `port` under `scheme` satisfies this rule.
    ///
    /// - Parameters:
    ///   - scheme: The URL's ASCII-lowercased scheme.
    ///   - host: The URL's parsed host.
    ///   - port: The URL's effective port, with the scheme's default already filled in.
    func matches(scheme: String, host: URLHost, port: Int) -> Bool {
        switch self {
        case let .origin(ruleScheme, ruleHost, rulePort):
            let expectedPort = rulePort ?? URLPolicy.defaultPort(forScheme: ruleScheme)
            return ruleScheme.lowercasedASCII == scheme
                && ruleHost == host
                && expectedPort == port
        case let .host(ruleHost):
            return ruleHost == host
        case let .hostSuffix(suffix):
            guard case let .domain(name) = host else {
                return false
            }
            let normalized = suffix.lowercasedASCII
            return name == normalized || name.hasSuffix(".\(normalized)")
        }
    }
}

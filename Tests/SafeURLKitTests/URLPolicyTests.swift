//
//  URLPolicyTests.swift
//  SafeURLKitTests
//
//  Each policy axis, exercised on its own: what the default rejects, and what turning a
//  single flag on then permits.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("URL policy")
struct URLPolicyTests {
    @Test("The default policy accepts an ordinary public HTTPS URL")
    func happyPath() throws {
        let validated = try URLPolicy.publicHTTPS.validate("https://coderpad.io/a/b?c=d")
        #expect(validated.scheme == "https")
        #expect(validated.host == .domain("coderpad.io"))
        #expect(validated.port == 443)
        #expect(validated.origin == "https://coderpad.io:443")
        #expect(validated.url.absoluteString == "https://coderpad.io/a/b?c=d")
    }

    @Test("Path segment count remains bounded when the text limit is disabled")
    func pathSegmentLimit() throws {
        let path = Array(repeating: "x", count: 257).joined(separator: "/")
        let url = "https://coderpad.io/\(path)"
        let policy = URLPolicy(maximumLength: nil)

        #expect(throws: URLValidationError.tooManyPathSegments(count: 257, limit: 256)) {
            try policy.validate(url)
        }

        let explicitlyUnbounded = URLPolicy(maximumLength: nil, maximumPathSegments: nil)
        #expect(explicitlyUnbounded.allows(url))
    }

    @Test("An explicit default port is accepted and normalizes to the same origin")
    func explicitDefaultPort() throws {
        let validated = try URLPolicy.publicHTTPS.validate("https://coderpad.io:443/a")
        #expect(validated.port == 443)
        #expect(validated.origin == "https://coderpad.io:443")
    }

    // MARK: Schemes

    @Test(
        "Only allowed schemes pass, and scheme matching is case-insensitive",
        arguments: [
            ("https://coderpad.io/", true),
            ("HTTPS://coderpad.io/", true),
            ("HtTpS://coderpad.io/", true),
            ("http://coderpad.io/", false),
            ("ftp://coderpad.io/", false),
            ("file://coderpad.io/", false),
            ("javascript://coderpad.io/", false),
            ("data://coderpad.io/", false)
        ]
    )
    func schemes(_ urlString: String, _ allowed: Bool) {
        #expect(URLPolicy.publicHTTPS.allows(urlString) == allowed)
    }

    @Test("A policy may allow plaintext HTTP, as a self-hosted origin needs")
    func httpAllowed() throws {
        let policy = URLPolicy(allowedSchemes: ["https", "http"])
        #expect(try policy.validate("http://coderpad.io/").port == 80)
        #expect(try policy.validate("https://coderpad.io/").port == 443)
    }

    @Test("Allowed schemes stay normalized after mutation")
    func mutatedSchemesAreNormalized() throws {
        var policy = URLPolicy()

        policy.allowedSchemes = ["HTTP"]

        #expect(policy.allowedSchemes == ["http"])
        #expect(try policy.validate("http://coderpad.io/").scheme == "http")
        #expect(!policy.allows("https://coderpad.io/"))
    }

    @Test("Schemeless, relative, and authority-less URLs are malformed")
    func malformed() {
        for urlString in ["coderpad.io", "/path", "https:coderpad.io", "mailto:a@coderpad.io", ""] {
            #expect(!URLPolicy.publicHTTPS.allows(urlString))
        }
    }

    // MARK: Credentials, fragments, queries

    @Test("Embedded credentials are rejected by default")
    func credentials() throws {
        #expect(throws: URLValidationError.credentialsPresent) {
            try URLPolicy.publicHTTPS.validate("https://user:pass@coderpad.io/")
        }
        #expect(throws: URLValidationError.credentialsPresent) {
            try URLPolicy.publicHTTPS.validate("https://user@coderpad.io/")
        }
        // A bare `@` is an empty userinfo section, not credentials.
        #expect(try URLPolicy.publicHTTPS.validate("https://@coderpad.io/").host
            == .domain("coderpad.io"))
    }

    @Test("Fragments are rejected by default and allowed on request")
    func fragments() throws {
        #expect(throws: URLValidationError.fragmentPresent) {
            try URLPolicy.publicHTTPS.validate("https://coderpad.io/a#frag")
        }
        // A bare trailing `#` carries no fragment payload and is allowed.
        #expect(URLPolicy.publicHTTPS.allows("https://coderpad.io/a#"))
        let permissive = URLPolicy(allowsFragment: true)
        #expect(permissive.allows("https://coderpad.io/a#frag"))
    }

    @Test("Queries are allowed by default and can be forbidden")
    func queries() throws {
        #expect(URLPolicy.publicHTTPS.allows("https://coderpad.io/a?b=c"))
        let thumbnailOnly = URLPolicy(allowsQuery: false)
        #expect(throws: URLValidationError.queryPresent) {
            try thumbnailOnly.validate("https://coderpad.io/a?b=c")
        }
        #expect(throws: URLValidationError.queryPresent) {
            try thumbnailOnly.validate("https://coderpad.io/a#notaquery?b=c")
        }
        #expect(thumbnailOnly.allows("https://coderpad.io/a"))
    }

    // MARK: Ports

    @Test("The default port rule accepts only the scheme's default port")
    func defaultPortRule() throws {
        #expect(URLPolicy.publicHTTPS.allows("https://coderpad.io/"))
        #expect(URLPolicy.publicHTTPS.allows("https://coderpad.io:443/"))
        #expect(throws: URLValidationError.disallowedPort(8443)) {
            try URLPolicy.publicHTTPS.validate("https://coderpad.io:8443/")
        }
    }

    @Test("An explicit port list is exactly what it says")
    func allowedPorts() throws {
        let policy = URLPolicy(portRule: .allowed([443, 8443]))
        #expect(policy.allows("https://coderpad.io/"))
        #expect(policy.allows("https://coderpad.io:8443/"))
        #expect(throws: URLValidationError.disallowedPort(8444)) {
            try policy.validate("https://coderpad.io:8444/")
        }

        // Omitting the default port from the list really does exclude it.
        let unusualOnly = URLPolicy(portRule: .allowed([8443]))
        #expect(!unusualOnly.allows("https://coderpad.io/"))
    }

    @Test("The any-port rule accepts any port in range and still rejects nonsense")
    func anyPort() throws {
        let policy = URLPolicy(portRule: .any)
        #expect(try policy.validate("https://coderpad.io:1/").port == 1)
        #expect(try policy.validate("https://coderpad.io:65535/").port == 65535)
        #expect(!policy.allows("https://coderpad.io:65536/"))
        #expect(!policy.allows("https://coderpad.io:-1/"))
        #expect(!policy.allows("https://coderpad.io:80x/"))
        // Port 0 is reserved and never a usable destination.
        #expect(throws: URLValidationError.disallowedPort(0)) {
            try policy.validate("https://coderpad.io:0/")
        }
        // An empty port means the scheme's default.
        #expect(try policy.validate("https://coderpad.io:/").port == 443)
    }

    @Test("A custom scheme with no default port must give one explicitly")
    func schemeWithoutDefaultPort() throws {
        let policy = URLPolicy(allowedSchemes: ["myapp"], portRule: .any)
        // Nothing names a destination port here, so there is nothing to approve.
        #expect(!policy.allows("myapp://coderpad.io/"))
        #expect(try policy.validate("myapp://coderpad.io:9000/").port == 9000)
    }

    @Test("Known schemes get their default port filled in")
    func defaultPorts() {
        #expect(URLPolicy.defaultPort(forScheme: "https") == 443)
        #expect(URLPolicy.defaultPort(forScheme: "HTTPS") == 443)
        #expect(URLPolicy.defaultPort(forScheme: "http") == 80)
        #expect(URLPolicy.defaultPort(forScheme: "ws") == 80)
        #expect(URLPolicy.defaultPort(forScheme: "wss") == 443)
        #expect(URLPolicy.defaultPort(forScheme: "ftp") == 21)
        #expect(URLPolicy.defaultPort(forScheme: "myapp") == nil)
    }

    // MARK: Hosts

    @Test("IP-literal hosts are rejected by default, however they are spelled")
    func ipLiterals() throws {
        for urlString in [
            "https://93.184.216.34/",
            "https://[2606:4700::1111]/",
            "https://2130706433/",
            "https://0x7f.1/"
        ] {
            #expect(!URLPolicy.publicHTTPS.allows(urlString), "\(urlString) should be rejected")
        }
    }

    @Test("Allowing IP literals still keeps reserved ranges out")
    func literalsButNotReserved() throws {
        let policy = URLPolicy(allowsIPLiteralHosts: true)
        #expect(policy.allows("https://93.184.216.34/"))
        #expect(policy.allows("https://[2606:4700::1111]/"))

        for urlString in ["https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/"] {
            guard case .specialPurposeAddress = try #require(policy.rejection(for: urlString)) else {
                Issue.record("\(urlString) should be rejected as a reserved address")
                continue
            }
        }
    }

    @Test("Both flags together permit a loopback URL, as a local test server needs")
    func fullyPermissive() throws {
        let policy = URLPolicy(
            allowedSchemes: ["http"],
            portRule: .any,
            allowsIPLiteralHosts: true,
            allowsSpecialUseHostNames: true,
            allowsSpecialPurposeAddresses: true
        )
        #expect(try policy.validate("http://127.0.0.1:8080/").port == 8080)
        #expect(policy.allows("http://localhost:3000/"))
        #expect(policy.allows("http://[::1]:3000/"))
    }

    @Test("Reserved host names are rejected by default")
    func reservedNames() throws {
        for urlString in [
            "https://localhost/",
            "https://localhost./",
            "https://api.localhost/",
            "https://printer.local/",
            "https://metadata.google.internal/"
        ] {
            guard
                case .specialUseHostName = try #require(
                    URLPolicy.publicHTTPS.rejection(for: urlString)
                )
            else {
                Issue.record("\(urlString) should be rejected as a reserved name")
                continue
            }
        }
    }

    @Test("An explicit allow-list entry can override the special-use host name block")
    func allowListOverridesSpecialUseName() throws {
        let policy = URLPolicy(
            allowedSchemes: ["http"],
            allowedOrigins: [.host(.domain("localhost"))],
            portRule: .any
        )
        #expect(try policy.validate("http://localhost:3000/").host == .domain("localhost"))
        // Other reserved names still fail.
        #expect(!policy.allows("http://printer.local:3000/"))
    }

    // MARK: Length

    @Test("The length limit is applied to the string's UTF-8 representation")
    func lengthLimit() throws {
        let long = "https://coderpad.io/" + String(repeating: "a", count: 3000)
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(long)
        }
        var policy = URLPolicy.publicHTTPS
        policy.maximumLength = nil
        #expect(policy.allows(long))
    }

    @Test("Combining scalars cannot bypass the UTF-8 byte limit")
    func combiningScalarsRespectLengthLimit() throws {
        let url = "https://example.com/" + "e" + String(repeating: "\u{0301}", count: 100)
        let policy = URLPolicy(maximumLength: 64)

        #expect(url.count == 21)
        #expect(url.utf8.count > 64)
        #expect(throws: URLValidationError.tooLong(length: url.utf8.count, limit: 64)) {
            try policy.validate(url)
        }
    }

    // MARK: URL overload

    @Test("Validating a URL value checks its absolute string")
    func urlOverload() throws {
        let url = try #require(URL(string: "https://coderpad.io/a"))
        #expect(try URLPolicy.publicHTTPS.validate(url).host == .domain("coderpad.io"))
        #expect(URLPolicy.publicHTTPS.allows(url))

        let bad = try #require(URL(string: "https://127.0.0.1/"))
        #expect(!URLPolicy.publicHTTPS.allows(bad))
    }

    @Test("Relative URLs are rejected explicitly by validate(URL)")
    func relativeURLRejected() throws {
        let relative = try #require(URL(string: "/path"))
        #expect(relative.host == nil)
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(relative)
        }
    }

    @Test("ValidatedURL.scheme matches the scheme casing of ValidatedURL.url")
    func schemeCasingMatchesURL() throws {
        let validated = try URLPolicy.publicHTTPS.validate("HTTPS://coderpad.io/")
        #expect(validated.scheme == "https")
        #expect(validated.url.scheme?.lowercased() == "https")
    }

    // MARK: Errors

    @Test("Rejections describe both what was blocked and what it resolved to")
    func errorMessages() throws {
        let policy = URLPolicy(allowsIPLiteralHosts: true)
        let error = try #require(policy.rejection(for: "https://2130706433/"))
        #expect(error.description.contains("127.0.0.1"))
        #expect(error.description.contains("loopback"))
    }

    @Test("Resolved addresses can be re-checked after DNS lookup")
    func validateResolvedAddresses() throws {
        let policy = URLPolicy.publicHTTPS

        #expect(throws: URLValidationError.self) {
            try policy.validate(resolvedAddress: IPv4Address(127, 0, 0, 1))
        }
        #expect(throws: URLValidationError.self) {
            try policy.validate(resolvedAddress: IPv4Address(169, 254, 169, 254))
        }
        #expect(throws: URLValidationError.self) {
            try policy.validate(resolvedAddress: IPv6Address.parse("::1"))
        }

        // Public addresses still fail the default policy's "no IP literals" rule, which is
        // what you want when connecting by address rather than by name.
        #expect(throws: URLValidationError.ipLiteralHost(.ipv4(IPv4Address(8, 8, 8, 8)))) {
            try policy.validate(resolvedAddress: IPv4Address(8, 8, 8, 8))
        }

        let literalsOK = URLPolicy(allowsIPLiteralHosts: true)
        try literalsOK.validate(resolvedAddress: IPv4Address(8, 8, 8, 8))
        try literalsOK.validate(resolvedHost: .ipv4(IPv4Address(93, 184, 216, 34)))
        #expect(throws: URLValidationError.self) {
            try literalsOK.validate(resolvedAddress: IPv4Address(10, 0, 0, 1))
        }
    }
}

extension URLPolicy {
    /// The error a URL is rejected with, or `nil` if it passes. Keeps the tests that care
    /// about *why* something failed from re-writing the same do/catch each time.
    func rejection(for urlString: String) -> URLValidationError? {
        do {
            _ = try validate(urlString)
            return nil
        } catch {
            return error
        }
    }
}

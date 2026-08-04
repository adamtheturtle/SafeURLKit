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
        let validated = try URLPolicy.publicHTTPS.validate("https://example.com/a/b?c=d")
        #expect(validated.scheme == "https")
        #expect(validated.host == .domain("example.com"))
        #expect(validated.port == 443)
        #expect(validated.origin == "https://example.com:443")
        #expect(validated.url.absoluteString == "https://example.com/a/b?c=d")
    }

    @Test("Path segment count remains bounded when the text limit is disabled")
    func pathSegmentLimit() throws {
        let path = Array(repeating: "x", count: 257).joined(separator: "/")
        let url = "https://example.com/\(path)"
        let policy = URLPolicy(maximumLength: nil)

        #expect(throws: URLValidationError.tooManyPathSegments(count: 257, limit: 256)) {
            try policy.validate(url)
        }

        let explicitlyUnbounded = URLPolicy(maximumLength: nil, maximumPathSegments: nil)
        #expect(explicitlyUnbounded.allows(url))
    }

    @Test("An explicit default port is accepted and normalizes to the same origin")
    func explicitDefaultPort() throws {
        let validated = try URLPolicy.publicHTTPS.validate("https://example.com:443/a")
        #expect(validated.port == 443)
        #expect(validated.origin == "https://example.com:443")
    }

    // MARK: Schemes

    @Test(
        "Only allowed schemes pass, and scheme matching is case-insensitive",
        arguments: [
            ("https://example.com/", true),
            ("HTTPS://example.com/", true),
            ("HtTpS://example.com/", true),
            ("http://example.com/", false),
            ("ftp://example.com/", false),
            ("file://example.com/", false),
            ("javascript://example.com/", false),
            ("data://example.com/", false)
        ]
    )
    func schemes(_ urlString: String, _ allowed: Bool) {
        #expect(URLPolicy.publicHTTPS.allows(urlString) == allowed)
    }

    @Test("A policy may allow plaintext HTTP, as a self-hosted origin needs")
    func httpAllowed() throws {
        let policy = URLPolicy(allowedSchemes: ["https", "http"])
        #expect(try policy.validate("http://example.com/").port == 80)
        #expect(try policy.validate("https://example.com/").port == 443)
    }

    @Test("Allowed schemes stay normalized after mutation")
    func mutatedSchemesAreNormalized() throws {
        var policy = URLPolicy()

        policy.allowedSchemes = ["HTTP"]

        #expect(policy.allowedSchemes == ["http"])
        #expect(try policy.validate("http://example.com/").scheme == "http")
        #expect(!policy.allows("https://example.com/"))
    }

    @Test("Schemeless, relative, and authority-less URLs are malformed")
    func malformed() {
        for urlString in ["example.com", "/path", "https:example.com", "mailto:a@example.com", ""] {
            #expect(!URLPolicy.publicHTTPS.allows(urlString))
        }
    }

    // MARK: Credentials, fragments, queries

    @Test("Embedded credentials are rejected by default")
    func credentials() throws {
        #expect(throws: URLValidationError.credentialsPresent) {
            try URLPolicy.publicHTTPS.validate("https://user:pass@example.com/")
        }
        #expect(throws: URLValidationError.credentialsPresent) {
            try URLPolicy.publicHTTPS.validate("https://user@example.com/")
        }
        // A bare `@` still counts: it is the marker that a userinfo section was written.
        #expect(throws: URLValidationError.credentialsPresent) {
            try URLPolicy.publicHTTPS.validate("https://@example.com/")
        }
    }

    @Test("Fragments are rejected by default and allowed on request")
    func fragments() throws {
        #expect(throws: URLValidationError.fragmentPresent) {
            try URLPolicy.publicHTTPS.validate("https://example.com/a#frag")
        }
        // An empty fragment is still a fragment.
        #expect(throws: URLValidationError.fragmentPresent) {
            try URLPolicy.publicHTTPS.validate("https://example.com/a#")
        }
        let permissive = URLPolicy(allowsFragment: true)
        #expect(permissive.allows("https://example.com/a#frag"))
    }

    @Test("Queries are allowed by default and can be forbidden")
    func queries() throws {
        #expect(URLPolicy.publicHTTPS.allows("https://example.com/a?b=c"))
        let thumbnailOnly = URLPolicy(allowsQuery: false)
        #expect(throws: URLValidationError.queryPresent) {
            try thumbnailOnly.validate("https://example.com/a?b=c")
        }
        #expect(thumbnailOnly.allows("https://example.com/a"))
    }

    // MARK: Ports

    @Test("The default port rule accepts only the scheme's default port")
    func defaultPortRule() throws {
        #expect(URLPolicy.publicHTTPS.allows("https://example.com/"))
        #expect(URLPolicy.publicHTTPS.allows("https://example.com:443/"))
        #expect(throws: URLValidationError.disallowedPort(8443)) {
            try URLPolicy.publicHTTPS.validate("https://example.com:8443/")
        }
    }

    @Test("An explicit port list is exactly what it says")
    func allowedPorts() throws {
        let policy = URLPolicy(portRule: .allowed([443, 8443]))
        #expect(policy.allows("https://example.com/"))
        #expect(policy.allows("https://example.com:8443/"))
        #expect(throws: URLValidationError.disallowedPort(8444)) {
            try policy.validate("https://example.com:8444/")
        }

        // Omitting the default port from the list really does exclude it.
        let unusualOnly = URLPolicy(portRule: .allowed([8443]))
        #expect(!unusualOnly.allows("https://example.com/"))
    }

    @Test("The any-port rule accepts any port in range and still rejects nonsense")
    func anyPort() throws {
        let policy = URLPolicy(portRule: .any)
        #expect(try policy.validate("https://example.com:1/").port == 1)
        #expect(try policy.validate("https://example.com:65535/").port == 65535)
        #expect(!policy.allows("https://example.com:65536/"))
        #expect(!policy.allows("https://example.com:-1/"))
        #expect(!policy.allows("https://example.com:80x/"))
        // An empty port means the scheme's default.
        #expect(try policy.validate("https://example.com:/").port == 443)
    }

    @Test("A custom scheme with no default port must give one explicitly")
    func schemeWithoutDefaultPort() throws {
        let policy = URLPolicy(allowedSchemes: ["myapp"], portRule: .any)
        // Nothing names a destination port here, so there is nothing to approve.
        #expect(!policy.allows("myapp://example.com/"))
        #expect(try policy.validate("myapp://example.com:9000/").port == 9000)
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

    // MARK: Length

    @Test("The length limit is applied to the string as written")
    func lengthLimit() throws {
        let long = "https://example.com/" + String(repeating: "a", count: 3000)
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(long)
        }
        var policy = URLPolicy.publicHTTPS
        policy.maximumLength = nil
        #expect(policy.allows(long))
    }

    // MARK: URL overload

    @Test("Validating a URL value checks its absolute string")
    func urlOverload() throws {
        let url = try #require(URL(string: "https://example.com/a"))
        #expect(try URLPolicy.publicHTTPS.validate(url).host == .domain("example.com"))
        #expect(URLPolicy.publicHTTPS.allows(url))

        let bad = try #require(URL(string: "https://127.0.0.1/"))
        #expect(!URLPolicy.publicHTTPS.allows(bad))
    }

    // MARK: Errors

    @Test("Rejections describe both what was blocked and what it resolved to")
    func errorMessages() throws {
        let policy = URLPolicy(allowsIPLiteralHosts: true)
        let error = try #require(policy.rejection(for: "https://2130706433/"))
        #expect(error.description.contains("127.0.0.1"))
        #expect(error.description.contains("loopback"))
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

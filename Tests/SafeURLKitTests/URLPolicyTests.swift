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
    @Test("An allow-listed IANA example domain passes without allowsSpecialUseHostNames")
    func exampleDomainAllowList() {
        let policy = URLPolicy(allowedOrigins: [.hostSuffix("example.com")])
        #expect(policy.allows("https://www.example.com/"))
        #expect(policy.allows("https://example.com/"))
    }

    @Test("The default policy accepts an ordinary public HTTPS URL")
    func happyPath() throws {
        let validated = try URLPolicy.publicHTTPS.validate("https://coderpad.io/a/b?c=d")
        #expect(validated.scheme == "https")
        #expect(validated.host == .domain("coderpad.io"))
        #expect(validated.port == 443)
        #expect(validated.origin == "https://coderpad.io")
        #expect(validated.url.absoluteString == "https://coderpad.io/a/b?c=d")
    }

    @Test("Dot and parent segments do not inflate the path segment limit")
    func normalizedPathSegmentCount() throws {
        let policy = URLPolicy(maximumPathSegments: 2)
        #expect(policy.allows("https://coderpad.io/a/./b/../c/"))
        #expect(!policy.allows("https://coderpad.io/a/b/c/"))
        #expect(URLPolicy.normalizedPathSegmentCount("/a/./b/../c") == 2)
    @Test("maximumPathSegments 0 traps at configuration time")
    func maximumPathSegmentsZero() async {
        await #expect(processExitsWith: .failure) {
            _ = URLPolicy(maximumPathSegments: 0)
        }
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
        #expect(validated.origin == "https://coderpad.io")
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

    @Test("ValidatedURL keeps Foundation's URL string; scheme is lowercased separately")
    func validatedURLPreservesInputSpelling() throws {
        let mixed = try URLPolicy.publicHTTPS.validate("HTTPS://coderpad.io/a%2Fb")
        #expect(mixed.scheme == "https")
        #expect(mixed.url.absoluteString == "HTTPS://coderpad.io/a%2Fb")
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
        // A bare `@` is empty userinfo, not credentials.
        #expect(try URLPolicy.publicHTTPS.validate("https://@coderpad.io/").host == .domain("coderpad.io"))
    }

    @Test("Fragments are rejected by default and allowed on request")
    func fragments() throws {
        #expect(throws: URLValidationError.fragmentPresent) {
            try URLPolicy.publicHTTPS.validate("https://coderpad.io/a#frag")
        }
        // A bare trailing `#` is not a fragment payload.
        let bareHash = try URLPolicy.publicHTTPS.validate("https://coderpad.io/a#")
        #expect(bareHash.url.absoluteString == "https://coderpad.io/a#")
        let permissive = URLPolicy(allowsFragment: true)
        #expect(permissive.allows("https://coderpad.io/a#frag"))
    }

    @Test("IPv6 origins use bracketed host serialization and omit the default port")
    func ipv6OriginSerialization() throws {
        let policy = URLPolicy(
            allowsIPLiteralHosts: true,
            allowsSpecialPurposeAddresses: true
        )
        let validated = try policy.validate("https://[::1]/")
        #expect(validated.origin == "https://[::1]")
    }

    @Test("Queries are allowed by default and can be forbidden")
    func queries() throws {
        #expect(URLPolicy.publicHTTPS.allows("https://coderpad.io/a?b=c"))
        let thumbnailOnly = URLPolicy(allowsQuery: false)
        #expect(throws: URLValidationError.queryPresent) {
            try thumbnailOnly.validate("https://coderpad.io/a?b=c")
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

    @Test("defaultPort knows ftp even though the default policy disallows it")
    func defaultPortIndependentOfAllowedSchemes() throws {
        // Presence in the default-port table is not scheme permission.
        #expect(!URLPolicy.publicHTTPS.allows("ftp://coderpad.io/"))
        #expect(URLPolicy.defaultPort(forScheme: "ftp") == 21)

        let ftp = URLPolicy(allowedSchemes: ["ftp"])
        #expect(try ftp.validate("ftp://coderpad.io/").port == 21)
        #expect(try ftp.validate("ftp://coderpad.io:21/").port == 21)
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

    @Test("maximumLength 0 traps at configuration time")
    func maximumLengthZero() async {
        await #expect(processExitsWith: .failure) {
            _ = URLPolicy(maximumLength: 0)
        }
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

    // MARK: Errors

    @Test("Rejections describe both what was blocked and what it resolved to")
    func errorMessages() throws {
        let policy = URLPolicy(allowsIPLiteralHosts: true)
        let error = try #require(policy.rejection(for: "https://2130706433/"))
        #expect(error.description.contains("127.0.0.1"))
        #expect(error.description.contains("loopback"))
    }

    @Test("parserDisagreement names the field that differed")
    func parserDisagreementField() {
        let error = URLValidationError.parserDisagreement(
            field: "port",
            safeURLKit: "443",
            foundation: "8443"
        )
        #expect(error.description.contains("port"))
        #expect(!error.description.contains("reads the host"))
    }

    // MARK: Post-DNS resolved addresses

    @Test("Post-DNS checks accept public addresses under publicHTTPS")
    func resolvedPublicAddresses() throws {
        try URLPolicy.publicHTTPS.validate(resolvedAddress: IPv4Address.parse("93.184.216.34"))
        try URLPolicy.publicHTTPS.validate(resolvedAddress: IPv6Address.parse("2606:4700::1111"))
        try URLPolicy.publicHTTPS.validate(resolvedHost: .ipv4(IPv4Address.parse("8.8.8.8")))
    }

    @Test("Post-DNS checks still reject reserved addresses")
    func resolvedReservedAddresses() throws {
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(resolvedAddress: IPv4Address.parse("127.0.0.1"))
        }
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(resolvedAddress: IPv4Address.parse("169.254.169.254"))
        }
        #expect(throws: URLValidationError.self) {
            try URLPolicy.publicHTTPS.validate(resolvedAddress: IPv6Address.parse("::1"))
        }
    }
}

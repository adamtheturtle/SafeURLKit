//
//  BypassCorpusTests.swift
//  SafeURLKitTests
//
//  The adversarial corpus: payloads whose entire purpose is to read as one destination to
//  a validator and another to a network stack.
//
//  Drawn from the PortSwigger URL validation bypass cheat sheet, the CVE-2020-28360
//  regression cases in frenchbread/private-ip, and JordanMilne/Advocate's address corpus.
//  These are the tests that would have caught the bugs the three in-app guards were each
//  patched for separately.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("Bypass corpus")
struct BypassCorpusTests {
    /// A policy that allows only `coderpad.io` and its subdomains over HTTPS - the shape a
    /// real call site has. Every payload below tries to reach somewhere else through it.
    private static let policy = URLPolicy(
        allowedSchemes: ["https"],
        allowedOrigins: [.hostSuffix("coderpad.io")]
    )

    @Test(
        "Userinfo confusion never reaches the host after the @",
        arguments: [
            "https://coderpad.io@evil.com/",
            "https://coderpad.io:443@evil.com/",
            "https://coderpad.io@evil.com@evil2.com/",
            "https://user:coderpad.io@evil.com/",
            "https://evil.com@coderpad.io@evil.com/",
            "https://coderpad.io%40evil.com/",
            "https://coderpad.io%2f@evil.com/"
        ]
    )
    func userinfoConfusion(_ urlString: String) {
        // Either the URL is rejected for carrying credentials or the host is read as
        // `evil.com` and fails the allow-list. Both are correct; being accepted is not.
        #expect(!Self.policy.allows(urlString))
    }

    @Test("The host is the text after the last @, not the first")
    func lastAtWins() throws {
        let policy = URLPolicy(allowsCredentials: true, allowsIPLiteralHosts: true)
        #expect(try policy.validate("https://coderpad.io@93.184.216.34/").host
            == .ipv4(IPv4Address(93, 184, 216, 34)))
        #expect(try policy.validate("https://a@b@github.com/").host == .domain("github.com"))
    }

    @Test(
        "Suffix rules are anchored, so a lookalike registration does not match",
        arguments: [
            "https://evilcoderpad.io/",
            "https://notcoderpad.io/",
            "https://coderpad.io.evil.com/",
            "https://coderpad.iomercial.net/",
            "https://xcoderpad.io/"
        ]
    )
    func suffixAnchoring(_ urlString: String) {
        #expect(!Self.policy.allows(urlString))
    }

    @Test(
        "Legitimate subdomains of an allowed suffix do match",
        arguments: [
            "https://coderpad.io/",
            "https://www.coderpad.io/",
            "https://a.b.c.coderpad.io/",
            "https://CODERPAD.IO/",
            "https://coderpad.io./"
        ]
    )
    func suffixMatches(_ urlString: String) {
        #expect(Self.policy.allows(urlString))
    }

    @Test(
        "Every exotic spelling of an internal destination is rejected",
        arguments: [
            // Loopback.
            "https://127.0.0.1/",
            "https://127.1/",
            "https://2130706433/",
            "https://0177.0.0.1/",
            "https://0x7f.0.0.1/",
            "https://0x7f000001/",
            "https://017700000001/",
            "https://[::1]/",
            "https://[0:0:0:0:0:0:0:1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:7f00:1]/",
            "https://localhost/",
            "https://LOCALHOST/",
            "https://localhost./",
            "https://api.localhost/",
            "https://127.0.0.1.localhost/",
            // Cloud metadata.
            "https://169.254.169.254/",
            "https://0xa9fea9fe/",
            "https://2852039166/",
            "https://0251.0376.0251.0376/",
            "https://[::ffff:169.254.169.254]/",
            "https://[::ffff:a9fe:a9fe]/",
            "https://[2002:a9fe:a9fe::]/",
            "https://[64:ff9b::169.254.169.254]/",
            "https://metadata.google.internal/",
            "https://metadata.google.internal./",
            // Private space.
            "https://10.0.0.1/",
            "https://192.168.1.1/",
            "https://172.16.0.1/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://printer.local/",
            // Broadcast and unspecified.
            "https://0.0.0.0/",
            "https://255.255.255.255/",
            "https://[::]/"
        ]
    )
    func internalDestinations(_ urlString: String) {
        // Checked against a policy with *no* origin allow-list, so the rejection comes from
        // the address and name rules rather than from the allow-list doing the work.
        #expect(!URLPolicy.publicHTTPS.allows(urlString), "\(urlString) should be rejected")
    }

    @Test(
        "Characters that URL parsers disagree about are refused rather than normalized",
        arguments: [
            "https://coderpad.io\\@evil.com/",
            "https://evil.com\\.coderpad.io/",
            "https://exam\tple.com/",
            "https://coderpad.io\n/",
            "https://coderpad.io\r\n/",
            "https://exa mple.com/",
            "https://coderpad.io\u{0000}.evil.com/",
            "http\t s://coderpad.io/"
        ]
    )
    func parserDisagreementCharacters(_ urlString: String) {
        #expect(!Self.policy.allows(urlString))
    }

    @Test(
        "Scheme games do not get past the scheme check",
        arguments: [
            "javascript:alert(1)//https://coderpad.io",
            "data:text/html,<script>1</script>",
            "file:///etc/passwd",
            "gopher://coderpad.io/",
            "https:/coderpad.io/",
            "https:coderpad.io/",
            "//coderpad.io/",
            "hTTps://coderpad.io/"
        ]
    )
    func schemeGames(_ urlString: String) throws {
        // The last one is a legitimate mixed-case `https`, which must be *accepted* - a
        // check that lowercases before comparing gets this right and a `==` does not.
        let expected = urlString == "hTTps://coderpad.io/"
        #expect(Self.policy.allows(urlString) == expected)
    }

    @Test(
        "Percent-encoded hosts are decoded before the allow-list is consulted",
        arguments: [
            "https://%63oderpad.io/",
            "https://c%6fderpad.io/",
            "https://CODERPAD%2EIO/"
        ]
    )
    func percentEncodedAllowed(_ urlString: String) {
        // These decode to `coderpad.io`, so they legitimately match the suffix rule. The
        // point is that the decision is made on the decoded host, not the written one.
        #expect(Self.policy.allows(urlString))
    }

    @Test(
        "Percent-encoding cannot smuggle a different host past the allow-list",
        arguments: [
            "https://evil%2ecom/",
            "https://%65vil.com/",
            "https://example%2ecom%2eevil.com/",
            "https://127%2e0%2e0%2e1/"
        ]
    )
    func percentEncodedRejected(_ urlString: String) {
        #expect(!Self.policy.allows(urlString))
    }

    @Test(
        "Unicode and internationalized hosts are refused, not guessed at",
        arguments: [
            "https://ехample.com/",
            "https://exаmple.com/",
            "https://例え.テスト/"
        ]
    )
    func unicodeHosts(_ urlString: String) throws {
        // The first two use Cyrillic homographs. SafeURLKit does not implement IDNA, so
        // rather than transcode approximately - and risk checking a different host than the
        // one that gets fetched - it rejects. Callers punycode first if they need these.
        #expect(!Self.policy.allows(urlString))
    }

    @Test("A punycoded host is checked as the ASCII name it is")
    func punycode() throws {
        let policy = URLPolicy(allowedOrigins: [.hostSuffix("xn--e1afmkfd.xn--p1ai")])
        #expect(policy.allows("https://xn--e1afmkfd.xn--p1ai/"))
        #expect(!policy.allows("https://xn--e1afmkfd.xn--p1ai.evil.com/"))
    }

    @Test(
        "Same host on a different port is a different origin",
        arguments: ["https://coderpad.io:8443/", "https://coderpad.io:8080/", "https://coderpad.io:1/"]
    )
    func portConfusion(_ urlString: String) {
        // The bug that #1748 was filed for: a host-only comparison lets an approved name on
        // an unapproved port through, and that is a different service.
        #expect(!Self.policy.allows(urlString))
    }

    @Test("An exact-origin rule pins the port as well as the host")
    func exactOrigin() throws {
        let policy = URLPolicy(
            allowedOrigins: [.origin(scheme: "https", host: .domain("coderpad.io"), port: 8443)],
            portRule: .any
        )
        #expect(policy.allows("https://coderpad.io:8443/"))
        #expect(!policy.allows("https://coderpad.io/"))
        #expect(!policy.allows("https://coderpad.io:443/"))
        #expect(!policy.allows("https://other.coderpad.io:8443/"))
    }

    @Test("The port rule and the origin list are separate checks, and both must pass")
    func portRuleAndOriginListCombine() throws {
        // Pinning the footgun: an origin rule naming a non-default port is not enough on
        // its own, because the port rule is checked first and rejects before the origin
        // list is ever consulted.
        let origins: [OriginRule] = [
            .origin(scheme: "https", host: .domain("coderpad.io"), port: 8443)
        ]
        #expect(!URLPolicy(allowedOrigins: origins).allows("https://coderpad.io:8443/"))
        #expect(
            URLPolicy(allowedOrigins: origins, portRule: .allowed([8443]))
                .allows("https://coderpad.io:8443/")
        )
    }

    @Test("A host rule accepts any port the port rule admits")
    func hostRule() throws {
        let policy = URLPolicy(
            allowedOrigins: [.host(.domain("coderpad.io"))],
            portRule: .allowed([443, 8443])
        )
        #expect(policy.allows("https://coderpad.io/"))
        #expect(policy.allows("https://coderpad.io:8443/"))
        #expect(!policy.allows("https://coderpad.io:9000/"))
        #expect(!policy.allows("https://other.coderpad.io/"))
    }

    @Test("An origin rule can be written as a URL string, and throws if unparseable")
    func originFromString() throws {
        let rule = try OriginRule.origin(matching: "https://coderpad.io:8443")
        #expect(rule == .origin(scheme: "https", host: .domain("coderpad.io"), port: 8443))
        #expect(throws: URLValidationError.self) {
            try OriginRule.origin(matching: "not a url")
        }
        #expect(throws: URLValidationError.self) {
            try OriginRule.origin(matching: "")
        }

        // A default-port origin string produces a rule with no explicit port, which then
        // matches both spellings of that origin.
        let implicit = try OriginRule.origin(matching: "https://coderpad.io")
        let policy = URLPolicy(allowedOrigins: [implicit])
        #expect(policy.allows("https://coderpad.io/"))
        #expect(policy.allows("https://coderpad.io:443/"))
    }

    @Test("An empty origin list rejects everything, so a misconfiguration fails closed")
    func emptyAllowList() {
        let policy = URLPolicy(allowedOrigins: [])
        #expect(!policy.allows("https://coderpad.io/"))
        #expect(!policy.allows("https://anything.at.all/"))
    }

    @Test("A nil origin list means no host restriction, not no checks")
    func nilAllowList() {
        let policy = URLPolicy(allowedOrigins: nil)
        #expect(policy.allows("https://anything.github.com/"))
        #expect(!policy.allows("https://127.0.0.1/"))
    }
}

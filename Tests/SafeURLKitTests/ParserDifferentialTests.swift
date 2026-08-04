//
//  ParserDifferentialTests.swift
//  SafeURLKitTests
//
//  The property that makes the rest of the package worth anything: the URL that gets
//  fetched is the URL that got checked.
//
//  Foundation does the fetching, so if Foundation reads a different host out of the string
//  than SafeURLKit did, the check guarded nothing. These tests pin that every URL which
//  passes validation is one Foundation agrees about.
//

import Foundation
@testable import SafeURLKit
import Testing

@Suite("Parser agreement")
struct ParserDifferentialTests {
    /// Every URL a test in this file might accept, exercised against the loosest policy
    /// that could accept it, so the only thing left doing the rejecting is disagreement.
    private static let permissive = URLPolicy(
        allowedSchemes: ["https", "http"],
        portRule: .any,
        allowsCredentials: true,
        allowsFragment: true,
        allowsIPLiteralHosts: true,
        allowsSpecialUseHostNames: true,
        allowsSpecialPurposeAddresses: true,
        maximumLength: nil
    )

    @Test(
        "Anything that validates, Foundation reads the same way",
        arguments: [
            "https://example.com/",
            "https://example.com:8443/a/b?c=d#e",
            "https://user:pass@example.com/",
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]:8080/",
            "http://localhost:3000/path",
            "https://example.com./",
            "https://ex%61mple.com/"
        ]
    )
    func agreement(_ urlString: String) throws {
        let validated = try Self.permissive.validate(urlString)
        let components = try #require(URLComponents(string: urlString))

        // Re-read Foundation's host through the same parser and confirm it denotes the
        // same destination.
        let foundationHost = try #require(components.percentEncodedHost)
        let bracketed =
            foundationHost.contains(":") && !foundationHost.hasPrefix("[")
                ? "[\(foundationHost)]"
                : foundationHost
        #expect(try URLHost.parse(bracketed) == validated.host)

        let foundationPort = components.port ?? URLPolicy.defaultPort(forScheme: validated.scheme)
        #expect(foundationPort == validated.port)
    }

    @Test("A punycoded host is accepted even though Foundation reports it decoded")
    func punycodeAgreement() throws {
        // `URLComponents.percentEncodedHost` IDNA-*decodes*: for `xn--e1afmkfd.xn--p1ai` it
        // returns the percent-encoded Cyrillic `пример.рф`, which this package's parser
        // rejects by design. The cross-check handles that by comparing renderings instead,
        // so a legitimate punycoded host is not mistaken for a parser disagreement.
        let validated = try Self.permissive.validate("https://xn--e1afmkfd.xn--p1ai/")
        #expect(validated.host == .domain("xn--e1afmkfd.xn--p1ai"))

        let components = try #require(URLComponents(string: "https://xn--e1afmkfd.xn--p1ai/"))
        #expect(components.percentEncodedHost?.allSatisfy(\.isASCII) == true)
        #expect(components.host == "пример.рф")
    }

    @Test("A genuine host disagreement is still a rejection, not a rendering match")
    func genuineDisagreement() throws {
        // Guard against the punycode fallback becoming a hole: two different hosts must not
        // render to the same thing.
        let error = try #require(Self.permissive.rejection(for: "https://exаmple.com/"))
        guard case .parserDisagreement = error else {
            // Rejected earlier, by the non-ASCII host rule, which is equally correct.
            #expect(error.description.contains("non-ASCII"))
            return
        }
    }

    @Test("The returned URL is the one that was validated")
    func returnedURL() throws {
        let validated = try Self.permissive.validate("https://example.com:8443/a?b=c#d")
        #expect(validated.url.absoluteString == "https://example.com:8443/a?b=c#d")
    }

    @Test("A URL Foundation cannot parse at all is rejected")
    func foundationCannotParse() {
        // Nothing here should ever reach the disagreement check - the string parser refuses
        // first - but the policy must reject either way.
        for urlString in ["https://[/", "https://exa[mple.com/", "https://example.com:99999/"] {
            #expect(!Self.permissive.allows(urlString))
        }
    }

    @Test("Backslashes are refused because parsers disagree about them")
    func backslashes() {
        // WHATWG treats `\` as a path separator for HTTP URLs and Foundation does not, so
        // `https://evil.com\@example.com/` is two different origins depending who reads it.
        #expect(!Self.permissive.allows("https://evil.com\\@example.com/"))
        #expect(!Self.permissive.allows("https://example.com\\..\\evil.com/"))
    }

    @Test("Tabs and newlines are refused because WHATWG strips them and Foundation does not")
    func whitespaceStripping() {
        #expect(!Self.permissive.allows("https://exam\tple.com/"))
        #expect(!Self.permissive.allows("https://exam\nple.com/"))
        #expect(!Self.permissive.allows("https://exam\rple.com/"))
        // A literal CR-LF pair is one `Character` but two forbidden scalars, and the scan
        // is over scalars precisely so that this is not a hole.
        #expect(!Self.permissive.allows("https://exam\r\nple.com/"))
        #expect(!Self.permissive.allows("https://example.com/?a=x\r\nb"))
        #expect(!Self.permissive.allows("https://example.com/\r\n"))
    }

    @Test(
        "C1 and Unicode format controls are rejected throughout the URL",
        arguments: [
            "https://example.com/path\u{0085}suffix",
            "https://example.com/path\u{202E}suffix",
            "https://example.com/path?key=before\u{200B}after",
            "https://example.com/path#before\u{2066}after"
        ]
    )
    func nonPrintingControls(_ urlString: String) {
        #expect(throws: URLStringParsingError.self) {
            try ParsedURLString.parse(urlString)
        }
        #expect(!Self.permissive.allows(urlString))
    }

    @Test("The forbidden-character scan sees both scalars of a CR-LF pair")
    func crlfIsTwoScalars() throws {
        // The property the fix rests on, stated directly: Swift's grapheme clustering is
        // what made the pair invisible, and `Character.isASCII` agreeing made it worse.
        let crlf = "\r\n"
        #expect(crlf.count == 1)
        #expect(crlf.unicodeScalars.count == 2)
        let everyCharacterLooksASCII = crlf.allSatisfy(\.isASCII)
        #expect(everyCharacterLooksASCII)

        #expect(throws: URLStringParsingError.self) {
            try ParsedURLString.parse("https://example.com/\r\n")
        }
    }

    @Test("An authority with more than one colon is ambiguous and refused")
    func ambiguousAuthority() {
        #expect(!Self.permissive.allows("https://example.com:80:443/"))
        #expect(!Self.permissive.allows("https://a:b:c/"))
    }

    @Test("Text after an IPv6 literal, other than a port, is refused")
    func junkAfterLiteral() {
        #expect(!Self.permissive.allows("https://[::1]x/"))
        #expect(!Self.permissive.allows("https://[::1]evil.com/"))
        #expect(Self.permissive.allows("https://[::1]:8080/"))
    }
}

@Suite("URL string splitting")
struct URLStringParserTests {
    @Test("An absolute URL splits into the parts a policy checks")
    func split() throws {
        let parsed = try ParsedURLString.parse("HTTPS://user:pw@Example.COM:8443/p/q?a=b#frag")
        #expect(parsed.scheme == "https")
        #expect(parsed.userinfo == "user:pw")
        // The host keeps its written case; lowercasing is the host parser's job.
        #expect(parsed.hostText == "Example.COM")
        #expect(parsed.port == 8443)
        #expect(parsed.query == "a=b")
        #expect(parsed.fragment == "frag")
    }

    @Test("Absent components are nil rather than empty")
    func absentComponents() throws {
        let parsed = try ParsedURLString.parse("https://example.com")
        #expect(parsed.userinfo == nil)
        #expect(parsed.port == nil)
        #expect(parsed.query == nil)
        #expect(parsed.fragment == nil)
        #expect(parsed.hostText == "example.com")
    }

    @Test("Present-but-empty components are distinguishable from absent ones")
    func emptyComponents() throws {
        let parsed = try ParsedURLString.parse("https://@example.com/?#")
        #expect(parsed.userinfo == "")
        #expect(parsed.query == "")
        #expect(parsed.fragment == "")
    }

    @Test("A query inside a fragment is part of the fragment")
    func queryInFragment() throws {
        let parsed = try ParsedURLString.parse("https://example.com/p#frag?notaquery")
        #expect(parsed.fragment == "frag?notaquery")
        #expect(parsed.query == nil)
    }

    @Test("An `@` after the authority does not create userinfo")
    func atInPath() throws {
        let parsed = try ParsedURLString.parse("https://example.com/a@b")
        #expect(parsed.userinfo == nil)
        #expect(parsed.hostText == "example.com")
    }

    @Test("An `@` in the fragment does not create userinfo either")
    func atInFragment() throws {
        let parsed = try ParsedURLString.parse("https://example.com#@evil.com")
        #expect(parsed.userinfo == nil)
        #expect(parsed.hostText == "example.com")
        #expect(parsed.fragment == "@evil.com")
    }

    @Test("A bracketed literal keeps its brackets for the host parser")
    func bracketedLiteral() throws {
        #expect(try ParsedURLString.parse("https://[::1]/").hostText == "[::1]")
        #expect(try ParsedURLString.parse("https://[::1]:8080/").port == 8080)
    }

    @Test(
        "Strings that are not unambiguous absolute URLs are refused",
        arguments: [
            "",
            "example.com",
            "/path",
            "https:/example.com",
            "https://",
            "https://:8080/",
            "https://[::1/",
            "https://a:b:c/",
            "https://example.com:80x/",
            "https://example.com:99999/",
            "1https://example.com/"
        ]
    )
    func refused(_ input: String) {
        #expect(throws: URLStringParsingError.self) {
            try ParsedURLString.parse(input)
        }
    }
}

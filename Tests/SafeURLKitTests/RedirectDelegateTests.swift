//
//  RedirectDelegateTests.swift
//  SafeURLKitTests
//
//  Redirect revalidation, driven by calling the delegate method directly.
//
//  Standing up a real redirecting server would test URLSession rather than the policy, so
//  the delegate callback is invoked the way URLSession invokes it and the decision is
//  observed through the completion handler.
//

import Foundation
@testable import SafeURLKit
import Testing

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

@Suite("Redirect revalidation")
struct RedirectDelegateTests {
    /// Ask a delegate what it would do with a redirect to `urlString`, returning the
    /// request it allowed through, or `nil` for a refusal.
    private func decision(
        _ delegate: PolicyEnforcingRedirectDelegate,
        redirectingTo urlString: String,
        rawLocation: String? = nil
    ) throws -> URLRequest? {
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }

        let original = try #require(URL(string: "https://example.com/"))
        let target = try #require(URL(string: urlString))
        let response = try #require(
            HTTPURLResponse(
                url: original,
                statusCode: 302,
                httpVersion: nil,
                headerFields: ["Location": rawLocation ?? urlString]
            )
        )

        var result: URLRequest?
        delegate.urlSession(
            session,
            task: session.dataTask(with: original),
            willPerformHTTPRedirection: response,
            newRequest: URLRequest(url: target)
        ) { result = $0 }
        return result
    }

    @Test("A redirect to a URL the policy accepts is followed")
    func allowedRedirect() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let allowed = try decision(delegate, redirectingTo: "https://other.example.org/")
        #expect(allowed?.url?.absoluteString == "https://other.example.org/")
    }

    @Test(
        "The hop that actually matters - a redirect to an internal address - is refused",
        arguments: [
            "http://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://localhost/",
            "https://[::1]/",
            "https://10.0.0.1/",
            "file:///etc/passwd"
        ]
    )
    func refusedRedirect(_ urlString: String) throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        #expect(try decision(delegate, redirectingTo: urlString) == nil)
    }

    @Test("An origin allow-list is enforced across the redirect too")
    func allowListAcrossRedirect() throws {
        let policy = URLPolicy(allowedOrigins: [.hostSuffix("example.com")])
        let delegate = PolicyEnforcingRedirectDelegate(policy: policy)
        #expect(try decision(delegate, redirectingTo: "https://app.example.com/") != nil)
        #expect(try decision(delegate, redirectingTo: "https://evil.com/") == nil)
    }

    @Test("Refusals are reported to the observer with the reason")
    func rejectionObserver() throws {
        let recorded = Recorder()
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS) { url, error in
            recorded.record(url: url, error: error)
        }
        _ = try decision(delegate, redirectingTo: "https://169.254.169.254/")

        let rejections = recorded.rejections
        #expect(rejections.count == 1)
        #expect(rejections.first?.url.absoluteString == "https://169.254.169.254/")
        #expect(rejections.first?.error.description.contains("cloud metadata") == true)
    }

    @Test("Allowed redirects do not notify the observer")
    func noSpuriousRejections() throws {
        let recorded = Recorder()
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS) { url, error in
            recorded.record(url: url, error: error)
        }
        _ = try decision(delegate, redirectingTo: "https://example.org/")
        #expect(recorded.rejections.isEmpty)
    }

    @Test("The raw Location header must agree with Foundation's generated request")
    func rawLocationMustAgree() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://other.example.org/",
            rawLocation: "https://evil.com/"
        )
        #expect(result == nil)
    }

    @Test("Ambiguous raw relative locations are rejected before normalization")
    func ambiguousRawLocation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://example.com/evil",
            rawLocation: "\\evil"
        )
        #expect(result == nil)
    }

    @Test("A relative Location is resolved against the response URL")
    func relativeLocation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://example.com/next",
            rawLocation: "/next"
        )
        #expect(result?.url?.absoluteString == "https://example.com/next")
    }

    @Test("The delegate exposes the policy it was built with")
    func exposesPolicy() {
        let policy = URLPolicy(allowedSchemes: ["http"])
        #expect(PolicyEnforcingRedirectDelegate(policy: policy).policy == policy)
    }
}

/// Collects the refusals a delegate reports. `URLSession` may deliver delegate messages on
/// any queue, so the observer closure is `@Sendable` and this is locked accordingly.
private final class Recorder: @unchecked Sendable {
    struct Rejection {
        let url: URL
        let error: URLValidationError
    }

    private let lock = NSLock()
    private var storage: [Rejection] = []

    func record(url: URL, error: URLValidationError) {
        lock.withLock { storage.append(Rejection(url: url, error: error)) }
    }

    var rejections: [Rejection] {
        lock.withLock { storage }
    }
}

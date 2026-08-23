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
        rawLocation: String? = nil,
        headers: [String: String] = [:]
    ) throws -> URLRequest? {
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }

        let original = try #require(URL(string: "https://coderpad.io/"))
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
            newRequest: {
                var request = URLRequest(url: target)
                for (name, value) in headers {
                    request.setValue(value, forHTTPHeaderField: name)
                }
                return request
            }()
        ) { result = $0 }
        return result
    }

    @Test("A redirect to a URL the policy accepts is followed")
    func allowedRedirect() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let allowed = try decision(delegate, redirectingTo: "https://other.github.com/")
        #expect(allowed?.url?.absoluteString == "https://other.github.com/")
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
        let policy = URLPolicy(allowedOrigins: [.hostSuffix("coderpad.io")])
        let delegate = PolicyEnforcingRedirectDelegate(policy: policy)
        #expect(try decision(delegate, redirectingTo: "https://app.coderpad.io/") != nil)
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
        _ = try decision(delegate, redirectingTo: "https://github.com/")
        #expect(recorded.rejections.isEmpty)
    }

    @Test("The raw Location header must agree with Foundation's generated request")
    func rawLocationMustAgree() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://github.com/",
            rawLocation: "https://evil.com/"
        )
        #expect(result == nil)
    }

    @Test("Ambiguous raw relative locations are rejected before normalization")
    func ambiguousRawLocation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://coderpad.io/evil",
            rawLocation: "\\evil"
        )
        #expect(result == nil)
    }

    @Test("A relative Location is resolved against the response URL")
    func relativeLocation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://coderpad.io/next",
            rawLocation: "/next"
        )
        #expect(result?.url?.absoluteString == "https://coderpad.io/next")
    }

    @Test("Cross-origin redirects strip sensitive caller headers")
    func crossOriginHeaderSanitization() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let request = try decision(
            delegate,
            redirectingTo: "https://github.com/",
            headers: [
                "Authorization": "Bearer secret",
                "API-Key": "secret",
                "X-Access-Token": "secret",
                "X-CSRF-Token": "secret",
                "Session-Token": "secret",
                "Accept": "text/plain"
            ]
        )

        #expect(request?.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(request?.value(forHTTPHeaderField: "API-Key") == nil)
        #expect(request?.value(forHTTPHeaderField: "X-Access-Token") == nil)
        #expect(request?.value(forHTTPHeaderField: "X-CSRF-Token") == nil)
        #expect(request?.value(forHTTPHeaderField: "Session-Token") == nil)
        #expect(request?.value(forHTTPHeaderField: "Accept") == "text/plain")
        #expect(request?.allHTTPHeaderFields?.keys.contains { $0.lowercased() == "authorization" } != true)
        #expect(request?.allHTTPHeaderFields?.keys.contains { $0.lowercased() == "api-key" } != true)
    }

    @Test("Same-origin redirects preserve sensitive caller headers")
    func sameOriginHeaderPreservation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let request = try decision(
            delegate,
            redirectingTo: "https://coderpad.io/next",
            headers: ["Authorization": "Bearer secret", "API-Key": "secret"]
        )

        #expect(request?.value(forHTTPHeaderField: "Authorization") == "Bearer secret")
        #expect(request?.value(forHTTPHeaderField: "API-Key") == "secret")
    }

    @Test("Equivalent host spellings count as same-origin for header preservation")
    func semanticSameOriginHeaderPreservation() throws {
        let policy = URLPolicy(
            allowsIPLiteralHosts: true,
            allowsSpecialPurposeAddresses: true
        )
        let delegate = PolicyEnforcingRedirectDelegate(policy: policy)
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }

        let original = try #require(URL(string: "https://127.0.0.1/"))
        let target = try #require(URL(string: "https://2130706433/next"))
        let response = try #require(
            HTTPURLResponse(
                url: original,
                statusCode: 302,
                httpVersion: nil,
                headerFields: ["Location": "https://2130706433/next"]
            )
        )

        var result: URLRequest?
        var request = URLRequest(url: target)
        request.setValue("Bearer secret", forHTTPHeaderField: "Authorization")
        delegate.urlSession(
            session,
            task: session.dataTask(with: original),
            willPerformHTTPRedirection: response,
            newRequest: request
        ) { result = $0 }

        #expect(result?.value(forHTTPHeaderField: "Authorization") == "Bearer secret")
    }

    @Test("The delegate exposes the policy it was built with")
    func exposesPolicy() {
        let policy = URLPolicy(allowedSchemes: ["http"])
        #expect(PolicyEnforcingRedirectDelegate(policy: policy).policy == policy)
    }

    @Test("Protocol-relative Location headers are validated as absolute URLs")
    func protocolRelativeLocation() throws {
        let delegate = PolicyEnforcingRedirectDelegate(policy: .publicHTTPS)
        let result = try decision(
            delegate,
            redirectingTo: "https://169.254.169.254/",
            rawLocation: "//169.254.169.254/"
        )
        #expect(result == nil)
    }

    @Test("rejectedRedirectBehavior is configurable")
    func rejectedRedirectBehavior() {
        let delegate = PolicyEnforcingRedirectDelegate(
            policy: .publicHTTPS,
            rejectedRedirectBehavior: .cancelTask
        )
        #expect(delegate.rejectedRedirectBehavior == .cancelTask)
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

# ``SafeURLKit``

SSRF-style URL policy validation for Swift, with a WHATWG-conformant host parser.

## Overview

`SafeURLKit` answers one question: *may this app fetch this URL?* You describe what is
acceptable as a ``URLPolicy`` value - schemes, origins, ports, whether credentials or
fragments are tolerated, whether IP literals or reserved ranges are - and validation
returns a ``ValidatedURL`` or throws a ``URLValidationError`` naming the check that failed.

```swift
let policy = URLPolicy(
    allowedSchemes: ["https"],
    allowedOrigins: [.hostSuffix("coderpad.io")]
)
let validated = try policy.validate(userSuppliedURLString)
let (data, _) = try await URLSession.shared.data(from: validated.url)
```

The reason a package is warranted rather than a helper function is the host parser. A
hand-written check compares strings, and `127.0.0.1` has many spellings that a string
comparison misses and the network stack does not:

| Written | Reaches |
| --- | --- |
| `0177.0.0.1` | `127.0.0.1` |
| `0x7f.1` | `127.0.0.1` |
| `2130706433` | `127.0.0.1` |
| `[::ffff:169.254.169.254]` | the cloud metadata endpoint |
| `[2002:a9fe:a9fe::]` | the cloud metadata endpoint, via 6to4 |

``URLHost/parse(_:)`` implements the WHATWG host parser, so each of these resolves to the
address it denotes before any policy check runs, and
``SpecialPurposeAddresses`` matches the resolved address against the IANA registries.

### Parser disagreement is a rejection

Validating with one parser and fetching with another is how a correct check ends up
guarding nothing. `SafeURLKit` splits the URL string itself, then re-reads it through
`URLComponents` and rejects with ``URLValidationError/parserDisagreement(safeURLKit:foundation:)``
if the two readings differ. Characters that parsers are known to disagree about - tab,
newline, backslash - are refused outright rather than normalized.

### Scope

This is string-level validation, and it cannot address DNS rebinding: a name that passes
may resolve to loopback a moment later, and `URLSession` offers no hook between resolution
and connection. The defences that do work - resolving first and connecting to a vetted
address, or an egress proxy such as Smokescreen - are not buildable on `URLSession`, and
are a non-goal here.

What is in scope, and is where string checks are most often bypassed in practice, is
redirects: ``PolicyEnforcingRedirectDelegate`` re-applies the policy to every hop.

## Topics

### Policies

- ``URLPolicy``
- ``OriginRule``
- ``PortRule``
- ``ValidatedURL``
- ``URLValidationError``

### Hosts and addresses

- ``URLHost``
- ``IPv4Address``
- ``IPv6Address``
- ``HostParsingError``

### Reserved names and addresses

- ``SpecialUseDomains``
- ``SpecialPurposeAddresses``
- ``SpecialPurposeMatch``
- ``SpecialPurposeIPv4Range``
- ``SpecialPurposeIPv6Range``
- ``IPv4Prefix``
- ``IPv6Prefix``

### Redirects

- ``PolicyEnforcingRedirectDelegate``

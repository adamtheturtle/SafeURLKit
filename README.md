# SafeURLKit

SSRF-style URL policy validation for Swift, with a WHATWG-conformant host parser.

[Documentation](https://swiftpackageindex.com/adamtheturtle/SafeURLKit/documentation/safeurlkit) |
[Swift Package Index](https://swiftpackageindex.com/adamtheturtle/SafeURLKit)

## Installation

```swift
.package(url: "https://github.com/adamtheturtle/SafeURLKit.git", from: "0.1.0")
```

Add the `SafeURLKit` product to your target dependencies.

## Usage

Describe what is acceptable as a value, then validate:

```swift
import SafeURLKit

let policy = URLPolicy(
    allowedSchemes: ["https"],
    allowedOrigins: [.hostSuffix("example.com")]
)

let validated = try policy.validate(userSuppliedURLString)
let (data, _) = try await URLSession.shared.data(from: validated.url)
```

Validation returns a `ValidatedURL` - a value only `validate` can produce, so "this URL was
checked" is something the compiler tracks rather than a convention to remember - or throws a
`URLValidationError` naming the check that failed.

## Why a package

A hand-written check compares host strings, and `127.0.0.1` has many spellings that a string
comparison misses and the network stack does not:

| Written | Reaches |
| --- | --- |
| `0177.0.0.1` | `127.0.0.1` |
| `0x7f.1` | `127.0.0.1` |
| `2130706433` | `127.0.0.1` |
| `[::ffff:169.254.169.254]` | the cloud metadata endpoint |
| `[2002:a9fe:a9fe::]` | the cloud metadata endpoint, via 6to4 |

`SafeURLKit` implements the WHATWG host parser, so each of these resolves to the address it
denotes *before* any policy check runs, and the resolved address is matched against the IANA
special-purpose registries.

### Parser disagreement is a rejection

Validating with one parser and fetching with another is how a correct check ends up guarding
nothing. `SafeURLKit` splits the URL string itself, then re-reads it through `URLComponents`
and rejects if the two readings differ. Characters that parsers are known to disagree about -
tab, newline, backslash - are refused outright rather than normalized.

### Secure by default

Every axis defaults to its strict setting: HTTPS only, the scheme's default port, no embedded
credentials, no fragment, no IP literals, no reserved names or addresses. Loosening any of
them is an explicit argument, so it shows up in a diff as a decision rather than an omission.

## Policy axes

| Axis | Default | Notes |
| --- | --- | --- |
| `allowedSchemes` | `["https"]` | Compared case-insensitively |
| `allowedOrigins` | `nil` | `nil` is "any host"; `[]` rejects everything, so a misconfiguration fails closed |
| `portRule` | `.defaultForScheme` | Also `.any` and `.allowed(Set<Int>)` |
| `allowsCredentials` | `false` | Blocks `https://trusted.com@evil.com/` |
| `allowsFragment` | `false` | |
| `allowsQuery` | `true` | |
| `allowsIPLiteralHosts` | `false` | |
| `allowsSpecialUseHostNames` | `false` | `localhost`, `.local`, `.internal`, … |
| `allowsSpecialPurposeAddresses` | `false` | Loopback, RFC 1918, link-local, and the rest |
| `maximumLength` | `2048` | |

Origin rules are `.origin(scheme:host:port:)` for an exact port-aware origin, `.host(_:)` for
an exact host on any permitted port, and `.hostSuffix(_:)` for a suffix anchored at a label
boundary - so `.hostSuffix("example.com")` matches `app.example.com` and does not match
`evilexample.com`.

`portRule` and `allowedOrigins` are separate checks and both must pass, so an exact origin on
a non-default port needs the port rule to admit it too:

```swift
URLPolicy(
    allowedOrigins: [.origin(scheme: "https", host: .domain("a.example"), port: 8443)],
    portRule: .allowed([8443])  // without this, everything is rejected
)
```

## Redirects

Validating the supplied URL and then following redirects unchecked is the most common way a
string check ends up protecting nothing: the URL passes, and the server answers
`302 Location: http://169.254.169.254/`. Re-apply the policy to every hop:

```swift
let delegate = PolicyEnforcingRedirectDelegate(policy: policy)
let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
defer { session.finishTasksAndInvalidate() }

let (data, response) = try await session.data(from: validated.url)
```

A refused redirect is not an error: `URLSession` returns the 3xx response itself. Check the
status code, or pass an `onRejection` closure to observe refusals.

## Scope

**This is URL-string policy validation.** It cannot address DNS rebinding: a name that passes
the check can resolve to `127.0.0.1` a moment later, and `URLSession` exposes no hook between
resolution and connection at which the resolved address could be re-checked.

The defences that do work live at other layers - resolving first and connecting to a vetted
address, as [ssrf_filter](https://github.com/arkadiyt/ssrf_filter) does in Ruby, or an egress
proxy such as [Smokescreen](https://github.com/stripe/smokescreen) - and neither is buildable
on `URLSession` alone. Both are non-goals here.

**Internationalized hosts are refused, not transcoded.** Foundation exposes no IDNA/UTS-46
entry point, and an approximate implementation inside a security check is worse than none: it
would produce a host that differs from the one the network stack uses, which is the exact
condition this package exists to prevent. Punycode the host before validating.

## Prior art

The design owes a lot to [doyensec/safeurl](https://github.com/doyensec/safeurl) (Go) for the
config-object shape, [arkadiyt/ssrf_filter](https://github.com/arkadiyt/ssrf_filter) (Ruby)
for the prefix table and per-hop revalidation, and
[JordanMilne/Advocate](https://github.com/JordanMilne/Advocate) (Python) for keeping the
policy object separate from the transport. The test corpus draws on the
[PortSwigger URL validation bypass cheat sheet](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet)
and the CVE-2020-28360 regression cases from
[frenchbread/private-ip](https://github.com/frenchbread/private-ip).

## Requirements

- Swift 6.2+
- macOS 14+, iOS 17+, tvOS 17+, watchOS 10+, or visionOS 1+, or Linux
- No dependencies

## License

MIT. See [LICENSE](LICENSE).

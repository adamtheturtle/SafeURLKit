//
//  SpecialPurposeAddresses.swift
//  SafeURLKit
//
//  The IANA special-purpose address registries, as prefix tables.
//
//  For SSRF the interesting entries are the ones that name something reachable but not
//  public: loopback, the RFC 1918 ranges, and above all 169.254.169.254, the cloud
//  metadata endpoint that link-local 169.254.0.0/16 covers. The table is complete rather
//  than curated because "which reserved range is dangerous" is a question about the
//  deployment, not about the address, and an allow-list-first policy should not depend on
//  the answer.
//
//  Sources:
//  - IANA IPv4 Special-Purpose Address Registry
//  - IANA IPv6 Special-Purpose Address Registry
//

import Foundation

// MARK: - Prefixes

/// A CIDR prefix of the IPv4 address space.
public struct IPv4Prefix: Sendable, Hashable, CustomStringConvertible {
    /// The network address, with all host bits already cleared.
    public let base: UInt32
    /// The prefix length in bits, `0...32`.
    public let bits: UInt8

    /// Create a prefix, masking off any host bits set in `base`.
    ///
    /// Returns `nil` when `bits` is greater than 32.
    public init?(_ base: IPv4Address, _ bits: UInt8) {
        guard bits <= 32 else { return nil }
        self.init(validated: base, bits: bits)
    }

    fileprivate init(validated base: IPv4Address, bits: UInt8) {
        self.bits = bits
        let mask: UInt32 = bits == 0 ? 0 : ~0 << (32 - UInt32(bits))
        self.base = base.rawValue & mask
    }

    /// Whether `address` falls inside this prefix.
    public func contains(_ address: IPv4Address) -> Bool {
        let mask: UInt32 = bits == 0 ? 0 : ~0 << (32 - UInt32(bits))
        return address.rawValue & mask == base
    }

    public var description: String {
        "\(IPv4Address(rawValue: base))/\(bits)"
    }
}

/// A CIDR prefix of the IPv6 address space.
public struct IPv6Prefix: Sendable, Hashable, CustomStringConvertible {
    /// The network address, with all host bits already cleared.
    public let base: IPv6Address
    /// The prefix length in bits, `0...128`.
    public let bits: UInt8

    /// Create a prefix, masking off any host bits set in `base`.
    ///
    /// - Precondition: `bits` is at most 128.
    public init(_ base: IPv6Address, _ bits: UInt8) {
        precondition(bits <= 128, "An IPv6 prefix is at most 128 bits")
        self.bits = bits
        self.base = IPv6Address(pieces: Self.masked(base.pieces, bits: bits))
    }

    /// Whether `address` falls inside this prefix.
    public func contains(_ address: IPv6Address) -> Bool {
        Self.masked(address.pieces, bits: bits) == base.pieces
    }

    /// Clear every bit of `pieces` below the `bits`-th, so two masked addresses compare
    /// equal exactly when they share a prefix.
    private static func masked(_ pieces: [UInt16], bits: UInt8) -> [UInt16] {
        pieces.enumerated().map { index, piece in
            let consumed = Int(bits) - index * 16
            if consumed >= 16 {
                return piece
            }
            if consumed <= 0 {
                return 0
            }
            return piece & (UInt16.max << (16 - UInt16(consumed)))
        }
    }

    public var description: String {
        "\(base)/\(bits)"
    }
}

// MARK: - Registry entries

/// A named entry of the IPv4 special-purpose address registry.
public struct SpecialPurposeIPv4Range: Sendable, Hashable {
    /// The prefix the entry covers.
    public let prefix: IPv4Prefix
    /// A short human-readable name, for logs and error messages.
    public let name: String

    public init(_ prefix: IPv4Prefix, _ name: String) {
        self.prefix = prefix
        self.name = name
    }
}

/// A named entry of the IPv6 special-purpose address registry.
public struct SpecialPurposeIPv6Range: Sendable, Hashable {
    /// The prefix the entry covers.
    public let prefix: IPv6Prefix
    /// A short human-readable name, for logs and error messages.
    public let name: String

    public init(_ prefix: IPv6Prefix, _ name: String) {
        self.prefix = prefix
        self.name = name
    }
}

/// Which registry entry a host matched, and - for addresses smuggled inside an IPv6 form -
/// the IPv4 address that actually matched.
public enum SpecialPurposeMatch: Sendable, Hashable, CustomStringConvertible {
    /// An IPv4 address matched an IPv4 registry entry. The address is included because it
    /// may have been extracted from an IPv6 wrapper rather than written directly.
    case ipv4(SpecialPurposeIPv4Range, IPv4Address)
    /// An IPv6 address matched an IPv6 registry entry.
    case ipv6(SpecialPurposeIPv6Range, IPv6Address)

    /// The matched entry's name.
    public var name: String {
        switch self {
        case let .ipv4(range, _):
            range.name
        case let .ipv6(range, _):
            range.name
        }
    }

    public var description: String {
        switch self {
        case let .ipv4(range, address):
            "\(address) is in \(range.prefix) (\(range.name))"
        case let .ipv6(range, address):
            "\(address) is in \(range.prefix) (\(range.name))"
        }
    }
}

// MARK: - The registries

/// The IANA special-purpose address registries, and the lookup over them.
public enum SpecialPurposeAddresses {
    /// The IPv4 special-purpose address registry.
    public static let ipv4: [SpecialPurposeIPv4Range] = [
        .init(.init(validated: IPv4Address(0, 0, 0, 0), bits: 8), "this network"),
        .init(.init(validated: IPv4Address(10, 0, 0, 0), bits: 8), "private-use (RFC 1918)"),
        .init(.init(validated: IPv4Address(100, 64, 0, 0), bits: 10), "shared address space / CGNAT"),
        .init(.init(validated: IPv4Address(127, 0, 0, 0), bits: 8), "loopback"),
        .init(.init(validated: IPv4Address(169, 254, 0, 0), bits: 16), "link-local / cloud metadata"),
        .init(.init(validated: IPv4Address(172, 16, 0, 0), bits: 12), "private-use (RFC 1918)"),
        .init(.init(validated: IPv4Address(192, 0, 0, 0), bits: 24), "IETF protocol assignments"),
        .init(.init(validated: IPv4Address(192, 0, 2, 0), bits: 24), "documentation (TEST-NET-1)"),
        .init(.init(validated: IPv4Address(192, 31, 196, 0), bits: 24), "AS112-v4"),
        .init(.init(validated: IPv4Address(192, 52, 193, 0), bits: 24), "AMT"),
        .init(.init(validated: IPv4Address(192, 88, 99, 0), bits: 24), "deprecated 6to4 relay anycast"),
        .init(.init(validated: IPv4Address(192, 168, 0, 0), bits: 16), "private-use (RFC 1918)"),
        .init(.init(validated: IPv4Address(192, 175, 48, 0), bits: 24), "direct delegation AS112 service"),
        .init(.init(validated: IPv4Address(198, 18, 0, 0), bits: 15), "benchmarking"),
        .init(.init(validated: IPv4Address(198, 51, 100, 0), bits: 24), "documentation (TEST-NET-2)"),
        .init(.init(validated: IPv4Address(203, 0, 113, 0), bits: 24), "documentation (TEST-NET-3)"),
        .init(.init(validated: IPv4Address(224, 0, 0, 0), bits: 4), "multicast"),
        .init(.init(validated: IPv4Address(240, 0, 0, 0), bits: 4), "reserved, including limited broadcast")
    ]

    /// The IPv6 special-purpose address registry.
    ///
    /// The IPv4-mapped and IPv4-compatible entries are listed even though
    /// ``match(_:)-(IPv6Address)`` unwraps those forms first: a mapped address whose payload
    /// is a *public* IPv4 address, such as `[::ffff:93.184.216.34]`, is still a spelling no
    /// legitimate URL uses, and the entry is what rejects it.
    public static let ipv6: [SpecialPurposeIPv6Range] = [
        .init(.init(IPv6Address(pieces: [0, 0, 0, 0, 0, 0, 0, 0]), 128), "unspecified"),
        .init(.init(IPv6Address(pieces: [0, 0, 0, 0, 0, 0, 0, 1]), 128), "loopback"),
        .init(
            .init(IPv6Address(pieces: [0, 0, 0, 0, 0, 0xFFFF, 0, 0]), 96),
            "IPv4-mapped"
        ),
        .init(
            .init(IPv6Address(pieces: [0x64, 0xFF9B, 0, 0, 0, 0, 0, 0]), 96),
            "IPv4-IPv6 translation (NAT64)"
        ),
        .init(
            .init(IPv6Address(pieces: [0x64, 0xFF9B, 1, 0, 0, 0, 0, 0]), 48),
            "IPv4-IPv6 translation (local-use NAT64)"
        ),
        .init(.init(IPv6Address(pieces: [0x100, 0, 0, 0, 0, 0, 0, 0]), 64), "discard-only"),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0, 0, 0, 0, 0, 0, 0]), 32),
            "Teredo tunnelling"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0x2, 0, 0, 0, 0, 0, 0]), 48),
            "benchmarking"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0x10, 0, 0, 0, 0, 0, 0]), 28),
            "deprecated ORCHID"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28),
            "ORCHIDv2"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0x30, 0, 0, 0, 0, 0, 0]), 28),
            "DRIP"
        ),
        // The covering registration, listed after its more specific children so that
        // `match(_:)`'s first-hit lookup reports the narrower name where one applies. It is
        // what catches the individually registered assignments inside it - PCP anycast at
        // 2001:1::1, AMT at 2001:3::/32, AS112-v6 at 2001:4:112::/48 - without listing each.
        // Note that 2001:db8::/32 lies outside it and is a separate entry below.
        .init(
            .init(IPv6Address(pieces: [0x2001, 0, 0, 0, 0, 0, 0, 0]), 23),
            "IETF protocol assignments"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0]), 32),
            "documentation"
        ),
        .init(
            .init(IPv6Address(pieces: [0x2002, 0, 0, 0, 0, 0, 0, 0]), 16),
            "deprecated 6to4"
        ),
        .init(
            .init(IPv6Address(pieces: [0x3FFF, 0, 0, 0, 0, 0, 0, 0]), 20),
            "documentation"
        ),
        .init(
            .init(IPv6Address(pieces: [0x5F00, 0, 0, 0, 0, 0, 0, 0]), 16),
            "segment routing (SRv6) SIDs"
        ),
        // The IPv6 counterpart of 192.175.48.0/24, which is in the IPv4 table above.
        .init(
            .init(IPv6Address(pieces: [0x2620, 0x4F, 0x8000, 0, 0, 0, 0, 0]), 48),
            "direct delegation AS112 service"
        ),
        .init(.init(IPv6Address(pieces: [0xFC00, 0, 0, 0, 0, 0, 0, 0]), 7), "unique-local"),
        .init(.init(IPv6Address(pieces: [0xFE80, 0, 0, 0, 0, 0, 0, 0]), 10), "link-local"),
        .init(.init(IPv6Address(pieces: [0xFF00, 0, 0, 0, 0, 0, 0, 0]), 8), "multicast")
    ]

    /// The registry entry `address` falls in, or `nil` if it is ordinary public space.
    public static func match(_ address: IPv4Address) -> SpecialPurposeMatch? {
        ipv4.first { $0.prefix.contains(address) }.map { .ipv4($0, address) }
    }

    /// The registry entry `address` falls in, or `nil` if it is ordinary public space.
    ///
    /// Addresses embedded in an IPv6 wrapper are checked first and reported as the IPv4
    /// match they are, so `[::ffff:169.254.169.254]` is rejected as cloud metadata rather
    /// than as the vaguer "IPv4-mapped". See ``IPv6Address/embeddedIPv4Addresses``.
    public static func match(_ address: IPv6Address) -> SpecialPurposeMatch? {
        for embedded in address.embeddedIPv4Addresses {
            if let match = match(embedded) {
                return match
            }
        }
        return ipv6.first { $0.prefix.contains(address) }.map { .ipv6($0, address) }
    }

    /// The registry entry `host` falls in, or `nil` for a domain name or for an address in
    /// ordinary public space.
    public static func match(_ host: URLHost) -> SpecialPurposeMatch? {
        switch host {
        case .domain:
            nil
        case let .ipv4(address):
            match(address)
        case let .ipv6(address):
            match(address)
        }
    }
}

// MARK: - IPv4 smuggled inside IPv6

extension IPv6Address {
    /// Every IPv4 address this IPv6 address carries inside it, under any of the transition
    /// mechanisms that embed one.
    ///
    /// Each of these is a real route to an IPv4 destination, so each is a way to reach
    /// `169.254.169.254` while writing something that no IPv4 block list would recognise:
    ///
    /// - IPv4-mapped, `::ffff:a.b.c.d`
    /// - IPv4-compatible, `::a.b.c.d` (deprecated, but still parsed)
    /// - NAT64, `64:ff9b::a.b.c.d`
    /// - 6to4, `2002:aabb:ccdd::/48`, where the address is in the second and third pieces
    /// - Teredo, `2001:0:<server>::/32`, where the server address is in the third and
    ///   fourth pieces
    ///
    /// Teredo's fifth field, the client address XOR-ed with all ones, is deliberately *not*
    /// read. It identifies the far endpoint rather than a host anything here would connect
    /// to, and de-obfuscating it on an address that merely starts with `2001:0:` produces a
    /// meaningless address that then matches a reserved range and buries the real reason in
    /// the log.
    ///
    /// The all-zero and loopback addresses are excluded from the IPv4-compatible reading,
    /// since `::` and `::1` are those addresses in their own right and are caught by the
    /// IPv6 registry.
    public var embeddedIPv4Addresses: [IPv4Address] {
        var addresses: [IPv4Address] = []

        func trailingIPv4() -> IPv4Address {
            IPv4Address(rawValue: UInt32(pieces[6]) << 16 | UInt32(pieces[7]))
        }

        let leadingPiecesAreZero = pieces[0 ... 4].allSatisfy { $0 == 0 }

        if leadingPiecesAreZero, pieces[5] == 0xFFFF {
            addresses.append(trailingIPv4())
        } else if leadingPiecesAreZero, pieces[5] == 0, pieces[6] != 0 || pieces[7] > 1 {
            addresses.append(trailingIPv4())
        }

        if pieces[0] == 0x64, pieces[1] == 0xFF9B, pieces[2 ... 5].allSatisfy({ $0 == 0 }) {
            addresses.append(trailingIPv4())
        }

        // For the tunnelling formats, an all-zero field is a placeholder rather than an
        // address: reading it as 0.0.0.0 would report `2001:0::1` as "this network" instead
        // of the Teredo range it is actually in. The address is rejected either way, but the
        // narrower name is the one worth logging.
        func appendIfNonZero(_ raw: UInt32, transform: (UInt32) -> UInt32 = { $0 }) {
            guard raw != 0 else {
                return
            }
            addresses.append(IPv4Address(rawValue: transform(raw)))
        }

        if pieces[0] == 0x2002 {
            appendIfNonZero(UInt32(pieces[1]) << 16 | UInt32(pieces[2]))
        }

        if pieces[0] == 0x2001, pieces[1] == 0 {
            appendIfNonZero(UInt32(pieces[2]) << 16 | UInt32(pieces[3]))
        }

        return addresses
    }
}

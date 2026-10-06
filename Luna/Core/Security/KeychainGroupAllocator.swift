//
//  KeychainGroupAllocator.swift
//  Luna
//
//  Keychain compartmentalisation for guests.
//
//  THE PROBLEM
//  -----------
//  Every guest runs inside Luna's own process, which means every guest shares
//  Luna's Keychain access groups. Without intervention, guest A can read the
//  credentials guest B wrote — and, worse, a malicious guest can read anything
//  a less careful launcher left lying around.
//
//  iOS lets an app declare multiple Keychain access groups in its
//  entitlements. Each guest is assigned one group at import time, chosen
//  deterministically from its bundle identifier. The practical effect is that
//  two guests only collide if they are the same app (and, with an explicit
//  override, not even then).
//
//  THE HONEST CAVEAT
//  -----------------
//  This is a *speed bump*, not a boundary. Because all guests execute in one
//  process with one set of entitlements, a determined guest can still reach
//  the shared keychain via the `kSecAttrAccessGroup` of a group it can guess.
//  True isolation requires a separate process, which iOS does not permit here.
//  See SECURITY.md for the full disclosure.
//

import Foundation

enum KeychainGroupAllocator {

    /// Number of access groups Luna reserves for guests.
    ///
    /// This number must match the number of `keychain-access-groups` entries in
    /// the host's entitlements. 128 is a deliberate trade-off: enough to cover
    /// any realistic guest count, small enough to keep the entitlements file
    /// reviewable by a human.
    static let groupCount = 128

    /// The prefix under which all of Luna's groups are registered.
    ///
    /// Must be prefixed with the host's team ID at signing time; we store the
    /// suffix and let the provisioning profile supply the prefix.
    static let groupSuffix = "luna.guest"

    /// Deterministically picks a group index for a bundle identifier.
    ///
    /// Determinism matters: if a guest is uninstalled and reinstalled, it must
    /// land in the same group, otherwise it loses access to its own
    /// previously-written keychain items.
    ///
    /// We use FNV-1a rather than `String.hashValue` because Swift's hashing is
    /// deliberately seeded per-process and would not be stable across launches.
    static func groupIndex(forBundleID bundleID: String) -> Int {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in bundleID.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        return Int(hash % UInt64(groupCount))
    }

    /// The full access group string for a guest, including the team prefix.
    static func accessGroup(
        forBundleID bundleID: String,
        teamID: String
    ) -> String {
        "\(teamID).\(groupSuffix).\(groupIndex(forBundleID: bundleID))"
    }

    /// Generates the entitlements fragment declaring every reserved group.
    ///
    /// `Xcode` substitutes `$(TeamIdentifierPrefix)` at signing time, so the
    /// same file works for any team. This is what the repo's
    /// `Luna.entitlements` is generated from.
    static func entitlementsFragment() -> String {
        let groups = (0..<groupCount)
            .map { "        <string>$(TeamIdentifierPrefix)\(groupSuffix).\($0)</string>" }
            .joined(separator: "\n")
        return """
        <key>keychain-access-groups</key>
        <array>
        \(groups)
        </array>
        """
    }
}

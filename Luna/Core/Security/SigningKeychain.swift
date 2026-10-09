//
//  SigningKeychain.swift
//  Luna
//
//  Keychain access for signing material.
//
//  This is the first place in the project that imports Security.framework.
//  Everything the signing identity needs to keep secret — the `.p12` export
//  password and the imported private key — goes through here, so there is
//  exactly one file to audit for "what does Luna stash in the keychain".
//
//  WHY THE PASSWORD IS KEPT AT ALL
//  -------------------------------
//  It would be tidier to decrypt the `.p12` once and forget the password.
//  But the `.p12` on disk stays encrypted, and `SecPKCS12Import` is what
//  turns it back into an identity — so the password has to be available on
//  the next launch, not just this one. Storing it in the keychain, tied to
//  the certificate's UUID, is the least-bad option: it never touches the
//  manifest, never survives a device migration
//  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and never appears in a
//  log.
//

import Foundation
import Security

/// Keychain-backed storage for a signing identity's secrets.
///
/// Every item is keyed by the certificate's UUID, so removing a certificate
/// is a matter of deleting everything whose account ends in that UUID. There
/// is no shared state between certificates, and no global "current password".
enum SigningKeychain {

    /// Namespace for everything Luna puts in the keychain.
    private static let service = "com.maihaobo.luna.signing"

    /// Account name for a certificate's `.p12` export password.
    private static func passwordAccount(_ id: UUID) -> String {
        "luna.signing.p12-password.\(id.uuidString)"
    }

    /// Account name for a certificate's imported private key.
    private static func privateKeyAccount(_ id: UUID) -> String {
        "luna.signing.private-key.\(id.uuidString)"
    }

    // MARK: - Passwords

    /// Stores (or replaces) the `.p12` export password for a certificate.
    static func storePassword(_ password: String, for id: UUID) throws {
        guard let data = password.data(using: .utf8) else {
            throw CertificateImportError.keychainFailure("密码无法编码")
        }
        try store(data, account: passwordAccount(id))
    }

    /// Reads back the `.p12` export password.
    ///
    /// Returns `nil` when there is no item — which happens for certificates
    /// imported by an older build, and is recoverable by re-importing. The
    /// caller decides whether that is fatal.
    static func password(for id: UUID) -> String? {
        guard let data = load(account: passwordAccount(id)) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func removePassword(for id: UUID) {
        remove(account: passwordAccount(id))
    }

    // MARK: - Private keys

    /// Persists a private key and returns a handle to the stored copy.
    ///
    /// The key returned by `SecIdentityCopyPrivateKey` on a freshly-imported
    /// `.p12` is only valid for the lifetime of that import; anything that
    /// needs to sign on a later launch must go through the keychain, so this
    /// is called once at import time and never again.
    static func storePrivateKey(_ key: SecKey, for id: UUID) throws -> SecKey {
        guard let data = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            // An unexportable key (a Secure Enclave key, or one whose `.p12`
            // had a protective attribute) cannot be re-imported from bytes.
            // Luna has no use for one: signing a guest happens on Luna's own
            // schedule, not a user's tap.
            throw CertificateImportError.keychainFailure("私钥无法导出到钥匙串")
        }

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrService as String: service,
            kSecAttrAccount as String: privateKeyAccount(id),
            kSecAttrApplicationTag as String: Data(privateKeyAccount(id).utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]

        // Delete first: `SecItemAdd` fails with `errSecDuplicateItem` rather
        // than replacing, and re-importing the same certificate is normal.
        removePrivateKey(for: id)

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CertificateImportError.keychainFailure(
                "写入私钥失败（OSStatus \(status)）")
        }

        guard let restored = privateKey(for: id) else {
            throw CertificateImportError.keychainFailure("私钥写入后无法读回")
        }
        return restored
    }

    /// Reads back a certificate's private key, or `nil` if the item is gone.
    ///
    /// A `nil` here is a real possibility that the UI must handle: the
    /// keychain item can be dropped by a restore from a backup made on a
    /// different device, since it is `ThisDeviceOnly`.
    static func privateKey(for id: UUID) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrService as String: service,
            kSecAttrAccount as String: privateKeyAccount(id),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    static func removePrivateKey(for id: UUID) {
        remove(account: privateKeyAccount(id))
    }

    // MARK: - Bulk removal

    /// Deletes every keychain item belonging to a certificate.
    ///
    /// Written as two explicit deletes rather than a `SecItemDelete` by
    /// service, because a service-wide delete would take out *every*
    /// certificate's items. The pair below is exhaustive: `passwordAccount`
    /// and `privateKeyAccount` are the only two accounts this type writes.
    static func removeAll(for id: UUID) {
        removePrivateKey(for: id)
        removePassword(for: id)
    }

    // MARK: - Primitives

    private static func store(_ data: Data, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        // `SecItemUpdate` first, then `SecItemAdd`: update fails with
        // `errSecItemNotFound` on a fresh install, and add fails with
        // `errSecDuplicateItem` on a re-import. Together they cover both.
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

        if status == errSecItemNotFound {
            var insert = query
            insert.merge(attributes) { current, _ in current }
            status = SecItemAdd(insert as CFDictionary, nil)
        }

        guard status == errSecSuccess else {
            throw CertificateImportError.keychainFailure(
                "钥匙串写入失败（OSStatus \(status)）")
        }
    }

    private static func load(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    private static func remove(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

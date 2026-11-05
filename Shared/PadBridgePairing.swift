#if os(iOS)
import Foundation
import Security
import CryptoKit

/// A single Windows computer is paired over the already trusted USB channel.
/// The identity, its import password and authorization token live only in the
/// app's device-local Keychain, never in the app bundle or a cloud build.
enum PadBridgePairing {
    private static let service = "PadBridge.secure-wifi"
    private static let account = "paired-computer"

    private static func query() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func load() -> [String: String]? {
        var q = query()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let record = try? JSONSerialization.jsonObject(with: data) as? [String: String]
        else { return nil }
        return record
    }

    static func identity(from record: [String: String]) -> SecIdentity? {
        guard let b64 = record["p12"], let p12 = Data(base64Encoded: b64),
              let password = record["password"] else { return nil }
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: password]
        guard SecPKCS12Import(p12 as CFData, options as CFDictionary, &items) == errSecSuccess,
              let values = items as? [[String: Any]], let first = values.first,
              let rawIdentity = first[kSecImportItemIdentity as String],
              CFGetTypeID(rawIdentity as CFTypeRef) == SecIdentityGetTypeID()
        else { return nil }
        return rawIdentity as! SecIdentity
    }

    static func identity() -> SecIdentity? {
        guard let record = load() else { return nil }
        return identity(from: record)
    }

    static func token() -> String? { load()?["token"] }

    static func install(_ offer: [String: Any], expectedID: String) -> Bool {
        guard offer["id"] as? String == expectedID,
              let p12 = offer["p12"] as? String, p12.count < 20_000,
              let password = offer["password"] as? String, password.count < 200,
              let token = offer["token"] as? String, token.count >= 32,
              let fingerprint = offer["sha256"] as? String, fingerprint.count == 64
        else { return false }
        let record = ["p12": p12, "password": password, "token": token]
        guard let identity = identity(from: record) else { return false }
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
              let certificate else { return false }
        let actual = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
            .map { String(format: "%02x", $0) }.joined()
        guard actual == fingerprint else { return false }
        guard let data = try? JSONSerialization.data(withJSONObject: record) else { return false }
        SecItemDelete(query() as CFDictionary)
        var attrs = query()
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
    }
}
#endif

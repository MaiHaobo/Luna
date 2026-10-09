//
//  CertificateImportError.swift
//  Luna
//
//  Everything that can go wrong importing a signing identity.
//
//  These messages are shown to the user verbatim, so each one names the
//  actual problem and, where there is one, the action that fixes it. The
//  failure modes here are unusually user-facing — a `.p12` and a
//  `.mobileprovision` come from a portal whose terminology does not match
//  anything on the device — so "导入失败" is never an acceptable message.
//

import Foundation

enum CertificateImportError: LocalizedError {

    /// No file at the given path, or it could not be read.
    case unreadableFile(URL, String)

    /// File exists but is not the type its extension claims.
    case wrongFileType(name: String, expected: String)

    /// `SecPKCS12Import` refused the file or the password.
    case badPassword

    /// `SecPKCS12Import` accepted the file but found no identity in it.
    ///
    /// Distinct from `badPassword` because the fix is different: the user
    /// exported the certificate without its private key, and has to go back
    /// to Keychain Access and export again.
    case noIdentity

    /// The `.p12` has no private key, only a certificate.
    case missingPrivateKey

    /// The key's algorithm is not one Luna can produce a CMS signature for.
    case unsupportedKeyAlgorithm(String)

    /// The certificate is outside its validity window.
    case certificateExpired(until: Date)
    case certificateNotYetValid(from: Date)

    /// The certificate's subject has no `OU`, so there is no team ID.
    case missingTeamIdentifier(String)

    /// The `.mobileprovision` could not be unwrapped or parsed.
    case profileUnreadable(String)

    case profileExpired(on: Date)

    /// The profile is not willing to sign with this certificate.
    ///
    /// The two fingerprints are included so a user comparing them against the
    /// portal can see which half is wrong.
    case profileCertificateMismatch(profileName: String, certificateName: String)

    /// The profile and the certificate come from different teams.
    case teamMismatch(certificateTeam: String, profileTeam: String)

    /// `SecItemAdd` / `SecItemUpdate` failed.
    case keychainFailure(String)

    /// Writing the `.p12` into Luna's container failed.
    case storageFailure(String)

    var errorDescription: String? {
        switch self {
        case .unreadableFile(let url, let detail):
            return "无法读取 \(url.lastPathComponent)：\(detail)"

        case .wrongFileType(let name, let expected):
            return "\(name) 不是\(expected)文件，请确认选对了文件类型。"

        case .badPassword:
            return "密码不正确，或这个 .p12 文件已损坏。请重新输入导出时设置的密码。"

        case .noIdentity:
            return """
                这个 .p12 里没有找到「证书 + 私钥」配对。\
                常见原因是导出时只选了证书。请在「钥匙串访问」中展开证书、\
                同时选中它下面的私钥，一起导出为 .p12。
                """

        case .missingPrivateKey:
            return "这个 .p12 只有证书、没有私钥，无法用于签名。"

        case .unsupportedKeyAlgorithm(let algorithm):
            return "不支持 \(algorithm) 密钥。请使用 RSA 2048 位或 ECDSA P-256 证书。"

        case .certificateExpired(let date):
            return "证书已于 \(Self.date(date)) 过期。请到开发者后台重新生成。"

        case .certificateNotYetValid(let date):
            return "证书要到 \(Self.date(date)) 才生效。请检查设备时间是否正确。"

        case .missingTeamIdentifier(let subject):
            return """
                证书主题里没有团队标识（OU）。Luna 需要它来判断证书属于哪个团队。\
                证书主题：\(subject)
                """

        case .profileUnreadable(let detail):
            return "描述文件解析失败：\(detail)。请确认选的是 .mobileprovision 文件。"

        case .profileExpired(let date):
            return "描述文件已于 \(Self.date(date)) 过期。请到开发者后台重新生成并下载。"

        case .profileCertificateMismatch(let profileName, let certificateName):
            return """
                描述文件「\(profileName)」不包含证书「\(certificateName)」。\
                请确认两者来自同一个开发者账号，且证书已加入这个描述文件。
                """

        case .teamMismatch(let certificateTeam, let profileTeam):
            return """
                证书属于团队 \(certificateTeam)，描述文件属于团队 \(profileTeam)，\
                两者必须来自同一个团队。
                """

        case .keychainFailure(let detail):
            return "钥匙串操作失败：\(detail)"

        case .storageFailure(let detail):
            return "保存证书文件失败：\(detail)"
        }
    }

    /// Renders a date the way a user reads it, not the way a machine writes it.
    private static func date(_ value: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: value)
    }
}

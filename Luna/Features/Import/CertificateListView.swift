//
//  CertificateListView.swift
//  Luna
//
//  Managing the signing identities the user has imported.
//
//  Laid out as the certificate counterpart of `AppLibraryView`: a list, a
//  `+` in the toolbar that opens a file picker, a progress banner along the
//  bottom, and one alert for failures. The consistency is deliberate — a
//  user who has imported an IPA already knows how this screen works.
//
//  THE ONE THING THAT NEEDS EXPLAINING IN THE UI
//  ---------------------------------------------
//  Importing a `.p12` and importing a `.mobileprovision` are two halves of one
//  action, and users routinely arrive with only one of them. So the picker
//  accepts either, and a `.p12` imported on its own is listed as *not usable*
//  with a button offering to attach a profile. That is friendlier than
//  refusing the import, and it matches how the material actually arrives —
//  usually two files downloaded separately from the developer portal.
//

import SwiftUI
import UniformTypeIdentifiers
import UIKit
import Security

struct CertificateListView: View {

    @EnvironmentObject private var store: CertificateStore

    @State private var isImporterPresented = false
    @State private var pendingPassword: PendingImport?
    @State private var password = ""
    @State private var alertMessage: String?
    @State private var pendingDelete: SigningCertificate?
    @State private var attachingProfileTo: SigningCertificate?

    /// A file the user picked, waiting for its password.
    ///
    /// Imports are two-step because a `.p12` cannot be read without its
    /// export password, and the password cannot be guessed. Holding the URL
    /// here while the password sheet is up keeps the security-scoped access
    /// on a single, short-lived code path.
    private struct PendingImport: Identifiable {
        let id = UUID()
        var p12: URL?
        var profile: URL?
    }

    var body: some View {
        List {
            if store.certificates.isEmpty {
                emptyState
            } else {
                Section {
                    ForEach(store.certificates) { certificate in
                        CertificateRow(
                            certificate: certificate,
                            isSelected: store.selectedID == certificate.id,
                            onSelect: { store.select(certificate.id) },
                            onAttachProfile: { attachingProfileTo = certificate })
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                pendingDelete = certificate
                            } label: {
                                Label("删除", systemImage: "trash")
                            }
                        }
                    }
                } footer: {
                    Text("新签名会使用被选中的证书。没有证书时，Luna 写入 adhoc 签名"
                         + "（无证书，仅用于自签加载）。")
                }
            }

            Section {
                Button {
                    isImporterPresented = true
                } label: {
                    Label("导入证书或描述文件", systemImage: "plus.circle")
                }
            } footer: {
                Text("把 .p12 和 .mobileprovision 放到 "
                     + "「文件」App → 我的 iPhone → Luna → CertImport，"
                     + "或直接在这里选择。若 .p12 有导出密码，会一并询问。")
            }

            Section("存放位置") {
                VStack(alignment: .leading, spacing: 3) {
                    Text("证书目录")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    Text(LunaPaths.certificatesDirectory.path)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(3)
                }
            }
        }
        .navigationTitle("签名证书")
        .safeAreaInset(edge: .bottom) {
            if let stage = store.importStage {
                banner(stage)
            }
        }
        .fileImporter(
            isPresented: $isImporterPresented,
            allowedContentTypes: allowedTypes,
            allowsMultipleSelection: true
        ) { result in
            handlePick(result)
        }
        .fileImporter(
            isPresented: Binding(
                get: { attachingProfileTo != nil },
                set: { if !$0 { attachingProfileTo = nil } }
            ),
            allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            handleProfilePick(result)
        }
        .sheet(item: $pendingPassword) { pending in
            passwordSheet(pending)
        }
        .alert(
            "导入失败",
            isPresented: Binding(
                get: { alertMessage != nil },
                set: { if !$0 { alertMessage = nil } }
            )
        ) {
            Button("好") { alertMessage = nil }
        } message: {
            Text(alertMessage ?? "")
        }
        .confirmationDialog(
            "删除证书「\(pendingDelete?.displayName ?? "")」？",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("删除", role: .destructive) {
                if let certificate = pendingDelete {
                    store.remove(certificate)
                }
                pendingDelete = nil
            }
            Button("取消", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("私钥与描述文件会一并从钥匙串和沙盒中删除，已签名的应用不受影响。")
        }
    }

    // MARK: - Pieces

    private var allowedTypes: [UTType] {
        [
            UTType(filenameExtension: "p12"),
            UTType(filenameExtension: "mobileprovision"),
            UTType(filenameExtension: "pfx"),
        ].compactMap { $0 }
    }

    private var emptyState: some View {
        Section {
            VStack(spacing: 10) {
                Image(systemName: "key.slash")
                    .font(.system(size: 34))
                    .foregroundStyle(.tertiary)
                Text("还没有导入证书")
                    .font(.system(size: 15, weight: .medium))
                Text("没有证书时 Luna 使用 adhoc 签名，只能在本机加载；"
                     + "导入自己的证书后可以对 guest 做正式签名并导出 IPA。")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
        }
    }

    private func banner(_ message: String) -> some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(message).font(.system(size: 12)).lineLimit(2)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
    }

    private func passwordSheet(_ pending: PendingImport) -> some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("导出密码", text: $password)
                        .textContentType(.password)
                        .autocorrectionDisabled()
                } header: {
                    Text("输入 .p12 的导出密码")
                } footer: {
                    Text("导出 .p12 时设置的密码。留空表示该文件没有密码。"
                         + "密码会保存在钥匙串中，用于以后重新读取这个证书。")
                }

                if let profile = pending.profile {
                    Section("描述文件") {
                        Text(profile.lastPathComponent)
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("导入证书")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        pendingPassword = nil
                        password = ""
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("导入") { performImport(pending) }
                        .disabled(pending.p12 == nil)
                }
            }
        }
    }

    // MARK: - Import

    /// Sorts a multi-file pick into the two halves of an import.
    ///
    /// The picker allows selecting both files at once, which is what a user
    /// who downloaded them together will do. Order is not guaranteed, so the
    /// classification is by extension rather than by position.
    private func handlePick(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard !urls.isEmpty else { return }
            var pending = PendingImport()
            for url in urls {
                switch url.pathExtension.lowercased() {
                case "p12", "pfx": pending.p12 = url
                case "mobileprovision": pending.profile = url
                default: break
                }
            }
            guard pending.p12 != nil else {
                alertMessage = "请选择 .p12 文件。描述文件可以稍后单独添加。"
                return
            }
            password = ""
            pendingPassword = pending

        case .failure(let error):
            alertMessage = error.localizedDescription
        }
    }

    private func handleProfilePick(_ result: Result<[URL], Error>) {
        guard let certificate = attachingProfileTo else { return }
        defer { attachingProfileTo = nil }

        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            store.importStage = "校验描述文件…"
            defer { store.clearImportStage() }

            let needsScope = url.startAccessingSecurityScopedResource()
            defer { if needsScope { url.stopAccessingSecurityScopedResource() } }

            do {
                let profileData = try Data(contentsOf: url, options: .mappedIfSafe)
                let profile = try CertificateImporter.parseProfile(profileData)

                // Re-derive the certificate's fingerprint so the profile can
                // be checked against it. This is the same check the original
                // import ran; doing it again here is what stops a user from
                // attaching a profile from a different team to a certificate
                // that will never be able to use it.
                let summary = try existingSummary(for: certificate)
                try CertificateImporter.validate(profile: profile, against: summary)

                var updated = certificate
                updated.profile = profile
                store.update(updated)

                // Keep the bytes: signing needs the entitlements dictionary,
                // and the summary above is deliberately lossy.
                let destination = store.folderURL(for: certificate)
                    .appendingPathComponent("profile.mobileprovision")
                try profileData.write(to: destination, options: [.atomic, .completeFileProtection])
            } catch {
                alertMessage = error.localizedDescription
            }

        case .failure(let error):
            alertMessage = error.localizedDescription
        }
    }

    /// Reads a stored certificate's summary back out of its `.p12`.
    private func existingSummary(
        for certificate: SigningCertificate
    ) throws -> CertificateImporter.CertificateSummary {
        guard let password = SigningKeychain.password(for: certificate.id) else {
            throw CertificateImportError.keychainFailure(
                "找不到 .p12 的导出密码，请重新导入证书")
        }
        let data = try Data(contentsOf: store.p12URL(for: certificate),
                            options: .mappedIfSafe)
        let identity = try CertificateImporter.importIdentity(from: data, password: password)

        var leaf: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &leaf) == errSecSuccess,
              let leaf else {
            throw CertificateImportError.noIdentity
        }
        return try CertificateImporter.summarize(leaf)
    }

    private func performImport(_ pending: PendingImport) {
        guard let p12URL = pending.p12 else { return }
        pendingPassword = nil
        store.importStage = "读取证书…"

        // The picker's URLs are security-scoped, and the scope has to be held
        // for as long as the bytes are being read — which is now, not later.
        let needsScope = p12URL.startAccessingSecurityScopedResource()
        let profileURL = pending.profile
        let profileNeedsScope = profileURL?.startAccessingSecurityScopedResource() ?? false
        defer {
            if needsScope { p12URL.stopAccessingSecurityScopedResource() }
            if profileNeedsScope { profileURL?.stopAccessingSecurityScopedResource() }
        }

        do {
            let p12Data = try Data(contentsOf: p12URL, options: .mappedIfSafe)
            let profileData = try profileURL.map {
                try Data(contentsOf: $0, options: .mappedIfSafe)
            }

            store.importStage = "解析证书…"
            let installed = try CertificateImporter.install(
                p12: p12Data,
                password: password,
                profile: profileData,
                into: store)

            store.select(installed.certificate.id)
            store.importStage = installed.replacedExisting
                ? "已更新「\(installed.certificate.displayName)」"
                : "已导入「\(installed.certificate.displayName)」"

            // Clear the banner after a beat so the screen does not keep a
            // stale "importing" line; the list itself is the confirmation.
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                store.clearImportStage()
            }
        } catch {
            store.importStage = nil
            alertMessage = error.localizedDescription
        }

        password = ""
    }
}

// MARK: - Row

private struct CertificateRow: View {

    let certificate: SigningCertificate
    let isSelected: Bool
    let onSelect: () -> Void
    let onAttachProfile: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                Text(certificate.displayName)
                    .font(.system(size: 15, weight: .medium))
                    .lineLimit(1)
                Spacer(minLength: 8)
                if certificate.isUsable {
                    statusPill("可用", color: .green)
                } else {
                    statusPill("不可用", color: .orange)
                }
            }

            Text(certificate.subtitle)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)

            if let profile = certificate.profile {
                Label {
                    Text("\(profile.name) · \(profile.applicationIdentifier)")
                        .font(.system(size: 11))
                        .lineLimit(1)
                } icon: {
                    Image(systemName: "doc.badge.gearshape")
                        .font(.system(size: 10))
                }
                .foregroundStyle(.secondary)
            }

            // The reason is shown inline rather than only on a detail screen:
            // "why can't I use this" is the question the row exists to answer.
            if let reason = certificate.unusableReason {
                Text(reason)
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)
                if certificate.profile == nil, certificate.isValid {
                    Button("添加描述文件…", action: onAttachProfile)
                        .font(.system(size: 12))
                        .buttonStyle(.borderless)
                }
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
    }

    private func statusPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}

//
//  GuestDetailView.swift
//  Luna
//
//  Everything Luna knows about one guest, plus the trust gate.
//

import SwiftUI

struct GuestDetailView: View {

    let guest: GuestApp

    @EnvironmentObject private var store: GuestStore
    @EnvironmentObject private var coordinator: SessionCoordinator
    @Environment(\.dismiss) private var dismiss

    @State private var isTrustSheetPresented = false

    /// Always read from the store so the view reflects updates.
    private var current: GuestApp {
        store.guests.first { $0.id == guest.id } ?? guest
    }

    var body: some View {
        NavigationStack {
            List {
                if !current.warnings.isEmpty {
                    warningsSection
                }

                Section("标识") {
                    row("名称", current.displayName)
                    row("Bundle ID", current.bundleIdentifier, monospaced: true)
                    row("版本", "\(current.version) (\(current.buildNumber))")
                    row("最低系统", current.minimumOSVersion.isEmpty ? "—" : current.minimumOSVersion)
                    row("包大小", current.formattedSize)
                }

                binaryStatusSection

                Section("容器") {
                    row("Guest 文件夹", current.storageDescription, monospaced: true)
                    row("数据文件夹", current.dataFolderName, monospaced: true)
                    row("Keychain 组", "\(KeychainGroupAllocator.groupSuffix).\(current.keychainGroupIndex)",
                        monospaced: true)
                    if let digest = current.executableDigest {
                        row("可执行文件摘要", String(digest.prefix(24)) + "…", monospaced: true)
                    }
                }

                if let summary = current.patchSummary {
                    Section("二进制修补报告") {
                        Text(summary)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                if let error = current.lastError {
                    Section("上次错误") {
                        Text(error)
                            .font(.system(size: 12))
                            .foregroundStyle(.red)
                    }
                }

                trustSection

                Section {
                    Button {
                        store.reinspect(current)
                    } label: {
                        Label("重新检测", systemImage: "arrow.clockwise.circle")
                    }
                    Button {
                        store.repatch(current)
                    } label: {
                        Label("重新修补二进制", systemImage: "arrow.triangle.2.circlepath")
                    }
                    Button(role: .destructive) {
                        store.delete(current, purgeData: true)
                        dismiss()
                    } label: {
                        Label("删除应用并清空数据", systemImage: "trash")
                    }
                }
            }
            .navigationTitle(current.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("完成") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        dismiss()
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                            coordinator.launch(current)
                        }
                    } label: {
                        Label("运行", systemImage: "play.fill")
                    }
                    .disabled(!current.trustAcknowledged)
                }
            }
            .sheet(isPresented: $isTrustSheetPresented) {
                TrustAcknowledgementSheet(guest: current) {
                    store.acknowledgeTrust(for: current)
                    isTrustSheetPresented = false
                } onCancel: {
                    isTrustSheetPresented = false
                }
            }
        }
    }

    // MARK: - Sections

    /// FairPlay state of the guest's main binary.
    ///
    /// Guests imported by older builds have `encryption == nil` (the field
    /// did not exist), which reads as "not recorded" rather than "plain" —
    /// re-inspection fills it in.
    @ViewBuilder
    private var binaryStatusSection: some View {
        if let enc = current.encryption {
            Section("二进制状态") {
                HStack {
                    Label(enc.isEncrypted ? "FairPlay 加密" : "未加密",
                          systemImage: enc.isEncrypted ? "lock.fill" : "checkmark.seal.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(enc.isEncrypted ? Color.red : Color.green)
                    Spacer()
                }
                row("cryptoff", String(format: "0x%X", enc.cryptoff), monospaced: true)
                row("cryptsize", byteCount(enc.cryptsize), monospaced: true)
                row("cryptid", "\(enc.cryptid)", monospaced: true)
            }
        } else {
            Section {
                Label("未检测", systemImage: "questionmark.circle")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            } header: {
                Text("二进制状态")
            } footer: {
                Text("该 guest 导入于旧版本 Luna，没有加密参数记录。"
                     + "点下方「重新检测」即可补齐，并清除可能过时的警告。")
            }
        }
    }

    private func byteCount(_ bytes: UInt32) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private var warningsSection: some View {
        Section("导入检查") {
            ForEach(current.warnings, id: \.self) { warning in
                Label {
                    Text(warning).font(.system(size: 12))
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private var trustSection: some View {
        Section {
            if current.trustAcknowledged {
                Label("已确认可信来源", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.system(size: 13))
            } else {
                Button {
                    isTrustSheetPresented = true
                } label: {
                    Label("确认可信来源", systemImage: "shield.lefthalf.filled")
                }
                .disabled(current.hasBlockingWarning)
            }
        } header: {
            Text("可信来源")
        } footer: {
            Text("Luna 无法验证第三方 IPA 的真实性，也无法校验 Apple 的代码签名。"
                 + "容器内的所有应用与 Luna 共享同一进程与 Keychain —— 请只导入你自己信任的来源。")
        }
    }

    private func row(_ title: String, _ value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .top) {
            Text(title)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .font(.system(size: 13, design: monospaced ? .monospaced : .default))
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

// MARK: - Trust gate

/// A deliberate speed bump before a guest is first launched.
///
/// This is the most important screen in the app. Everything Luna runs shares
/// one process and one keychain, and Luna has no ability to verify what an IPA
/// actually does. The only real defence is an informed user, so the friction
/// here is intentional.
struct TrustAcknowledgementSheet: View {

    let guest: GuestApp
    let onConfirm: () -> Void
    let onCancel: () -> Void

    @State private var hasScrolledToBottom = false
    @State private var isChecked = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 12) {
                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 30))
                            .foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(guest.displayName)
                                .font(.headline)
                            Text(guest.bundleIdentifier)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }

                    Divider()

                    risk(
                        "唯一的进程",
                        "guest 与 Luna 运行在同一个进程、同一个 UID 下。它拥有 Luna 的全部权限，"
                        + "包括读写 Luna 容器内所有文件的能力。"
                    )
                    risk(
                        "共享的 Keychain",
                        "Luna 为每个 guest 分配了独立的 Keychain 组，但这只是降低误碰，"
                        + "不是安全边界。恶意 guest 仍可能触及共享凭据。"
                    )
                    risk(
                        "无签名校验",
                        "Luna 无法验证该 IPA 的代码签名，也无法判断它内部实际做了什么。"
                        + "一个看起来正常的应用可以包含任意逻辑。"
                    )
                    risk(
                        "已知的真实案例",
                        "同类容器工具已出现过闭源第三方构建窃取用户 Keychain 与登录凭据的事件。"
                        + "风险不是理论上的。"
                    )

                    Divider()

                    Toggle(isOn: $isChecked) {
                        Text("我确认该应用来自我自己信任的来源，并理解上述风险。")
                            .font(.system(size: 13))
                    }

                    Color.clear.frame(height: 1)
                        .onAppear { hasScrolledToBottom = true }
                }
                .padding(20)
            }
            .navigationTitle("运行前确认")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("取消", action: onCancel)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("确认") { onConfirm() }
                        .disabled(!isChecked)
                        .fontWeight(.semibold)
                }
            }
        }
    }

    private func risk(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            Text(body)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

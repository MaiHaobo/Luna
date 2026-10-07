//
//  SettingsView.swift
//  Luna
//
//  Container maintenance and the compliance disclosures.
//

import SwiftUI
import UIKit

struct SettingsView: View {

    @EnvironmentObject private var store: GuestStore
    @EnvironmentObject private var coordinator: SessionCoordinator

    @State private var storageReport: StorageReport?
    @State private var isComputingStorage = false
    @State private var isEntitlementsPresented = false

    var body: some View {
        NavigationStack {
            List {
                Section("存储") {
                    if isComputingStorage {
                        HStack {
                            ProgressView().controlSize(.small)
                            Text("统计中…").font(.system(size: 13)).foregroundStyle(.secondary)
                        }
                    } else if let report = storageReport {
                        infoRow("Guest 数量", "\(report.guestCount)")
                        infoRow("应用占用", report.bundleSize)
                        infoRow("数据占用", report.dataSize)
                        infoRow("修补产物", report.patchedSize)
                        infoRow("合计", report.totalSize)
                    } else {
                        Button("统计存储占用") { computeStorage() }
                    }
                }

                Section("容器路径") {
                    pathRow("导入收件夹", LunaPaths.importInboxDirectory.path)
                    pathRow("根目录", LunaPaths.root.path)
                    pathRow("Guest 数据", LunaPaths.guestDataDirectory.path)
                    pathRow("修补产物", LunaPaths.patchedDirectory.path)
                }

                Section {
                    Button {
                        isEntitlementsPresented = true
                    } label: {
                        Label("查看 Keychain 组模板", systemImage: "key.horizontal")
                    }
                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("关于与合规", systemImage: "info.circle")
                    }
                } footer: {
                    Text("Luna 需要 128 个 Keychain 访问组来为每个 guest 分配独立分区。"
                         + "模板可直接用于 Xcode 签名配置。")
                }

                Section("危险操作") {
                    Button(role: .destructive) {
                        for guest in store.guests {
                            store.delete(guest, purgeData: true)
                        }
                    } label: {
                        Label("删除全部应用与数据", systemImage: "trash")
                    }
                    .disabled(store.guests.isEmpty)
                }
            }
            .navigationTitle("设置")
            .sheet(isPresented: $isEntitlementsPresented) {
                EntitlementsTemplateView()
            }
        }
    }

    private func computeStorage() {
        isComputingStorage = true
        let guests = store.guests
        Task.detached(priority: .utility) {
            let bundles = guests.reduce(Int64(0)) { $0 + directorySize($1.bundleURL) }
            let data = guests.reduce(Int64(0)) { $0 + directorySize($1.dataURL) }
            let patched = guests.reduce(Int64(0)) { $0 + directorySize($1.patchedDirectoryURL) }
            let report = StorageReport(
                guestCount: guests.count,
                bundleSize: ByteCountFormatter.string(fromByteCount: bundles, countStyle: .file),
                dataSize: ByteCountFormatter.string(fromByteCount: data, countStyle: .file),
                patchedSize: ByteCountFormatter.string(fromByteCount: patched, countStyle: .file),
                totalSize: ByteCountFormatter.string(fromByteCount: bundles + data + patched, countStyle: .file)
            )
            await MainActor.run {
                storageReport = report
                isComputingStorage = false
            }
        }
    }

    private func infoRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title).font(.system(size: 13)).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).font(.system(size: 13))
        }
    }

    private func pathRow(_ title: String, _ path: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            Text(path)
                .font(.system(size: 10, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(3)
        }
    }
}

struct StorageReport {
    let guestCount: Int
    let bundleSize: String
    let dataSize: String
    let patchedSize: String
    let totalSize: String
}

private func directorySize(_ url: URL) -> Int64 {
    guard let enumerator = FileManager.default.enumerator(
        at: url,
        includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
        options: [.skipsHiddenFiles]
    ) else { return 0 }
    var total: Int64 = 0
    for case let fileURL as URL in enumerator {
        let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        if values?.isRegularFile == true {
            total += Int64(values?.fileSize ?? 0)
        }
    }
    return total
}

// MARK: - Entitlements template

struct EntitlementsTemplateView: View {

    @Environment(\.dismiss) private var dismiss

    private var template: String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \(KeychainGroupAllocator.entitlementsFragment())
        </dict>
        </plist>
        """
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(template)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationTitle("Keychain 组模板")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("关闭") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        UIPasteboard.general.string = template
                    } label: {
                        Label("拷贝", systemImage: "doc.on.doc")
                    }
                }
            }
        }
    }
}

// MARK: - About

struct AboutView: View {

    var body: some View {
        List {
            Section("Luna 是什么") {
                Text("""
                一个在 iOS 应用内部解压、检查并准备第三方 IPA 的容器。
                它不会把任何东西安装到系统 —— 所有内容都保存在 Luna 自己的沙盒目录中。
                """)
                .font(.system(size: 13))
            }

            Section("能做什么") {
                bullet("导入 IPA 并在容器内解压")
                bullet("解析 Mach-O，识别架构、段、加密状态与依赖")
                bullet("完成加载前所需的二进制改写（filetype / __PAGEZERO / LC_LOAD_DYLIB）")
                bullet("为每个 guest 分配独立的 Keychain 访问组")
                bullet("在应用内的浮层窗口中承载 guest 会话")
            }

            Section("不能做什么") {
                bullet("上架 App Store —— 违反审核指南 2.5.2", negative: true)
                bullet("在未获得 JIT 权限的设备上映射 guest 代码", negative: true)
                bullet("解密 FairPlay 加密的 IPA —— 系统密钥不可及，请使用已解密（脱壳）的构建", negative: true)
                bullet("验证第三方 IPA 的代码签名或合法性", negative: true)
                bullet("隔离 guest 之间的文件访问", negative: true)
            }

            Section("许可与致谢") {
                Text("""
                Luna 的实现参考了 LiveContainer（Apache-2.0）、litehook 与 ZSign 等开源项目
                在应用内加载领域积累的公开技术资料。相关致谢见仓库 docs/ACKNOWLEDGEMENTS.md。
                """)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("关于")
    }

    private func bullet(_ text: String, negative: Bool = false) -> some View {
        Label {
            Text(text).font(.system(size: 13))
        } icon: {
            Image(systemName: negative ? "xmark.circle" : "checkmark.circle")
                .foregroundStyle(negative ? .red : .green)
        }
    }
}

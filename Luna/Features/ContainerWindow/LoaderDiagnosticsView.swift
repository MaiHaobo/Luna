//
//  LoaderDiagnosticsView.swift
//  Luna
//
//  Shows what the current build can and cannot do, and why.
//
//  This screen exists because the honest answer to "why won't my app run" is
//  almost always one of three environmental facts, not a bug: no JIT
//  entitlement, an encrypted binary, or a binary that isn't arm64. Surfacing
//  those facts concretely is more useful than a generic error.
//

import SwiftUI
import UIKit

struct LoaderDiagnosticsView: View {

    @EnvironmentObject private var coordinator: SessionCoordinator

    var body: some View {
        NavigationStack {
            List {
                Section {
                    verdict
                }

                Section("能力探测") {
                    capabilityRow(
                        "可写可执行内存",
                        value: coordinator.capabilities.hasWritableExecutableMemory,
                        detail: "dyld 重定位自我映射镜像的必要条件")
                    capabilityRow(
                        "调试器已附加",
                        value: coordinator.capabilities.isDebugged,
                        detail: "iOS 上 get-task-allow 的通常表现，也是 JIT 的前置条件")
                    capabilityRow(
                        "特权环境",
                        value: coordinator.capabilities.isPrivilegedEnvironment,
                        detail: "TrollStore / 越狱环境下沙盒限制被放宽")
                }

                if let reason = coordinator.runtimeUnavailabilityReason {
                    Section("运行时加载被阻断的原因") {
                        ForEach(reason.split(separator: "\n").map(String.init), id: \.self) { line in
                            Label {
                                Text(line).font(.system(size: 12))
                            } icon: {
                                Image(systemName: "nosign").foregroundStyle(.red)
                            }
                        }
                    }
                }

                Section("环境") {
                    infoRow("Luna 版本", LunaEnvironment.appVersion)
                    infoRow("系统版本", UIDevice.current.systemVersion)
                    infoRow("设备", UIDevice.current.model)
                    infoRow("已启用加载器", coordinator.isRunningDegraded ? "预览模式" : "运行时加载")
                    infoRow("加载器 Shim", LunaEnvironment.hasLoaderShim ? "已随包提供" : "未随包提供")
                }

                Section {
                    Text("""
                    在 App Store 分发的构建里，上述任一项都不会通过 —— Apple 不允许应用申请可执行内存。
                    这正是 Luna 必须以未签名 IPA 形式侧载的原因，也是它无法上架的原因。
                    """)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("诊断")
        }
    }

    private var verdict: some View {
        HStack(spacing: 14) {
            Image(systemName: coordinator.isRunningDegraded
                  ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                .font(.system(size: 30))
                .foregroundStyle(coordinator.isRunningDegraded ? .orange : .green)
            VStack(alignment: .leading, spacing: 3) {
                Text(coordinator.isRunningDegraded ? "当前为预览模式" : "运行时加载可用")
                    .font(.system(size: 15, weight: .semibold))
                Text(coordinator.isRunningDegraded
                     ? "容器、解压、二进制修补均正常工作；代码映射被系统阻止。"
                     : "满足全部前置条件，可以映射 guest 镜像。")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 6)
    }

    private func capabilityRow(_ title: String, value: Bool, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: value ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(value ? .green : .red)
                .font(.system(size: 17))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 14, weight: .medium))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    private func infoRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title).font(.system(size: 13)).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).font(.system(size: 13, design: .monospaced))
        }
    }
}

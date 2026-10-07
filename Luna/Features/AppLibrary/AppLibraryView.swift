//
//  AppLibraryView.swift
//  Luna
//
//  The guest list, and the entry point for importing one.
//

import SwiftUI
import UniformTypeIdentifiers

struct AppLibraryView: View {

    @EnvironmentObject private var store: GuestStore
    @EnvironmentObject private var coordinator: SessionCoordinator

    @State private var isImporterPresented = false
    @State private var detailGuest: GuestApp?
    @State private var pendingDelete: GuestApp?
    @State private var alertMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if store.guests.isEmpty {
                    emptyState
                } else {
                    guestList
                }
            }
            .navigationTitle("Luna")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    if coordinator.isRunningDegraded {
                        degradedBadge
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        isImporterPresented = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("导入 IPA")
                }
            }
            .safeAreaInset(edge: .bottom) {
                if let stage = store.importStage {
                    importBanner(stage)
                }
            }
            .fileImporter(
                isPresented: $isImporterPresented,
                allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    if !await store.importIPA(from: url) {
                        alertMessage = "已有导入正在进行，请稍候再试。"
                    }
                case .failure(let error):
                    alertMessage = error.localizedDescription
                }
            }
            .sheet(item: $detailGuest) { guest in
                GuestDetailView(guest: guest)
                    .environmentObject(store)
                    .environmentObject(coordinator)
            }
            .confirmationDialog(
                "删除 \(pendingDelete?.displayName ?? "")？",
                isPresented: Binding(
                    get: { pendingDelete != nil },
                    set: { if !$0 { pendingDelete = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("仅删除应用，保留数据") {
                    if let guest = pendingDelete { store.delete(guest, purgeData: false) }
                    pendingDelete = nil
                }
                Button("删除应用并清空数据", role: .destructive) {
                    if let guest = pendingDelete { store.delete(guest, purgeData: true) }
                    pendingDelete = nil
                }
                Button("取消", role: .cancel) { pendingDelete = nil }
            } message: {
                Text("guest 数据保存在 Luna 容器内，不会随应用删除自动清除。")
            }
            .alert("提示", isPresented: Binding(
                get: { alertMessage != nil || coordinator.launchError != nil },
                set: {
                    if !$0 {
                        alertMessage = nil
                        coordinator.launchError = nil
                    }
                }
            )) {
                Button("好") {
                    alertMessage = nil
                    coordinator.launchError = nil
                }
            } message: {
                Text(alertMessage ?? coordinator.launchError ?? "")
            }
        }
    }

    // MARK: - List

    private var guestList: some View {
        List {
            Section {
                ForEach(store.guests) { guest in
                    GuestRow(guest: guest)
                        .contentShape(Rectangle())
                        .onTapGesture { detailGuest = guest }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                pendingDelete = guest
                            } label: {
                                Label("删除", systemImage: "trash")
                            }
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                Task { await launch(guest) }
                            } label: {
                                Label("运行", systemImage: "play.fill")
                            }
                            .tint(.green)
                        }
                }
            } footer: {
                Text("所有 guest 均存放于 Luna 容器内，未安装到系统。"
                     + "卸载 Luna 会一并移除它们。")
            }
        }
        .listStyle(.insetGrouped)
        .refreshable { await store.scanImportInbox() }
    }

    private func launch(_ guest: GuestApp) async {
        guard guest.trustAcknowledged else {
            detailGuest = guest
            return
        }
        coordinator.launch(guest)
    }

    // MARK: - Empty state

    private var emptyState: some View {
        ContentUnavailableView {
            Label("还没有应用", systemImage: "square.stack.3d.up.slash")
        } description: {
            Text("点击右上角 + 选择 IPA，或用「文件」App 把 IPA 放到 Luna 的 Import 文件夹里，回到 Luna 会自动导入。")
        } actions: {
            Button("导入 IPA") { isImporterPresented = true }
                .buttonStyle(.borderedProminent)
        }
    }

    // MARK: - Chrome

    private var degradedBadge: some View {
        Label("预览模式", systemImage: "exclamationmark.circle")
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(.orange)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(Color.orange.opacity(0.15)))
    }

    private func importBanner(_ stage: ImportStage) -> some View {
        HStack(spacing: 10) {
            switch stage {
            case .finished:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .failed:
                Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            default:
                ProgressView().controlSize(.small)
            }

            Text(stage.label)
                .font(.system(size: 13))
                .lineLimit(2)

            Spacer()

            if case .finished = stage {
                Button("查看") {
                    store.clearImportStage()
                }
                .font(.system(size: 13, weight: .medium))
            }
            if case .failed = stage {
                Button("关闭") { store.clearImportStage() }
                    .font(.system(size: 13, weight: .medium))
            }
        }
        // The import banner floats above the library list, which is exactly
        // the navigation layer the material is meant for. `.bar` was a
        // pre-iOS-26 approximation of the same idea; glassEffect is the
        // system's own treatment and picks up the list scrolling underneath.
        //
        // The padding moves after the material on purpose: applied before, it
        // would be measured into the glass's own bounds and the rounded edge
        // would land inside the banner rather than around it.
        .lunaGlassCard(cornerRadius: 16)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .transition(.move(edge: .bottom).combined(with: .opacity))
        .animation(.easeInOut, value: stage)
    }
}

// MARK: - Row

struct GuestRow: View {

    let guest: GuestApp

    var body: some View {
        HStack(spacing: 12) {
            iconView

            VStack(alignment: .leading, spacing: 3) {
                Text(guest.displayName)
                    .font(.system(size: 15, weight: .medium))
                    .lineLimit(1)
                Text("\(guest.bundleIdentifier) · \(guest.version)")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 6)

            VStack(alignment: .trailing, spacing: 4) {
                stateBadge
                if guest.hasBlockingWarning {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 9))
                        .foregroundStyle(.red)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var iconView: some View {
        RoundedRectangle(cornerRadius: 10, style: .continuous)
            .fill(Color.accentColor.opacity(0.16))
            .frame(width: 42, height: 42)
            .overlay(
                Text(String(guest.displayName.prefix(1)).uppercased())
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Color.accentColor)
            )
    }

    private var stateBadge: some View {
        Text(guest.state.label)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private var color: Color {
        switch guest.state {
        case .imported: return .gray
        case .ready: return .blue
        case .launching: return .orange
        case .launched: return .green
        case .failed: return .red
        }
    }
}

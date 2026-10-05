//
//  SessionCoordinator.swift
//  Luna
//
//  Owns the lifecycle of container sessions: choosing a loader, running the
//  launch, presenting the window, and feeding the session's log.
//

import SwiftUI
import UIKit

@MainActor
final class SessionCoordinator: ObservableObject {

    /// The session currently on screen, if any.
    @Published private(set) var activeSession: ContainerSession?

    /// Set when a launch could not proceed, for an alert.
    @Published var launchError: String?

    private var window: ContainerWindow?
    private let registry: LoaderRegistry
    private let store: GuestStore

    init(store: GuestStore) {
        self.store = store
        self.registry = LoaderRegistry()

        // Wire the preview loader's presentation callback.
        registry.preview.onPresent = { [weak self] guest, report, executable in
            self?.presentSession(
                for: guest,
                report: report,
                executable: executable
            )
        }
    }

    var capabilities: LoaderCapabilities { registry.capabilities }
    var isRunningDegraded: Bool { registry.isRunningDegraded }
    var runtimeUnavailabilityReason: String? { registry.runtime.unavailabilityReason }

    // MARK: - Launch

    func launch(_ guest: GuestApp) {
        guard activeSession == nil else {
            launchError = "已经有一个会话在运行。请先关闭当前窗口。"
            return
        }

        let loader = registry.active

        // Runtime loader gets its own path so a preview callback never fires
        // for a session the user expects to be real.
        if loader is RuntimeLoader {
            let session = ContainerSession(guest: guest, loaderName: loader.name)
            session.append("选择加载器：\(loader.name)")
            session.append("能力探测通过，开始映射 guest 镜像")
            begin(session)
            do {
                try loader.launch(guest)
            } catch {
                session.markFailed(error.localizedDescription)
                var updated = guest
                updated.state = .failed
                updated.lastError = error.localizedDescription
                store.update(updated)
            }
            return
        }

        do {
            try loader.launch(guest)
        } catch {
            launchError = error.localizedDescription
            var updated = guest
            updated.state = .failed
            updated.lastError = error.localizedDescription
            store.update(updated)
        }
    }

    /// Called by `PreviewLoader` once it has finished preparing a guest.
    private func presentSession(
        for guest: GuestApp,
        report: MachOPatchReport?,
        executable: URL
    ) {
        let session = ContainerSession(guest: guest, loaderName: registry.active.name)
        session.append("容器：\(guest.storageDescription)")
        session.append("可执行文件：\(guest.executableName)")

        if registry.isRunningDegraded {
            session.append("运行时加载不可用，已回退到预览模式")
            if let reason = registry.runtime.unavailabilityReason {
                for line in reason.split(separator: "\n") {
                    session.append(String(line))
                }
            }
        }

        session.markPrepared(report: report, executable: executable)
        session.markRendering()
        begin(session)

        var updated = guest
        updated.state = .launched
        updated.lastLaunchedAt = Date()
        updated.patchSummary = report?.humanReadable
        updated.lastError = nil
        store.update(updated)
    }

    private func begin(_ session: ContainerSession) {
        let window = ContainerWindow(session: session)
        window.onDismiss = { [weak self] in
            self?.activeSession = nil
            self?.window = nil
        }
        self.window = window
        self.activeSession = session
        window.present()
    }

    // MARK: - Teardown

    func closeActiveSession() {
        window?.dismiss()
        window = nil
        activeSession = nil
    }
}

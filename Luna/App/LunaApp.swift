//
//  LunaApp.swift
//  Luna
//

import SwiftUI

@main
struct LunaApp: App {

    @StateObject private var store = GuestStore()
    @StateObject private var certificates = CertificateStore()
    @StateObject private var coordinator: SessionCoordinator
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // `GuestStore` has to exist before the coordinator, which needs it for
        // state write-back on launch.
        let store = GuestStore()
        _store = StateObject(wrappedValue: store)
        _coordinator = StateObject(wrappedValue: SessionCoordinator(store: store))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(certificates)
                .environmentObject(coordinator)
                .task {
                    store.bootstrap()
                    // Certificates load after the guest store, because
                    // `bootstrap()` is what creates the directory tree both
                    // stores read from.
                    certificates.bootstrap()
                    await store.scanImportInbox()
                }
                .onChange(of: scenePhase) { _, phase in
                    // Certificate *material* dropped in `CertImport/` is
                    // deliberately not auto-imported: a `.p12` needs a
                    // password, and there is no way to ask for one from a
                    // background scan. The list screen imports what it finds.
                    if phase == .active {
                        Task { await store.scanImportInbox() }
                    }
                }
        }
    }
}

struct RootView: View {

    @EnvironmentObject private var store: GuestStore
    @EnvironmentObject private var coordinator: SessionCoordinator

    var body: some View {
        TabView {
            AppLibraryView()
                .tabItem { Label("应用", systemImage: "square.stack.3d.up") }

            LoaderDiagnosticsView()
                .tabItem { Label("诊断", systemImage: "stethoscope") }

            SettingsView()
                .tabItem { Label("设置", systemImage: "gearshape") }
        }
    }
}

//
//  LunaApp.swift
//  Luna
//

import SwiftUI

@main
struct LunaApp: App {

    @StateObject private var store = GuestStore()
    @StateObject private var coordinator: SessionCoordinator

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
                .environmentObject(coordinator)
                .task { store.bootstrap() }
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

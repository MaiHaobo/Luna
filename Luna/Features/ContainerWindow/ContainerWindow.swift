//
//  ContainerWindow.swift
//  Luna
//
//  The in-app virtual window.
//
//  WHY A SEPARATE UIWindow
//  -----------------------
//  A guest session needs to occupy a region of the screen that behaves like a
//  device: its own coordinate space, its own appearance, its own status area,
//  and its own dismissal. Rendering that as a child view controller inside the
//  main hierarchy fights with the navigation stack — the guest's own
//  `presentViewController` calls would land in Luna's hierarchy, and Luna's
//  navigation bar would sit on top of it.
//
//  A second `UIWindow` at a high window level gives the session a clean
//  boundary with no interaction with Luna's own view tree. Closing the window
//  tears the whole session down in one step, which is exactly the semantics we
//  want. Everything here is public API.
//

import SwiftUI
import UIKit

/// A resizable, draggable window that hosts a guest session.
@MainActor
final class ContainerWindow: UIWindow {

    /// Called when the user dismisses the window.
    var onDismiss: (() -> Void)?

    private let session: ContainerSession

    init(session: ContainerSession) {
        self.session = session

        // A UIWindow must belong to a scene. Luna declares a single-scene
        // manifest, so there is exactly one candidate in practice, but we
        // still prefer the active one so the window lands correctly when the
        // app is returning from the background.
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
            ?? UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first

        guard let scene else {
            // Without a scene a UIWindow cannot be created at all. The
            // coordinator checks `canPresentWindow` before it gets here, so
            // this is a defensive tripwire rather than a user-facing path.
            preconditionFailure("Luna requires an active UIWindowScene")
        }

        super.init(windowScene: scene)

        // Sit just above the app's normal windows but below system alerts, so
        // a permission prompt from the system still wins.
        self.windowLevel = .normal + 1
        self.backgroundColor = .clear

        let host = UIHostingController(
            rootView: ContainerWindowRootView(
                session: session,
                onClose: { [weak self] in self?.dismiss() }
            )
        )
        host.view.backgroundColor = .clear
        self.rootViewController = host
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func present() {
        isHidden = false
        makeKeyAndVisible()
    }

    func dismiss() {
        session.end()
        isHidden = true
        // Hand key status back to whatever was key before.
        windowsBelow().last?.makeKey()
        onDismiss?()
    }

    private func windowsBelow() -> [UIWindow] {
        (windowScene?.windows ?? [])
            .filter { $0 !== self && !$0.isHidden }
            .sorted { $0.windowLevel < $1.windowLevel }
    }
}

// MARK: - Session

/// The state of one running guest.
@MainActor
final class ContainerSession: ObservableObject {

    /// Phase of the session lifecycle.
    enum Phase: Equatable {
        case preparing
        case rendering
        case ended
        case failed(String)

        var label: String {
            switch self {
            case .preparing: return "准备中"
            case .rendering: return "运行中"
            case .ended: return "已结束"
            case .failed: return "失败"
            }
        }
    }

    let guest: GuestApp
    @Published private(set) var phase: Phase = .preparing
    @Published private(set) var patchReport: MachOPatchReport?
    @Published private(set) var patchedExecutableURL: URL?
    @Published private(set) var logLines: [String] = []
    @Published private(set) var startedAt = Date()

    /// Set when the runtime loader mapped the image. `nil` for preview
    /// sessions, which is how the canvas knows to show the spec sheet instead
    /// of the "image mapped" readout.
    @Published private(set) var dyldReport: DyldLoadReport?

    /// Which loader produced this session.
    let loaderName: String

    var elapsed: TimeInterval { Date().timeIntervalSince(startedAt) }

    init(guest: GuestApp, loaderName: String) {
        self.guest = guest
        self.loaderName = loaderName
    }

    func append(_ line: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        logLines.append("[\(formatter.string(from: Date()))] \(line)")
        if logLines.count > 500 { logLines.removeFirst(logLines.count - 500) }
    }

    func markPrepared(report: MachOPatchReport?, executable: URL?) {
        patchReport = report
        patchedExecutableURL = executable
        if report != nil {
            append("二进制修补完成")
        } else {
            append("二进制修补未执行")
        }
    }

    func markRendering() { phase = .rendering }

    /// Records a successful dyld load and moves the session to `rendering`.
    func markLoaded(report: DyldLoadReport) {
        dyldReport = report
        append("镜像已映射进本进程，入口点已解析")
        phase = .rendering
    }

    func markFailed(_ message: String) {
        append("失败：\(message)")
        phase = .failed(message)
    }

    func end() {
        append("会话结束")
        phase = .ended
    }
}

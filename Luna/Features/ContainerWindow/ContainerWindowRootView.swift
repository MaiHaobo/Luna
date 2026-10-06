//
//  ContainerWindowRootView.swift
//  Luna
//
//  Chrome for the virtual window: a title bar with a device frame around the
//  guest's rendering surface.
//

import SwiftUI

struct ContainerWindowRootView: View {

    @ObservedObject var session: ContainerSession
    let onClose: () -> Void

    @State private var isLogExpanded = false

    var body: some View {
        VStack(spacing: 0) {
            titleBar
            Divider().overlay(Color.white.opacity(0.12))
            content
            if isLogExpanded {
                Divider().overlay(Color.white.opacity(0.12))
                logPane
            }
        }
        // Liquid Glass, tinted dark. The overlay hosts a pure-black guest
        // canvas and draws white chrome over it, so plain glass would sample
        // the app behind the window and turn this into a light surface that
        // the white labels cannot sit on.
        //
        // Two things this deliberately no longer does. It does not paint an
        // opaque `secondarySystemBackground` fill: an opaque backing covers
        // the backdrop, leaving the material nothing to sample, which renders
        // glass as a flat grey rectangle. And it does not `.clipShape` the
        // card: the glass effect draws its own rounded bounds and clips to
        // them, so clipping again would cut off the highlight that makes the
        // material read as glass.
        //
        // Order matters. `glassEffect` must come after the layout-affecting
        // modifiers, and the outer `.padding` must stay outside it, or the
        // twelve-point inset gets swallowed into the material and the shadow
        // lands on the wrong bounds.
        .lunaGlassDarkScrim(cornerRadius: 18)
        .shadow(color: .black.opacity(0.35), radius: 24, y: 10)
        .padding(12)
    }

    // MARK: - Title bar

    private var titleBar: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(statusColor)
                .frame(width: 9, height: 9)

            VStack(alignment: .leading, spacing: 1) {
                // Both lines are explicit whites. The title bar previously sat
                // on an opaque `tertiarySystemBackground`, where `.primary` and
                // `.secondary` resolved correctly per appearance. It now sits
                // on dark glass, so the dynamic styles would render near-black
                // text in light mode against a dark surface.
                Text(session.guest.displayName)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Text("\(session.phase.label) · \(session.loaderName)")
                    .font(.system(size: 10))
                    .foregroundStyle(.white.opacity(0.6))
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            Button {
                isLogExpanded.toggle()
            } label: {
                Image(systemName: isLogExpanded ? "text.alignleft" : "text.alignleft")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.white)
                    .opacity(isLogExpanded ? 1 : 0.5)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("切换日志面板")

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 12, weight: .bold))
                    .padding(6)
                    .background(Circle().fill(Color.red.opacity(0.85)))
                    .foregroundStyle(.white)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("关闭窗口")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var statusColor: Color {
        switch session.phase {
        case .preparing: return .orange
        case .rendering: return .green
        case .ended: return .gray
        case .failed: return .red
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        switch session.phase {
        case .failed(let message):
            failureBody(message)
        default:
            deviceFrame
        }
    }

    /// A phone-shaped rendering surface, plus the state readout.
    private var deviceFrame: some View {
        VStack(spacing: 0) {
            ZStack {
                // The guest's pixels will land in this region. In preview mode
                // we render a spec sheet instead of a live surface; the frame
                // itself is identical either way, so the layout is already
                // correct when the runtime loader is wired up.
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color.black)

                GuestCanvas(session: session)
            }
            .aspectRatio(390.0 / 620.0, contentMode: .fit)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 14)
            .padding(.top, 12)

            statusStrip
        }
    }

    private var statusStrip: some View {
        HStack(spacing: 14) {
            metric("版本", session.guest.version)
            metric("Bundle", session.guest.bundleIdentifier, truncate: true)
            metric("修补", session.patchReport == nil ? "未执行" : "已完成")
            metric("运行", session.elapsed.formattedDuration)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
    }

    private func metric(_ title: String, _ value: String, truncate: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(.white.opacity(0.5))
            Text(value)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.white.opacity(0.85))
                .lineLimit(1)
                .truncationMode(truncate ? .middle : .tail)
        }
    }

    // MARK: - Failure

    private func failureBody(_ message: String) -> some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 34))
                .foregroundStyle(.orange)
            Text("无法启动")
                .font(.headline)
                .foregroundStyle(.white)
            Text(message)
                .font(.system(size: 12))
                .foregroundStyle(.white.opacity(0.7))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 28)
            Button("关闭窗口", action: onClose)
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Log

    private var logPane: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(session.logLines.enumerated()), id: \.offset) { pair in
                        Text(pair.element)
                            .font(.system(size: 10, design: .monospaced))
                            // An explicit white rather than `.secondary`. The
                            // pane used to be opaque black, where the dynamic
                            // secondary style resolved to a legible grey. It
                            // is now a translucent pane over dark glass, so
                            // the resolved colour follows the system
                            // appearance and drifts toward unreadable in
                            // light mode.
                            .foregroundStyle(.white.opacity(0.72))
                            .textSelection(.enabled)
                            .id(pair.offset)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
            }
            .frame(height: 150)
            .background(LunaGlassPalette.codePane)
            .onChange(of: session.logLines.count) { _, count in
                withAnimation { proxy.scrollTo(count - 1, anchor: .bottom) }
            }
        }
    }
}

// MARK: - Guest canvas

/// The region a guest would draw into.
///
/// In preview mode this renders the guest's inspected metadata, which is what
/// makes preview mode useful rather than decorative: it shows the real bundle
/// ID, the real patch report, and the real blockers.
private struct GuestCanvas: View {

    @ObservedObject var session: ContainerSession

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if let report = session.patchReport {
                    section("二进制修补报告") {
                        Text(report.humanReadable)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green.opacity(0.9))
                            .textSelection(.enabled)
                    }
                }
                if let executable = session.patchedExecutableURL {
                    section("已修补产物") {
                        Text(executable.lastPathComponent)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                if !session.guest.warnings.isEmpty {
                    section("导入时发现的警告") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(session.guest.warnings, id: \.self) { warning in
                                Label(warning, systemImage: "exclamationmark.triangle")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.yellow.opacity(0.95))
                            }
                        }
                    }
                }
                section("容器说明") {
                    Text("""
                    Luna 已解压该 bundle、解析其 Mach-O、完成加载前所需的二进制改写，并准备好会话容器。
                    这些步骤都不依赖 JIT。可选的运行时加载器会把改写后的二进制映射进进程，
                    那一步需要 JIT 权限；未满足时停在此处，而不是以崩溃告终。
                    """)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(session.guest.displayName)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(.white)
            Text(session.guest.bundleIdentifier)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.white.opacity(0.55))
        }
    }

    private func section<Content: View>(
        _ title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.white.opacity(0.4))
                .tracking(0.6)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Formatting

extension TimeInterval {
    var formattedDuration: String {
        let total = Int(self)
        let minutes = total / 60
        let seconds = total % 60
        return String(format: "%d:%02d", minutes, seconds)
    }
}

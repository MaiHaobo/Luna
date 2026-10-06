import SwiftUI

// MARK: - Liquid Glass style layer
//
// Luna targets iOS 26, so the system's Liquid Glass material is available
// directly. This file is the single place that decides how Luna uses it, so
// the individual views stay readable and the material is applied consistently.
//
// Deliberately an `extension View` rather than a `ViewModifier`: a modifier
// needs a new `struct` type, and tools/swift_sanity.py fails the build on
// duplicate type names across files. Extensions are exempt from that check.
//
// A second deliberate choice: these helpers do NOT forward a generic `Shape`.
// Writing `func glass<S: Shape>(in shape: S)` by hand is easy to get subtly
// wrong against the SDK's own constraints (Shape conforms to Sendable and
// Animatable), and a signature mismatch only surfaces on a macOS CI run. Two
// fixed shapes cover every call site we have, and let the compiler resolve
// the generic against the real API.

extension View {

    /// A glass panel: floating banners, cards, popovers.
    ///
    /// Per Apple's guidance this belongs on the *navigation* layer — things
    /// that float above content. Do not apply it to list rows or body text;
    /// the material samples the backdrop, which makes dense content harder
    /// to read.
    func lunaGlassCard(cornerRadius: CGFloat = 18) -> some View {
        self.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
    }

    /// A darkened glass panel, for the guest container overlay.
    ///
    /// That window hosts a pure-black guest canvas and draws white chrome on
    /// top of it. Plain glass would sample the app behind it and produce a
    /// light surface that the white labels cannot sit on, so the glass is
    /// tinted dark to keep the overlay's contrast.
    func lunaGlassDarkScrim(cornerRadius: CGFloat = 18) -> some View {
        self.glassEffect(
            .regular.tint(.black.opacity(0.30)),
            in: .rect(cornerRadius: cornerRadius)
        )
    }
}

// MARK: - Palette

/// Colours shared by the glass surfaces.
///
/// Only the handful of values that were previously duplicated as literals
/// across views live here. Anything that already reads clearly through a
/// semantic style (`.primary`, `.secondary`, `.tint`) is left alone.
enum LunaGlassPalette {

    /// Luna's accent, resolved through the asset catalog so the two do not
    /// drift apart.
    static let accent = Color.accentColor

    /// Scrim behind the guest overlay, when the app underneath must be
    /// dimmed rather than blurred.
    static let overlayScrim = Color.black.opacity(0.55)

    /// Backing for the log console inside the overlay. Opaque enough for
    /// monospaced output to stay legible, sheer enough to read as glass.
    static let codePane = Color.black.opacity(0.35)
}

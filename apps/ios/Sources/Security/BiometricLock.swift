// SEC-022: Biometric authentication gating for the iOS app.
//
// Usage: call `BiometricLock.shared.authenticate()` when the app returns
// to the foreground (in the scene phase change handler).
// If biometric auth is disabled in settings, this is a no-op.

import LocalAuthentication
import SwiftUI

@Observable
final class BiometricLock {
    static let shared = BiometricLock()

    private(set) var isLocked = false
    private(set) var biometricType: LABiometryType = .none

    private let settingsKey = "openclaw.biometricLockEnabled"

    var isEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: settingsKey) }
        set { UserDefaults.standard.set(newValue, forKey: settingsKey) }
    }

    var biometricLabel: String {
        switch biometricType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        @unknown default: return "Biometrics"
        }
    }

    var isAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    private init() {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            biometricType = context.biometryType
        }
    }

    func lockIfEnabled() {
        guard isEnabled else { return }
        isLocked = true
    }

    @MainActor
    func authenticate() async {
        guard isEnabled, isLocked else { return }
        let context = LAContext()
        context.localizedFallbackTitle = "Use Passcode"

        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Unlock OpenClaw")
            if success {
                isLocked = false
            }
        } catch {
            // Authentication failed or was cancelled — keep locked.
        }
    }
}

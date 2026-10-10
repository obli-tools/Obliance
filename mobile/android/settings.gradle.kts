pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "obli-shell-android"

include(":app")

// Platform, app-agnostic: no Obliance type may appear here.
include(":core:common")
include(":core:model")
include(":core:network")
include(":core:auth")
include(":core:designsystem")
include(":core:realtime")
include(":core:security")
// Device-bound validation: Keystore keys and their records.
include(":core:devicekey")
include(":core:data")
// Action host (confirmation, 2FA, approval and privacy prompts, biometric, results) and the web view.
include(":core:security-ui")
include(":core:webfallback")
include(":core:tunnel")

// Obliance.
include(":obliance:domain")
// Native Obliance alpha: plumbing, screens, application.
include(":obliance:api")
include(":obliance:data")
include(":obliance:access")
include(":obliance:triage")
include(":obliance:devices")
include(":obliance:fleet")
include(":obliance:more")
include(":obliance:remote")
include(":obliance:automations")
include(":obliance:notifications")
include(":obliance:app")

// Technical toolchain proofs: compiled and tested, never shipped.
include(":proofs")

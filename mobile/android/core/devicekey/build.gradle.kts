import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Device-bound validation, Android side without UI.
// Keystore keys (KeySpecPlan per API level, StrongBox else TEE,
// attestation), key health, and the persisted records (DataStore). Platform
// module: no Obliance type — "obli-devkey-v1" is common to every Obli app.
plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "tools.obli.core.devicekey"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    api(project(":core:security"))
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)

    // Robolectric has no AndroidKeyStore: the Keystore parameters are tested as a
    // pure plan (KeySpecPlan) and the store over a file DataStore, on the JVM.
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Typed calls of the Obliance server over core:network.
// Pure JVM: every DTO is unit-tested against recorded server shapes.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    api(project(":core:common"))
    api(project(":core:model"))
    api(project(":core:network"))
    // Device-bound validation: the enrolment API contract and the key levels (pure JVM).
    api(project(":core:security"))
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
}

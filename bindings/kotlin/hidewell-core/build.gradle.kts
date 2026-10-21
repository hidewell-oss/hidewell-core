// Android library wrapping the hidewell-core Rust library (UniFFI Kotlin bindings).
// Native libs: src/main/jniLibs (built by scripts/build-android.sh, not committed).
plugins {
    id("com.android.library") version "9.4.1"
}

group = "com.sentrybrain.hidewell"
version = "0.1.0"

android {
    namespace = "com.sentrybrain.hidewell.core"
    compileSdk = 36
    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.all {
            // Host JVM test loads the host build of libhidewell_ffi via JNA.
            val dir = project.findProperty("hostLibDir") as String?
            if (dir != null) it.systemProperty("jna.library.path", dir)
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    testImplementation("net.java.dev.jna:jna:5.19.1")
    testImplementation("junit:junit:4.13.2")
}

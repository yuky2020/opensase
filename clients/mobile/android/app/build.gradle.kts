plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// The Go core (gomobile .aar) is compiled in only when it exists:
//   -Popensase.engine=auto (default) real core if libs/opensase-core.aar exists, else a stub
//   -Popensase.engine=real  fail if the .aar is missing
//   -Popensase.engine=stub  never link the core
val coreAar = layout.projectDirectory.file("libs/opensase-core.aar").asFile
val engineMode = providers.gradleProperty("opensase.engine").getOrElse("auto")
val useGoCore = when (engineMode) {
    "real" -> {
        check(coreAar.exists()) { "opensase.engine=real but ${coreAar.path} is missing" }
        true
    }
    "stub" -> false
    else -> coreAar.exists()
}
logger.lifecycle("OpenSASE native engine: ${if (useGoCore) "Go core (opensase-core.aar)" else "stub"}")

android {
    namespace = "eu.opensase.android"
    compileSdk = 36
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "eu.opensase.android"
        minSdk = 29
        targetSdk = 36
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // The Go core .aar ships arm64-v8a and x86_64 only.
        if (useGoCore) ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    sourceSets {
        getByName("main") {
            java.srcDir(if (useGoCore) "src/gocore/kotlin" else "src/stubcore/kotlin")
        }
    }

    buildTypes {
        release {
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    if (useGoCore) implementation(files(coreAar))
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814") // real org.json for JVM unit tests
}

flutter {
    source = "../.."
}

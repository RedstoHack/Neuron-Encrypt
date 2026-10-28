plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing for the `standard` flavor.
//
// These come from CI environment variables. When they are not all present the
// flavor is built *unsigned* and the build says so loudly. Previously the
// project had no `signingConfigs` block at all, so the CI produced an
// unsigned `standardRelease` APK while the release metadata advertised a
// signed one that could never exist.
val releaseStorePath = System.getenv("UPLOAD_KEYSTORE_PATH")
val releaseStorePassword = System.getenv("UPLOAD_KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("UPLOAD_KEY_ALIAS")
val releaseKeyPassword = System.getenv("UPLOAD_KEY_PASSWORD")
val releaseSigningAvailable = listOf(
    releaseStorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrEmpty() }

android {
    namespace = "com.neuronencrypt.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.neuronencrypt.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 7
        versionName = "2.3.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    signingConfigs {
        if (releaseSigningAvailable) {
            create("release") {
                storeFile = file(releaseStorePath!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    flavorDimensions += "store"
    productFlavors {
        create("fdroid") {
            dimension = "store"
            // F-Droid re-signs the build with its own key, so this flavor
            // must be left unsigned.
            signingConfig = null
        }
        create("standard") {
            dimension = "store"
            signingConfig = if (releaseSigningAvailable) {
                signingConfigs.getByName("release")
            } else {
                logger.warn(
                    "neuron-encrypt: release signing environment is incomplete " +
                        "(UPLOAD_KEYSTORE_PATH / UPLOAD_KEYSTORE_PASSWORD / UPLOAD_KEY_ALIAS / " +
                        "UPLOAD_KEY_PASSWORD) — the standardRelease APK will be UNSIGNED."
                )
                null
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.10"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.navigation:navigation-compose:2.7.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-text")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.foundation:foundation")
}
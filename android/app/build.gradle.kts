plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.gms.google-services")
}

fun quote(value: String): String {
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}

val servoraBaseUrl = (providers.gradleProperty("SERVORA_BASE_URL").orNull ?: "https://example.com").trim().trimEnd('/')
val servoraAppId = (providers.gradleProperty("SERVORA_APP_ID").orNull ?: "ru.servora.tickets").trim()
val servoraAppName = (providers.gradleProperty("SERVORA_APP_NAME").orNull ?: "Servora Tickets").trim()
val servoraAllowCleartext = (providers.gradleProperty("SERVORA_ALLOW_CLEARTEXT").orNull ?: "false").trim()

android {
    namespace = servoraAppId
    compileSdk = 35

    defaultConfig {
        applicationId = servoraAppId
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        buildConfigField("String", "SERVORA_BASE_URL", quote(servoraBaseUrl))
        buildConfigField("String", "WEBVIEW_USER_AGENT_SUFFIX", quote("ServoraAndroidApp/1.0"))
        resValue("string", "app_name", quote(servoraAppName))
        manifestPlaceholders["usesCleartextTraffic"] = servoraAllowCleartext
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            isMinifyEnabled = false
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
        buildConfig = true
    }
}

dependencies {
    implementation(platform("com.google.firebase:firebase-bom:33.10.0"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.webkit:webkit:1.12.1")
    implementation("com.google.firebase:firebase-messaging-ktx")
}

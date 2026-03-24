# Android App Shell

This folder contains a native Android wrapper for the existing Servora web UI.

## What it does

- Opens the current `/web` application inside a WebView.
- Uses the same cookie-based login flow as the browser version.
- Registers the Android device in the backend with `/api/mobile/devices/register`.
- Receives native push notifications through Firebase Cloud Messaging.
- Opens the target ticket URL inside the app when the user taps a notification.

## Backend requirements

Set this variable in the backend `.env` file:

```env
FIREBASE_CREDENTIALS_FILE=./firebase-service-account.json
```

The backend also needs the `firebase-admin` Python dependency and the new Alembic migration `0025_mobile_devices`.

## Android setup

1. Open the `android/` folder in Android Studio.
2. Put the correct backend URL into `android/gradle.properties` as `SERVORA_BASE_URL`.
3. Keep `SERVORA_APP_ID` aligned with your Firebase Android app id. For the first release, use `ru.servora.tickets`.
4. Add `android/app/google-services.json` from Firebase Console.
5. Sync Gradle and build the APK.

Detailed setup:

- `android/FIREBASE_SETUP.md`
- `android/FIRST_RELEASE_CHECKLIST.md`

## Notes

- Production should use HTTPS. Voice comments in WebView depend on secure context rules.
- `SERVORA_ALLOW_CLEARTEXT=true` is only for local testing against non-HTTPS servers.
- Browser web push remains available for the PWA. Android APK push uses FCM independently.

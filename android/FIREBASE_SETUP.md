# Firebase Setup

This runbook gets the Android APK and backend mobile push working together.

## 1. Backend service account

1. Open Firebase Console.
2. Select your project.
3. Open `Project settings -> Service accounts`.
4. Click `Generate new private key`.
5. Save the JSON file as `firebase-service-account.json` in the project root or another secure path outside git.

Set the backend env variable:

```env
FIREBASE_CREDENTIALS_FILE=./firebase-service-account.json
```

The backend uses this file for FCM sends through `firebase-admin`.

## 2. Android app registration

Use this Android application id for the first release unless you intentionally want a different one:

```text
ru.servora.tickets
```

In Firebase Console:

1. Open `Project settings -> General`.
2. In `Your apps`, click `Add app`.
3. Choose Android.
4. Enter package name `ru.servora.tickets`.
5. Optionally set an app nickname like `Servora Tickets Android`.
6. Register the app.
7. Download `google-services.json`.
8. Place it into `android/app/google-services.json`.

## 3. Android project values

Open [gradle.properties](/c:/Projects/tickets_simple/android/gradle.properties) and set:

```properties
SERVORA_BASE_URL=https://your-domain.example
SERVORA_APP_ID=ru.servora.tickets
SERVORA_APP_NAME=Servora Tickets
SERVORA_ALLOW_CLEARTEXT=false
```

Notes:

- `SERVORA_BASE_URL` must be the exact public HTTPS origin used by the FastAPI app.
- `SERVORA_APP_ID` must match the package registered in Firebase.
- Leave `SERVORA_ALLOW_CLEARTEXT=false` in production.

## 4. Backend rollout

1. Install dependencies from [requirements.txt](/c:/Projects/tickets_simple/requirements.txt).
2. Run Alembic:

```bash
alembic upgrade head
```

3. Restart the backend after setting `FIREBASE_CREDENTIALS_FILE`.

## 5. Quick verification

1. Install the APK on an Android device.
2. Launch the app and log in through the normal web form.
3. Open `/web/settings?section=notifications` inside the app.
4. Confirm that the page shows Android/Firebase text instead of browser push buttons.
5. On the server, call `/api/mobile/devices/debug` for that user and confirm the device appears.
6. Call `/api/mobile/push/test` and confirm the push arrives.

## 6. Common failure points

- Wrong `SERVORA_BASE_URL`: login works inconsistently or device registration never appears.
- Wrong Firebase Android package: app builds, but push tokens do not match the project.
- Missing `google-services.json`: Gradle sync/build fails.
- Missing `FIREBASE_CREDENTIALS_FILE`: Android app opens, but server cannot send mobile push.
- Non-HTTPS production URL: microphone and some WebView/browser capabilities will be limited.

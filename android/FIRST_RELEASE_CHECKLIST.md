# First Release Checklist

## Before Build

- `FIREBASE_CREDENTIALS_FILE` is set on the backend.
- `alembic upgrade head` has been applied.
- `android/app/google-services.json` exists.
- `SERVORA_BASE_URL` points to the production HTTPS domain.
- `SERVORA_APP_ID` matches the Firebase Android app package.

## Smoke Test On Device

- App opens the login page.
- Login succeeds and lands on `/web`.
- Tickets list opens correctly.
- Notification settings page inside the app shows Android/Firebase text instead of browser push setup.
- Voice comment permission asks for microphone access.
- File upload chooser opens.

## Push Test

- Device appears in `/api/mobile/devices/debug`.
- `/api/mobile/push/test` returns `sent > 0`.
- Tap on notification opens the app.
- Tap on notification target lands on the intended `/web/...` page.

## Logout Test

- Logging out from `/web/logout` keeps the app usable.
- After logout, reopening the app shows the login page.
- After logging in again, device registration still appears once and does not duplicate endlessly.

## Release Notes

- Browser PWA push and Android APK push are separate channels.
- Android APK push depends on Firebase Cloud Messaging.
- The UI inside the APK is still the current web app, so backend deploys affect both web and APK immediately.

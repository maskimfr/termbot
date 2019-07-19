TermBot is an SSH client that supports authentication with YubiKeys, Nitrokeys and other OpenPGP cards over NFC and USB.

For this it uses the COTECH Hardware Security SDK available at https://hwsecurity.dev

TermBot is based on ConnectBot.

[<img src="https://f-droid.org/badge/get-it-on.png"
      alt="Get it on F-Droid"
      height="80">](https://f-droid.org/packages/org.sufficientlysecure.termbot/)
[<img src="https://play.google.com/intl/en_us/badges/images/generic/en-play-badge.png"
      alt="Get it on Google Play"
      height="80">](https://play.google.com/store/apps/details?id=org.sufficientlysecure.termbot)

## Supported Hardware

### NFC
- Cotech Card
- YubiKey NEO
- YubiKey 5 NFC

### USB
- Nitrokey Start, Pro, Storage (with adapter)
- YubiKey 4, 4 Nano, 5, 5 Nano (with adapter)
- YubiKey 4C, 4C Nano, 5C, 5C Nano (directly over USB-C)
- Gnuk (with adapter)
- Secalot (with adapter)

Full list of supported hardware can be found here: https://hwsecurity.dev/docs/supported-hardware/

## Build Release
```
git tag 1.9.5-termbot1
./gradlew --quiet androidGitVersion
./gradlew assembleGoogleRelease
```
afterwards, sign with keystore

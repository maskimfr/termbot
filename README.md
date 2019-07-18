SSH client that works with YubiKeys, Nitrokeys, and other OpenPGP smartcards.

[<img src="https://f-droid.org/badge/get-it-on.png"
      alt="Get it on F-Droid"
      height="80">](https://f-droid.org/packages/org.sufficientlysecure.termbot/)
[<img src="https://play.google.com/intl/en_us/badges/images/generic/en-play-badge.png"
      alt="Get it on Google Play"
      height="80">](https://play.google.com/store/apps/details?id=org.sufficientlysecure.termbot)

## Release new Version
```
git tag 1.9.5-termbot1
./gradlew --quiet androidGitVersion
./gradlew assembleGoogleRelease
```
afterwards, sign with keystore

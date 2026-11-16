# UKI CHAT (Testversion)

Anonymer Eins-zu-eins-Messenger für Android. Kontakt nur per gegenseitigem QR-Scan, Verbindung über das Tor-Netz, Ende-zu-Ende-verschlüsselt, nichts wird gespeichert.

## Installation auf Android

1. Unter **Actions → APK bauen** den neuesten erfolgreichen Lauf öffnen und unten `UKI-CHAT-test-apk` herunterladen (ZIP, darin die APK).
2. APK auf das Handy kopieren und öffnen. Android fragt, ob Installationen aus dieser Quelle erlaubt sind: einmal erlauben.
3. Für eine neue Testversion die alte vorher deinstallieren (jede Testversion hat einen eigenen Signaturschlüssel).

## Aufbau

| Teil | Datei | Aufgabe |
| --- | --- | --- |
| Oberfläche, Passwort, Verschlüsselung | `www/app.js` | WebCrypto: ECDH P-256 + Kanal-Passwort (PBKDF2) → HKDF → Schlüsselkette pro Richtung, neuer AES-256-GCM-Schlüssel pro Nachricht |
| Tor-Transport | `android/app/src/main/java/chat/uki/app/TorChatPlugin.java` | Startet Tor (`tor-android`), erzeugt eine flüchtige Onion-Adresse, verbindet über SOCKS |
| Hintergrund | `KeepAliveService.java` | Hält die Verbindung offen, Benachrichtigung ohne Inhalt |
| Bildschirmschutz | `MainActivity.java` | `FLAG_SECURE`: keine Bildschirmfotos |
| APK-Bau | `.github/workflows/build-apk.yml` | Baut bei jedem Push eine signierte Release-APK |

## Fremde Bausteine

- [tor-android](https://github.com/guardianproject/tor-android) (Guardian Project) und jtorctl
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0, Apache-2.0 (`www/vendor/jsQR.LICENSE`)
- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4, MIT
- [Capacitor](https://capacitorjs.com/) 7

## Bekannte Grenzen

- Keine unabhängige Sicherheitsprüfung bisher.
- Nur symmetrische Schlüsselkette (Forward Secrecy), noch kein Diffie-Hellman-Ratchet wie bei Signal.
- Beide müssen die App gleichzeitig offen haben; nach App-Neustart neu scannen.

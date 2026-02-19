# GOtv Remote Control

WiFi remote control app for GOtv Android TV Streamer.
Works on **any Android phone** - no IR blaster needed!

## Features

- Controls GOtv streamer over **WiFi** using Android TV Remote Protocol v2
- Same protocol used by the official Google TV app
- TLS encrypted connection (secure)
- Auto-reconnect to last paired device
- All standard buttons: Power, Volume, Channel, D-Pad, Numbers, Media controls
- Dark theme, haptic feedback
- Works on any Android 8.0+ phone (optimized for ASUS Zenfone 10)

## How to Use

1. Connect your phone and GOtv streamer to the **same WiFi network**
2. Open the app
3. Enter the **IP address** of your GOtv (find it in: GOtv Settings > Network > IP)
4. A **pairing code** will appear on your TV screen
5. Enter the code in the app
6. Done! The remote works automatically from now on

## Buttons

| Section | Buttons |
|---------|---------|
| Power | Power, Input, Mute |
| Numbers | 0-9, Last, Guide |
| D-Pad | Up, Down, Left, Right, OK |
| Volume | VOL+, VOL- |
| Channel | CH+, CH- |
| Functions | Menu, Home, Back, Info |
| Extra | EPG, FAV, SUB, Audio |
| Media | Play/Pause, Stop, Record, Rewind, Fast Forward |

## Download & Install

### From GitHub Actions
1. Go to **Actions** tab
2. Click the latest green build
3. Download **gotv-remote-debug** from Artifacts
4. Transfer APK to your phone
5. Install (enable "Install from unknown sources" in Settings)

### From Android Studio
1. Clone this repo
2. Open in Android Studio
3. Build > Build APK
4. Install on your phone

## Protocol

- **Android TV Remote Protocol v2** (same as Google TV app)
- Ports: **6466** (commands) / **6467** (pairing)
- Encryption: **TLS 1.2**
- No ADB or developer mode needed on the GOtv

## Troubleshooting

- **Can't connect**: Make sure both devices are on the same WiFi network
- **No pairing code on TV**: Try restarting the GOtv streamer, then reconnect
- **Connection drops**: Check WiFi stability. The app auto-reconnects on reopen
- **Wrong IP**: Long-press the settings icon to change the IP address
- **Reset pairing**: Go to Settings > "Forget Pairing & Reconnect"

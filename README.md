# GOtv Remote Control

Android IR remote control app for GOtv / StarTimes set-top box decoders.
Optimized for **ASUS Zenfone 10** (built-in IR blaster).

## Features

- Full GOtv decoder remote control via IR blaster
- All standard buttons: Power, Volume, Channel, D-Pad, Numbers, Media controls
- NEC protocol (38kHz) - compatible with GOtv/StarTimes decoders
- Dark theme optimized for ASUS Zenfone 10 (5.9" AMOLED, 1080x2400)
- Haptic feedback on button press
- No internet connection required (pure IR)

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

## Requirements

- Android phone with **IR blaster** (like ASUS Zenfone 10)
- Android 8.0+ (API 26)
- Point phone's IR emitter at GOtv decoder (within ~3m)

## Build

### From GitHub Actions
1. Go to **Actions** tab
2. Click latest build
3. Download **gotv-remote-debug** APK artifact
4. Install on your phone (enable "Install from unknown sources")

### From Android Studio
1. Clone this repo
2. Open in Android Studio
3. Build > Build Bundle(s) / APK(s) > Build APK(s)
4. Install the APK on your phone

## IR Protocol

- Protocol: **NEC**
- Carrier: **38kHz**
- Device Address: **0x04**
- Compatible with: GOtv, StarTimes, and similar decoders

## Troubleshooting

- **No IR Blaster detected**: Your phone doesn't have an IR emitter. This app requires a phone with built-in IR (ASUS Zenfone 10, Xiaomi, Huawei, etc.)
- **Buttons not working**: Point the top of your phone directly at the GOtv decoder. Keep within 3 meters. Remove any obstructions.
- **Wrong channels/functions**: The IR codes may need adjustment for your specific decoder model. Check Settings for protocol info.

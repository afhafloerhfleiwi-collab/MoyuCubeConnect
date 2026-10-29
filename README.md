# Moyu Cube

A web app like WCU Cube that connects to Moyu smart cubes (WeiLong V10 AI and compatible) via Web Bluetooth.

## Features
- Connect to Moyu smart cubes over Bluetooth Low Energy
- Live cube facelet state reading
- Battery level readout
- Gyro toggle
- Stackmat-style timer with solve history
- Statistics: best, average of 5, average of 12

## Protocol
This app implements the reverse-engineered Moyu V10 BLE protocol:

| Characteristic | UUID |
|---|---|
| Service | `0783b03e-7735-b5a0-1760-a305d2795cb0` |
| Notify | `...cb1` |
| Write | `...cb2` |

Packets are AES-CBC encrypted with a key/IV derived from a salt (the cube's MAC address or manufacturer-data bytes).

Message types: `0xA1` info, `0xA3` facelets, `0xA4` battery, `0xA5` move, `0xAB` gyro, `0xAC` gyro config.

## Usage
1. Open `index.html` in a browser that supports Web Bluetooth (Chrome, Edge, Opera on desktop/Android; Web Bluetooth must be enabled).
2. Click "Connect to Cube" and select your Moyu smart cube.
3. Wake the cube if it doesn't appear — BLE advertising may be intermittent.

## Files
- `index.html` — app markup
- `style.css` — styles
- `cube-protocol.js` — BLE protocol implementation (crypto, packet parsing)
- `app.js` — UI, timer, and connection logic

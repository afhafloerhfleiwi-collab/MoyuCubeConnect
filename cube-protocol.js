// Moyu Smart Cube BLE Protocol (WeiLong V10 AI / WCU compatible)
// Reverse-engineered from moyu_v10_rescue toolkit
//
// Service: 0783b03e-7735-b5a0-1760-a305d2795cb0
// Notify:  ...cb1
// Write:   ...cb2
// Packets are AES-CBC encrypted with a salt derived from the cube's MAC address.

const SERVICE_UUID = "0783b03e-7735-b5a0-1760-a305d2795cb0";
const NOTIFY_UUID  = "0783b03e-7735-b5a0-1760-a305d2795cb1";
const WRITE_UUID   = "0783b03e-7735-b5a0-1760-a305d2795cb2";

const ROOT_KEY  = new Uint8Array([0x15,0x77,0x3A,0x5C,0x67,0x0E,0x2D,0x1F,0x17,0x67,0x2A,0x13,0x9B,0x67,0x52,0x57]);
const ROOT_IV   = new Uint8Array([0x11,0x23,0x26,0x25,0x86,0x2A,0x2C,0x3B,0x55,0x06,0x7F,0x31,0x7E,0x67,0x21,0x57]);

const MSG_TYPE = {
  INFO:    0xA1,
  FACELETS:0xA3,
  BATTERY: 0xA4,
  MOVE:    0xA5,
  GYRO:    0xAB,
  GYRO_CFG:0xAC,
};

const MOVE_NAMES = ["F","F'","B","B'","U","U'","D","D'","L","L'","R","R'"];

const FACE_NAMES = ["F","B","U","D","L","R"];
const COLOR_GUESS = ["G","B","W","Y","O","R"];

function makePacket(type, payload = new Uint8Array(0)) {
  const pkt = new Uint8Array(20);
  pkt[0] = type;
  if (payload.length) pkt.set(payload, 1);
  return pkt;
}

function bitGroupsMsb(data, width, count) {
  const bits = [];
  for (const b of data) {
    for (let s = 7; s >= 0; s--) bits.push((b >> s) & 1);
  }
  const vals = [];
  for (let i = 0; i < count; i++) {
    let v = 0;
    for (let b = 0; b < width; b++) v = (v << 1) | bits[i * width + b];
    vals.push(v);
  }
  return vals;
}

function salted(root, salt) {
  const out = new Uint8Array(root);
  for (let i = 0; i < 6; i++) out[i] = (out[i] + salt[i]) % 0xFF;
  return out;
}

function xor(a, b) {
  const r = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i] ^ b[i];
  return r;
}

// Simple AES-CBC implementation using Web Crypto
class CubeCrypto {
  constructor(label, salt, key, iv) {
    this.label = label;
    this.salt = salt;
    this.key = key;
    this.iv = iv;
    this._aesKey = null;
  }

  async init() {
    this._aesKey = await crypto.subtle.importKey("raw", this.key, { name: "AES-CBC" }, false, ["encrypt","decrypt"]);
  }

  async crypt(data, encrypt) {
    const ivBuf = this.iv.buffer ? this.iv.buffer : this.iv;
    const alg = { name: "AES-CBC", iv: ivBuf };
    const op = encrypt ? "encrypt" : "decrypt";
    const result = await crypto.subtle[op](alg, this._aesKey, data);
    return new Uint8Array(result);
  }

  async encrypt(plain) {
    // Pad to 32 bytes (two AES blocks) per protocol: encrypt first 16, then last 16
    const buf = new Uint8Array(32);
    buf.set(plain);
    const first = await this.crypt(buf.slice(0,16), true);
    const second = await this.crypt(buf.slice(16,32), true);
    const out = new Uint8Array(32);
    out.set(first, 0);
    out.set(second, 16);
    return out;
  }

  async decrypt(data) {
    if (data.length < 16) return data;
    const len = data.length;
    const padded = new Uint8Array(Math.ceil(len / 16) * 16);
    padded.set(data);
    const blocks = padded.length / 16;
    const out = new Uint8Array(padded.length);
    // Decrypt each block independently (ECB-like per block as in protocol)
    for (let i = 0; i < blocks; i++) {
      const dec = await this.crypt(padded.slice(i*16, i*16+16), false);
      out.set(dec, i*16);
    }
    return out.slice(0, len);
  }

  static fromSalt(label, salt) {
    const key = salted(ROOT_KEY, salt);
    const iv  = salted(ROOT_IV, salt);
    return new CubeCrypto(label, salt, key, iv);
  }
}

function macToBytes(mac) {
  const h = mac.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  if (h.length !== 12) throw new Error("MAC must be 12 hex digits");
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(h.substr(i*2, 2), 16);
  return bytes;
}

function saltCandidates(mac, manufacturerData) {
  const candidates = [];
  const seen = new Set();

  const add = (label, six) => {
    if (six.length !== 6) return;
    const allZeros = six.every(b => b === 0);
    const allFF = six.every(b => b === 0xFF);
    if (allZeros || allFF) return;
    const variants = [
      { label: label + " (reversed)", salt: [...six].reverse() },
      { label: label + " (same)", salt: [...six] },
    ];
    for (const v of variants) {
      const key = v.salt.join(",");
      if (!seen.has(key)) {
        seen.add(key);
        candidates.push(CubeCrypto.fromSalt(v.label, new Uint8Array(v.salt)));
      }
    }
  };

  if (mac) add("manual MAC", macToBytes(mac));

  for (const [cid, blob] of Object.entries(manufacturerData || {})) {
    const b = new Uint8Array(blob);
    for (let i = 0; i <= b.length - 6; i++) {
      add(`mfg 0x${parseInt(cid).toString(16)} bytes ${i}-${i+5}`, b.slice(i, i+6));
    }
  }
  return candidates;
}

function parseInfo(dec) {
  return {
    model: String.fromCharCode(...dec.slice(1,9)).replace(/\0/g, ""),
    hw: dec.length > 10 ? `${dec[9]}.${dec[10]}` : "unknown",
    sw: dec.length > 12 ? `${dec[11]}.${dec[12]}` : "unknown",
  };
}

function parseFacelets(dec) {
  const vals = bitGroupsMsb(dec.slice(1,19), 3, 48);
  const faces = {};
  for (let i = 0; i < 6; i++) {
    const rawVals = vals.slice(i*8, i*8+8);
    const guessed = rawVals.map(v => COLOR_GUESS[v] || `?${v}`).join("");
    faces[FACE_NAMES[i]] = { raw: rawVals, guessed };
  }
  return { faces, serial: dec[19] };
}

function parseMove(dec) {
  const timesBE = [];
  const timesLE = [];
  for (let i = 0; i < 5; i++) {
    timesBE.push((dec[1 + 2*i] << 8) | dec[2 + 2*i]);
    timesLE.push(dec[1 + 2*i] | (dec[2 + 2*i] << 8));
  }
  const serial = dec[11];
  const codes = bitGroupsMsb(dec.slice(12,17), 5, 5);
  const moves = codes.map(c => MOVE_NAMES[c] || `?${c}`);
  return { serial, codes, moves, timesBE, timesLE };
}

export {
  SERVICE_UUID, NOTIFY_UUID, WRITE_UUID,
  MSG_TYPE, CubeCrypto, makePacket, saltCandidates,
  parseInfo, parseFacelets, parseMove,
};

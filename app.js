import {
  SERVICE_UUID, NOTIFY_UUID, WRITE_UUID,
  MSG_TYPE, CubeCrypto, makePacket, saltCandidates,
  parseInfo, parseFacelets, parseMove,
} from "./cube-protocol.js";

// ---- DOM refs ----
const connectBtn = document.getElementById("connectBtn");
const refreshBtn = document.getElementById("refreshBtn");
const statusEl = document.getElementById("status");
const deviceInfo = document.getElementById("deviceInfo");
const devName = document.getElementById("devName");
const devAddr = document.getElementById("devAddr");
const devModel = document.getElementById("devModel");
const devBattery = document.getElementById("devBattery");

const cubePanel = document.getElementById("cubePanel");
const timerPanel = document.getElementById("timerPanel");
const statsPanel = document.getElementById("statsPanel");
const historyPanel = document.getElementById("historyPanel");
const faceletState = document.getElementById("faceletState");

const readFaceletsBtn = document.getElementById("readFaceletsBtn");
const batteryBtn = document.getElementById("batteryBtn");
const gyroBtn = document.getElementById("gyroBtn");

const startStopBtn = document.getElementById("startStopBtn");
const resetBtn = document.getElementById("resetBtn");
const timerDisplay = document.getElementById("timerDisplay");
const lastSolve = document.getElementById("lastSolve");
const currentMove = document.getElementById("currentMove");
const statAvg5 = document.getElementById("statAvg5");
const statAvg12 = document.getElementById("statAvg12");
const statBest = document.getElementById("statBest");
const statCount = document.getElementById("statCount");
const solveList = document.getElementById("solveList");

// ---- State ----
let client = null;
let crypto = null;
let notifyStarted = false;
let notifyQueue = [];
let gyroEnabled = false;
let gyroWatchTimer = null;

let timerRunning = false;
let timerStart = 0;
let timerElapsed = 0;
let timerRaf = null;

const solves = []; // { time, date }

// ---- BLE connect ----
async function connect() {
  statusEl.textContent = "Requesting device...";
  connectBtn.disabled = true;

  try {
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE_UUID] }],
      optionalServices: [SERVICE_UUID],
    });

    statusEl.textContent = "Connecting...";
    client = await navigator.bluetooth.getDevice().gatt.connect();
    // Re-fetch device to access manufacturer data for salt
    const dev = device;

    const service = await client.getPrimaryService(SERVICE_UUID);
    const notifyChar = await service.getCharacteristic(NOTIFY_UUID);
    const writeChar = await service.getCharacteristic(WRITE_UUID);

    // Build salt candidates from manufacturer data
    const mfg = {};
    if (dev.uuids) { /* handled below */ }
    // manufacturerData not directly on requestDevice result; read via advertising
    // We'll attempt crypto init with MAC-derived candidates too
    const mac = dev.id; // BLE address on some platforms

    statusEl.textContent = "Initializing protocol crypto...";

    // Try notify to receive data, then attempt A1 handshake with candidate salts
    await client.startNotify(NOTIFY_UUID, onNotify);
    notifyStarted = true;

    crypto = await tryInitCrypto(dev);
    if (!crypto) {
      throw new Error("Could not initialize cube encryption. Try waking the cube and reconnecting.");
    }

    // Update UI
    devName.textContent = dev.name || "Moyu Cube";
    devAddr.textContent = dev.id;
    devModel.textContent = "Moyu Smart Cube";
    deviceInfo.classList.remove("hidden");

    // Read battery
    await readBattery();

    // Show panels
    cubePanel.classList.remove("hidden");
    timerPanel.classList.remove("hidden");
    statsPanel.classList.remove("hidden");
    historyPanel.classList.remove("hidden");

    statusEl.textContent = "Connected.";
    connectBtn.textContent = "Reconnect";
    connectBtn.disabled = false;
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Error: " + err.message;
    connectBtn.disabled = false;
  }
}

function onNotify(event) {
  const data = new Uint8Array(event.target.value.buffer);
  if (!crypto) { notifyQueue.push(data); return; }
  handleNotify(data);
}

async function tryInitCrypto(device) {
  const candidates = saltCandidates(null, null); // no mfg data available via requestDevice on all platforms
  // Add MAC-based candidates
  if (device && device.id) {
    try {
      const mac = macToBytes(device.id);
      for (const c of saltCandidates(mac, null)) candidates.push(c);
    } catch (e) { /* ignore bad MAC */ }
  }

  // Try each candidate with A1 handshake
  const writeChar = await getWriteChar();
  if (!writeChar) return null;

  for (const c of candidates) {
    try {
      await c.init();
      const plain = makePacket(MSG_TYPE.INFO);
      const enc = await c.encrypt(plain);
      await writeChar.writeValue(enc);

      // Wait for A1 response
      const resp = await waitForType([MSG_TYPE.INFO], 2000);
      if (resp) {
        const dec = await c.decrypt(resp);
        const info = parseInfo(dec);
        console.log("Cube info:", info);
        devModel.textContent = info.model || "Moyu Smart Cube";
        return c;
      }
    } catch (e) {
      console.log("Crypto candidate failed:", c.label, e.message);
    }
  }
  return null;
}

function getWriteChar() {
  if (!client) return null;
  return client.getPrimaryService(SERVICE_UUID).then(s => s.getCharacteristic(WRITE_UUID));
}

async function writePacket(type, payload = new Uint8Array(0)) {
  if (!client || !crypto) throw new Error("Not connected");
  const writeChar = await getWriteChar();
  const plain = makePacket(type, payload);
  const enc = await crypto.encrypt(plain);
  try { await writeChar.writeValue(enc); } catch {
    await writeChar.writeValue(enc); // retry with response
  }
}

async function waitForType(types, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const start = Date.now();
    const check = () => {
      if (done) return;
      if (notifyQueue.length) {
        const data = notifyQueue.shift();
        const dec = crypto.decrypt(data);
        const typ = dec[0];
        if (types.includes(typ)) { done = true; resolve(dec); return; }
      }
      if (Date.now() - start > timeoutMs) { done = true; resolve(null); return; }
      setTimeout(check, 50);
    };
    check();
  });
}

async function handleNotify(raw) {
  try {
    const dec = await crypto.decrypt(raw);
    const typ = dec[0];
    if (typ === MSG_TYPE.MOVE) {
      const move = parseMove(dec);
      currentMove.textContent = move.moves.join(" ");
      console.log("Move:", move);
    } else if (typ === MSG_TYPE.GYRO) {
      // gyro data - could be used for orientation
    }
  } catch (e) {
    console.log("Notify decrypt failed:", e.message);
  }
}

async function readBattery() {
  try {
    await writePacket(MSG_TYPE.BATTERY);
    const resp = await waitForType([MSG_TYPE.BATTERY], 2000);
    if (resp) devBattery.textContent = resp[1];
  } catch (e) { console.log("Battery read failed:", e.message); }
}

async function readFacelets() {
  try {
    await writePacket(MSG_TYPE.FACELETS);
    const resp = await waitForType([MSG_TYPE.FACELETS], 2000);
    if (resp) {
      const { faces } = parseFacelets(resp);
      renderFacelets(faces);
      faceletState.classList.remove("hidden");
    }
  } catch (e) { console.log("Facelet read failed:", e.message); }
}

function renderFacelets(faces) {
  const container = document.getElementById("cubeVisualization");
  container.innerHTML = "";
  // Show a flattened net: U on top, F-B-L-R in middle row, D on bottom
  const order = ["U", "L", "F", "R", "B", "D"];
  // Build a simple net layout using CSS grid positions
  container.style.gridTemplateColumns = "repeat(4, 1fr)";
  container.style.gridTemplateRows = "repeat(3, 1fr)";

  // positions: (col, row) for each face in a 4x3 grid
  const pos = { U: [1,0], L: [0,1], F: [1,1], R: [2,1], B: [3,1], D: [1,2] };

  for (const face of order) {
    const faceData = faces[face];
    for (let i = 0; i < 8; i++) {
      const cell = document.createElement("div");
      cell.className = "facelet";
      cell.textContent = faceData.guessed[i] || "?";
      const c = pos[face];
      cell.style.gridColumn = c[0] + 1;
      cell.style.gridRow = c[1] + 1;
      // offset cells within face region - simpler: just append all
      container.appendChild(cell);
    }
  }
}

// ---- Gyro ----
gyroBtn.addEventListener("click", async () => {
  gyroEnabled = !gyroEnabled;
  gyroBtn.textContent = `Gyro: ${gyroEnabled ? "On" : "Off"}`;
  gyroBtn.classList.toggle("active", gyroEnabled);
  try {
    const payload = new Uint8Array([0x00, gyroEnabled ? 0x01 : 0x00]);
    await writePacket(MSG_TYPE.GYRO_CFG, payload);
  } catch (e) { console.log("Gyro config failed:", e.message); }
});

readFaceletsBtn.addEventListener("click", readFacelets);
batteryBtn.addEventListener("click", readBattery);

// ---- Timer ----
function formatTime(ms) {
  const s = Math.floor(ms / 1000);
  const cs = Math.floor((ms % 1000) / 10);
  return `${s}.${cs.toString().padStart(2, "0")}`;
}

function updateTimer() {
  if (!timerRunning) return;
  const now = Date.now() - timerStart + timerElapsed;
  timerDisplay.textContent = (now / 1000).toFixed(3);
  timerRaf = requestAnimationFrame(updateTimer);
}

startStopBtn.addEventListener("click", () => {
  if (!timerRunning) {
    timerStart = Date.now();
    timerRunning = true;
    startStopBtn.textContent = "Stop";
    updateTimer();
  } else {
    timerRunning = false;
    cancelAnimationFrame(timerRaf);
    timerElapsed += Date.now() - timerStart;
    const total = timerElapsed;
    timerDisplay.textContent = (total / 1000).toFixed(3);
    startStopBtn.textContent = "Start";
    recordSolve(total);
    timerElapsed = 0;
  }
});

resetBtn.addEventListener("click", () => {
  timerRunning = false;
  cancelAnimationFrame(timerRaf);
  timerElapsed = 0;
  timerDisplay.textContent = "0.000";
  startStopBtn.textContent = "Start";
  currentMove.textContent = "--";
});

function recordSolve(ms) {
  const entry = { time: ms, date: new Date() };
  solves.unshift(entry);
  updateStats();
  renderHistory();
  lastSolve.textContent = `Last solve: ${(ms/1000).toFixed(3)}s`;
}

function updateStats() {
  const times = solves.map(s => s.time);
  statCount.textContent = times.length;
  if (times.length === 0) {
    statAvg5.textContent = "--";
    statAvg12.textContent = "--";
    statBest.textContent = "--";
    return;
  }
  const best = Math.min(...times);
  statBest.textContent = (best / 1000).toFixed(3) + "s";

  const avgN = (n) => {
    const t = times.slice(0, n);
    if (t.length === 0) return "--";
    const sum = t.reduce((a,b) => a+b, 0);
    return (sum / t.length / 1000).toFixed(3) + "s";
  };
  statAvg5.textContent = avgN(5);
  statAvg12.textContent = avgN(12);
}

function renderHistory() {
  solveList.innerHTML = "";
  for (const s of solves) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="solve-time">${(s.time/1000).toFixed(3)}s</span><span class="solve-date">${s.date.toLocaleTimeString()}</span>`;
    solveList.appendChild(li);
  }
}

// ---- Connect ----
connectBtn.addEventListener("click", connect);
refreshBtn.addEventListener("click", () => {
  readBattery();
  readFacelets();
});

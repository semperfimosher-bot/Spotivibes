require("dotenv").config();

const fs = require("fs");
const path = require("path");
const chokidar = require("chokidar");
const axios = require("axios");
const FormData = require("form-data");

const WATCH_FOLDER = process.env.WATCH_FOLDER;
const TOKEN = process.env.FOLDER_UPLOAD_TOKEN;
const API_BASE = process.env.WATCH_API_BASE || "http://localhost:3000/api";

const MAX_CONCURRENT_UPLOADS =
  Number(process.env.WATCH_UPLOAD_CONCURRENCY) || 1;

const UPLOAD_DELAY_MS =
  Number(process.env.WATCH_UPLOAD_DELAY_MS) || 3000;

const STATE_FILE = path.join(__dirname, "uploaded-files.json");

const uploadQueue = [];
let activeUploads = 0;

if (!WATCH_FOLDER) {
  console.error("WATCH_FOLDER missing in .env");
  process.exit(1);
}

if (!TOKEN) {
  console.error("FOLDER_UPLOAD_TOKEN missing in .env");
  process.exit(1);
}

const uploaded = fs.existsSync(STATE_FILE)
  ? new Set(JSON.parse(fs.readFileSync(STATE_FILE, "utf8")))
  : new Set();

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function saveState() {
  fs.writeFileSync(
    STATE_FILE,
    JSON.stringify([...uploaded], null, 2)
  );
}

function isAudio(filePath) {
  return [".mp3", ".flac", ".wav", ".m4a", ".aac", ".ogg"]
    .includes(path.extname(filePath).toLowerCase());
}

function getFingerprint(filePath) {
  const stat = fs.statSync(filePath);
  return `${filePath}:${stat.size}:${stat.mtimeMs}`;
}

function enqueueUpload(filePath) {
  if (!isAudio(filePath)) return;

  uploadQueue.push(filePath);
  processQueue();
}

function processQueue() {
  while (
    activeUploads < MAX_CONCURRENT_UPLOADS &&
    uploadQueue.length
  ) {
    const filePath = uploadQueue.shift();
    activeUploads++;

    uploadFileWithRetry(filePath)
      .finally(async () => {
        activeUploads--;
        await sleep(UPLOAD_DELAY_MS);
        processQueue();
      });
  }
}

async function markStart(filename) {
  await axios.post(
    `${API_BASE}/internal/upload-start`,
    { filename },
    {
      headers: {
        "x-upload-token": TOKEN
      },
      timeout: 30000
    }
  );
}

async function markComplete(filename) {
  await axios.post(
    `${API_BASE}/internal/upload-complete`,
    { filename },
    {
      headers: {
        "x-upload-token": TOKEN
      },
      timeout: 30000
    }
  );
}

async function markFailed(filename, error) {
  await axios.post(
    `${API_BASE}/internal/upload-failed`,
    { filename, error },
    {
      headers: {
        "x-upload-token": TOKEN
      },
      timeout: 30000
    }
  ).catch(() => {});
}

async function uploadFileWithRetry(filePath) {
  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await uploadFile(filePath);
      return;
    } catch (err) {
      const filename = path.basename(filePath);

      console.warn(
      `Retrying ${filename} (${attempt}/${maxAttempts})...`,
       err.message
      );

      if (attempt === maxAttempts) {
        await markFailed(
          filename,
          JSON.stringify(err.response?.data || err.message)
        );

        return;
      }

      const isConnectionReset =
       String(err.message || "").includes("ECONNRESET") ||
       String(err.response?.data || "").includes("ECONNRESET");

      await sleep(isConnectionReset ? 30000 : 5000);
    }
  }
}

async function uploadFile(filePath) {
  const filename = path.basename(filePath);
  const fingerprint = getFingerprint(filePath);

  if (uploaded.has(fingerprint)) return;

  console.log("Uploading:", filename);

  await markStart(filename);

  const form = new FormData();
  form.append("songs", fs.createReadStream(filePath), filename);

  const result = await axios.post(
    `${API_BASE}/upload-files`,
    form,
    {
      headers: {
        ...form.getHeaders(),
        "x-upload-token": TOKEN
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 10 * 60 * 1000,
      validateStatus: () => true
    }
  );

  if (result.status >= 400) {
    throw new Error(
      JSON.stringify(result.data || { status: result.status })
    );
  }

  const failed = result.data?.results?.find(r => r.success === false);

  if (failed) {
    throw new Error(failed.error || "Upload route reported failure");
  }

  uploaded.add(fingerprint);
  saveState();

  await markComplete(filename);

  console.log("Complete:", filename);
}

console.log("Watching folder:");
console.log(WATCH_FOLDER);

chokidar.watch(WATCH_FOLDER, {
  ignoreInitial: false,
  awaitWriteFinish: {
    stabilityThreshold: 6000,
    pollInterval: 1000
  }
})
.on("add", filePath => {
  enqueueUpload(filePath);
});
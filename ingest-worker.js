require("dotenv").config();

const fs = require("fs");
const path = require("path");
const axios = require("axios");

const {
  b2,
  B2_INGEST_BUCKET_NAME,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand
} = require("./services/storage.service");

const API_BASE =
  process.env.WATCH_API_BASE ||
  "https://api.spotivibes.com/api";

const TOKEN =
  process.env.FOLDER_UPLOAD_TOKEN;

const TEMP_DIR = path.join(__dirname, "temp-ingest");

if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR);
}

async function streamToFile(stream, filePath) {
  return new Promise((resolve, reject) => {

    const write = fs.createWriteStream(filePath);

    stream.pipe(write);

    stream.on("error", reject);

    write.on("finish", resolve);
    write.on("error", reject);

  });
}

async function uploadToAPI(filePath) {

  const FormData = require("form-data");

  const form = new FormData();

  form.append(
    "songs",
    fs.createReadStream(filePath)
  );

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
      timeout: 10 * 60 * 1000
    }
  );

  return result.data;
}

async function permanentlyDeleteIngestKey(objectKey) {
  let KeyMarker;
  let VersionIdMarker;

  do {
    const listed = await b2.send(
      new ListObjectVersionsCommand({
        Bucket: B2_INGEST_BUCKET_NAME,
        Prefix: objectKey,
        KeyMarker,
        VersionIdMarker
      })
    );

    const objectsToDelete = [
      ...(listed.Versions || [])
        .filter(v => v.Key === objectKey)
        .map(v => ({
          Key: v.Key,
          VersionId: v.VersionId
        })),

      ...(listed.DeleteMarkers || [])
        .filter(m => m.Key === objectKey)
        .map(m => ({
          Key: m.Key,
          VersionId: m.VersionId
        }))
    ];

    if (objectsToDelete.length) {
      await b2.send(
        new DeleteObjectsCommand({
          Bucket: B2_INGEST_BUCKET_NAME,
          Delete: {
            Objects: objectsToDelete,
            Quiet: true
          }
        })
      );
    }

    KeyMarker = listed.NextKeyMarker;
    VersionIdMarker = listed.NextVersionIdMarker;

  } while (KeyMarker);
}

async function processFile(objectKey) {
  const filename = path.basename(objectKey);
  const localPath = path.join(TEMP_DIR, filename);

  console.log("Processing:", filename);

  try {
    await axios.post(
      `${API_BASE}/internal/upload-start`,
      { filename },
      { headers: { "x-upload-token": TOKEN } }
    );

    const object = await b2.send(
      new GetObjectCommand({
        Bucket: B2_INGEST_BUCKET_NAME,
        Key: objectKey
      })
    );

    await streamToFile(object.Body, localPath);

    const result = await uploadToAPI(localPath);

    const failed = result?.results?.find(r => r.success === false);

    if (failed) {
      throw new Error(failed.error || "Upload failed");
    }

    await permanentlyDeleteIngestKey(objectKey);

    await axios.post(
      `${API_BASE}/internal/upload-complete`,
      { filename },
      { headers: { "x-upload-token": TOKEN } }
    );

    console.log("Imported:", filename);

  } catch (err) {
    console.error(
      "FAILED:",
      filename,
      err.response?.data || err.message
    );

    await axios.post(
      `${API_BASE}/internal/upload-failed`,
      {
        filename,
        error: err.response?.data?.error || err.message
      },
      { headers: { "x-upload-token": TOKEN } }
    ).catch(() => {});

  } finally {
    if (fs.existsSync(localPath)) {
      fs.unlinkSync(localPath);
    }
  }
}

let isScanning = false;
const MIN_FILE_AGE_MS = 2 * 60 * 1000;

async function scanBucket() {
  if (isScanning) {
    return;
  }

  isScanning = true;

  try {
    const listed = await b2.send(
      new ListObjectsV2Command({
        Bucket: B2_INGEST_BUCKET_NAME,
        MaxKeys: 20
      })
    );

    const files = listed.Contents || [];
    const now = Date.now();

    for (const file of files) {
      if (
        !file.Key.toLowerCase().match(
          /\.(mp3|flac|wav|m4a|aac|ogg)$/
        )
      ) {
        continue;
      }

      const ageMs =
        now - new Date(file.LastModified).getTime();

      if (ageMs < MIN_FILE_AGE_MS) {
        console.log("Skipping still-uploading file:", file.Key);
        continue;
      }

      await processFile(file.Key);
    }

  } catch (err) {
    console.error("SCAN FAILED:", err.message);
  } finally {
    isScanning = false;
  }
}

console.log("B2 ingest worker running...");

scanBucket();

setInterval(
  scanBucket,
  20 * 1000
);
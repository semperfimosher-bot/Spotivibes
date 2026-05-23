require("dotenv").config();

const fs = require("fs");
const path = require("path");
const axios = require("axios");

const {
  b2,
  B2_INGEST_BUCKET_NAME,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand
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

    await b2.send(
      new DeleteObjectCommand({
        Bucket: B2_INGEST_BUCKET_NAME,
        Key: objectKey
      })
    );

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

async function scanBucket() {

  try {

    const listed = await b2.send(
      new ListObjectsV2Command({
        Bucket: B2_INGEST_BUCKET_NAME,
        MaxKeys: 10
      })
    );

    const files =
      listed.Contents || [];

    for (const file of files) {

      if (
        !file.Key.toLowerCase().match(
          /\.(mp3|flac|wav|m4a|aac|ogg)$/
        )
      ) {
        continue;
      }

      await processFile(file.Key);

    }

  } catch (err) {

    console.error(
      "SCAN FAILED:",
      err.message
    );

  }
}

console.log("B2 ingest worker running...");

scanBucket();

setInterval(
  scanBucket,
  60 * 1000
);
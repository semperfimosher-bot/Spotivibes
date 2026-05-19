require("dotenv").config();

const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectVersionsCommand
} = require("@aws-sdk/client-s3");

const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

function cleanEnv(value) {
  return value?.trim().replace(/^["']|["']$/g, "");
}

const B2_ENDPOINT = cleanEnv(process.env.B2_ENDPOINT);
const B2_KEY_ID = cleanEnv(process.env.B2_KEY_ID);
const B2_APP_KEY = cleanEnv(process.env.B2_APP_KEY);
const B2_BUCKET_NAME = cleanEnv(process.env.B2_BUCKET_NAME);
const B2_REGION = cleanEnv(process.env.B2_REGION);

console.log("B2 ENV CHECK:", {
  endpoint: B2_ENDPOINT,
  region: B2_REGION,
  keyIdLength: B2_KEY_ID?.length,
  appKeyLength: B2_APP_KEY?.length,
  bucket: B2_BUCKET_NAME
});

const b2 = new S3Client({
  region: B2_REGION,
  endpoint: B2_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: B2_KEY_ID,
    secretAccessKey: B2_APP_KEY
  },
});

async function getFileUrl(fileKey) {
  if (!fileKey) return null;

  const command = new GetObjectCommand({
    Bucket: B2_BUCKET_NAME,
    Key: fileKey,
  });

  return await getSignedUrl(b2, command, {
    expiresIn: 60 * 60,
  });
}

module.exports = {
  b2,
  getFileUrl,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectVersionsCommand
};
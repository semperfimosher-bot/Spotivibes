require("dotenv").config();

const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command,
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
const B2_AUDIO_BUCKET_NAME = cleanEnv(
  process.env.B2_AUDIO_BUCKET_NAME || process.env.B2_BUCKET_NAME
);

const B2_COVER_BUCKET_NAME = cleanEnv(
  process.env.B2_COVER_BUCKET_NAME || process.env.B2_BUCKET_NAME
);
const B2_REGION = cleanEnv(process.env.B2_REGION);

const b2 = new S3Client({
  region: B2_REGION,
  endpoint: B2_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: B2_KEY_ID,
    secretAccessKey: B2_APP_KEY
  },
});

async function getFileUrl(fileKey, bucketName = B2_AUDIO_BUCKET_NAME) {
  if (!fileKey) return null;

  const command = new GetObjectCommand({
    Bucket: bucketName,
    Key: fileKey,
  });

  return await getSignedUrl(b2, command, {
    expiresIn: 60 * 60,
  });
}

function getPublicCoverUrl(fileKey) {
  if (!fileKey) return null;

  if (fileKey.startsWith("http")) {
    return fileKey;
  }

  if (!process.env.B2_COVER_PUBLIC_URL) {
    return null;
  }

  return `${process.env.B2_COVER_PUBLIC_URL}/${encodeURIComponent(fileKey).replace(/%2F/g, "/")}`;
}

module.exports = {
  b2,
  getFileUrl,
  getPublicCoverUrl,
  B2_AUDIO_BUCKET_NAME,
  B2_COVER_BUCKET_NAME,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand
};
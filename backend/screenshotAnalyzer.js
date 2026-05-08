const path = require("path");
const Tesseract = require("tesseract.js");

const ALLOWED_IMAGE_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const ALLOWED_IMAGE_EXTENSIONS = new Set([".jpg", ".jpeg", ".png", ".webp"]);
const INVALID_IMAGE_ERROR = "Only JPG, PNG, and WEBP screenshots are allowed.";
const NO_TEXT_ERROR =
  "No readable text was found in the screenshot. Try a clearer image or paste the message manually.";

function getFileExtension(fileName = "") {
  return path.extname(String(fileName)).toLowerCase();
}

function hasAllowedImageSignature(buffer, mimetype) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return false;
  }

  if (mimetype === "image/jpeg") {
    return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }

  if (mimetype === "image/png") {
    return buffer
      .subarray(0, 8)
      .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  }

  if (mimetype === "image/webp") {
    return (
      buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
      buffer.subarray(8, 12).toString("ascii") === "WEBP"
    );
  }

  return false;
}

function validateImageFile(file) {
  if (!file) {
    return { valid: false, error: "Screenshot image is required." };
  }

  const extension = getFileExtension(file.originalname);
  if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype) || !ALLOWED_IMAGE_EXTENSIONS.has(extension)) {
    return { valid: false, error: INVALID_IMAGE_ERROR };
  }

  if (!hasAllowedImageSignature(file.buffer, file.mimetype)) {
    return { valid: false, error: INVALID_IMAGE_ERROR };
  }

  return { valid: true };
}

function cleanOcrText(text = "") {
  return String(text)
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+/g, " ").trim())
    .filter(Boolean)
    .join("\n")
    .trim();
}

async function extractTextFromImage(buffer) {
  const ocrResult = await Tesseract.recognize(buffer, "eng");
  const extractedText = cleanOcrText(ocrResult?.data?.text || "");
  const ocrConfidence = Math.round(Number(ocrResult?.data?.confidence || 0));

  if (!extractedText) {
    const error = new Error(NO_TEXT_ERROR);
    error.statusCode = 422;
    throw error;
  }

  return { extractedText, ocrConfidence };
}

function parseBooleanField(value) {
  if (typeof value === "boolean") {
    return value;
  }
  return String(value || "").toLowerCase() === "true";
}

module.exports = {
  ALLOWED_IMAGE_MIME_TYPES,
  ALLOWED_IMAGE_EXTENSIONS,
  INVALID_IMAGE_ERROR,
  NO_TEXT_ERROR,
  validateImageFile,
  extractTextFromImage,
  cleanOcrText,
  parseBooleanField
};

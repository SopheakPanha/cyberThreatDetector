const express = require("express");
const multer = require("multer");
const path = require("path");
const { analyzeRisk } = require("./riskAnalyzer");
const {
  ALLOWED_IMAGE_EXTENSIONS,
  ALLOWED_IMAGE_MIME_TYPES,
  INVALID_IMAGE_ERROR,
  validateImageFile,
  extractTextFromImage,
  parseBooleanField
} = require("./screenshotAnalyzer");

const app = express();
const PORT = process.env.PORT || 5000;
const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SCREENSHOT_BYTES, files: 1 },
  fileFilter: (req, file, cb) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype) || !ALLOWED_IMAGE_EXTENSIONS.has(extension)) {
      return cb(new Error(INVALID_IMAGE_ERROR));
    }
    return cb(null, true);
  }
});

app.use(express.json({ limit: "200kb" }));

app.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  const configuredOrigin = process.env.CLIENT_ORIGIN;
  const localDevOrigin =
    requestOrigin && /^https?:\/\/(127\.0\.0\.1|localhost):\d+$/.test(requestOrigin);

  res.setHeader("Access-Control-Allow-Origin", configuredOrigin || (localDevOrigin ? requestOrigin : "http://127.0.0.1:5173"));
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  return next();
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "cyber-risk-checker" });
});

app.post("/api/analyze-risk", (req, res) => {
  try {
    const result = analyzeRisk(req.body || {});
    res.json(result);
  } catch (error) {
    res.status(500).json({
      error: "Risk analysis failed.",
      message: "Please try again with plain text and file metadata only."
    });
  }
});

app.post("/api/analyze-screenshot", (req, res) => {
  upload.single("screenshot")(req, res, async (uploadError) => {
    if (uploadError) {
      const message =
        uploadError instanceof multer.MulterError && uploadError.code === "LIMIT_FILE_SIZE"
          ? "Image is too large. Maximum allowed size is 5MB."
          : INVALID_IMAGE_ERROR;
      return res.status(400).json({ error: message });
    }

    const validation = validateImageFile(req.file);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    try {
      const { extractedText, ocrConfidence } = await extractTextFromImage(req.file.buffer);
      const result = analyzeRisk({
        message: extractedText,
        senderEmail: req.body.senderEmail || "",
        source: req.body.source || "",
        userActions: {
          clickedLink: parseBooleanField(req.body.clickedLink),
          enteredPassword: parseBooleanField(req.body.enteredPassword),
          sharedCode: parseBooleanField(req.body.sharedCode),
          sentMoney: parseBooleanField(req.body.sentMoney),
          installedSoftware: parseBooleanField(req.body.installedSoftware),
          gaveRemoteAccess: parseBooleanField(req.body.gaveRemoteAccess)
        }
      });

      return res.json({ extractedText, ocrConfidence, ...result });
    } catch (error) {
      return res.status(error.statusCode || 500).json({
        error: error.statusCode
          ? error.message
          : "Screenshot analysis failed. Please try again with a clearer image."
      });
    }
  });
});

app.listen(PORT, () => {
  console.log(`Risk checker API running on http://127.0.0.1:${PORT}`);
});

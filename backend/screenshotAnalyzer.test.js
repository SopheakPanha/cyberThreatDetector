const assert = require("assert");
const {
  cleanOcrText,
  parseBooleanField,
  validateImageFile,
  INVALID_IMAGE_ERROR
} = require("./screenshotAnalyzer");

const pngBuffer = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x00
]);

assert.strictEqual(
  cleanOcrText("  URGENT:   verify now\r\n\r\n https://paypal.test  "),
  "URGENT: verify now\nhttps://paypal.test"
);
assert.strictEqual(parseBooleanField("true"), true);
assert.strictEqual(parseBooleanField("false"), false);
assert.strictEqual(parseBooleanField(true), true);

assert.deepStrictEqual(
  validateImageFile({
    originalname: "screenshot.png",
    mimetype: "image/png",
    buffer: pngBuffer
  }),
  { valid: true }
);

assert.deepStrictEqual(
  validateImageFile({
    originalname: "invoice.pdf",
    mimetype: "application/pdf",
    buffer: pngBuffer
  }),
  { valid: false, error: INVALID_IMAGE_ERROR }
);

console.log("All screenshot analyzer helper tests passed.");

/*
Manual screenshot upload tests:
1. Screenshot text: "URGENT: Your PayPal account is suspended. Click https://paypal-verify-account.com and verify your password now." Expected: High or Critical.
2. Screenshot text: "Hi, here are the meeting notes from today." Expected: Low.
3. Upload .exe selected or renamed badly. Expected: rejected by backend.
4. Upload .pdf. Expected: rejected by backend.
5. Upload image over 5MB. Expected: size error.
6. Upload blurry/no-text image. Expected: helpful no-readable-text error.
7. Upload screenshot and check "I entered my password." Expected: Critical with emergency account actions.
*/

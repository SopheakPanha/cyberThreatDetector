const assert = require("assert");
const { analyzeRisk } = require("./riskAnalyzer");

const cases = [
  {
    name: "PayPal impersonation phishing",
    input: {
      message:
        "URGENT: Your PayPal account is suspended. Click https://paypal-verify-account.com and verify your password now."
    },
    expectedLevels: ["High Risk", "Critical Risk"]
  },
  {
    name: "Normal meeting notes",
    input: {
      message: "Hi, here are the meeting notes from today."
    },
    expectedLevels: ["Low Risk"]
  },
  {
    name: "Double extension executable",
    input: {
      message: "",
      file: { fileName: "invoice.pdf.exe", fileSizeBytes: 245760 }
    },
    expectedLevels: ["High Risk", "Critical Risk"]
  },
  {
    name: "Opened suspicious file",
    input: {
      file: {
        fileName: "invoice.pdf.exe",
        fileSizeBytes: 245760,
        userAlreadyOpened: true
      }
    },
    expectedLevels: ["Critical Risk"]
  },
  {
    name: "Fake job asks for bank info",
    input: {
      message:
        "Easy work from home job, $300/day, no interview required. Send your bank info."
    },
    expectedLevels: ["High Risk"]
  }
];

for (const testCase of cases) {
  const result = analyzeRisk(testCase.input);
  assert(
    testCase.expectedLevels.includes(result.riskLevel),
    `${testCase.name}: expected ${testCase.expectedLevels.join(" or ")}, got ${result.riskLevel}`
  );
  assert.strictEqual(typeof result.score, "number");
  assert(Array.isArray(result.redFlags));
  assert(Array.isArray(result.safeActions));
  assert(Array.isArray(result.extractedLinks));
  assert(Array.isArray(result.fileWarnings));
}

console.log("All risk analyzer sample tests passed.");

const DISCLAIMER =
  "This tool provides risk indicators, not a guarantee. Verify sensitive actions through official websites or apps.";

const trustedDomains = [
  "paypal.com",
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "bankofamerica.com",
  "chase.com",
  "wellsfargo.com",
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "indeed.com",
  "handshake.com",
  "roblox.com"
];

const brandDomains = {
  paypal: "paypal.com",
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  appleid: "apple.com",
  amazon: "amazon.com",
  bankofamerica: "bankofamerica.com",
  "bank of america": "bankofamerica.com",
  chase: "chase.com",
  wellsfargo: "wellsfargo.com",
  "wells fargo": "wellsfargo.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  linkedin: "linkedin.com",
  indeed: "indeed.com",
  handshake: "handshake.com",
  roblox: "roblox.com"
};

const freeEmailDomains = new Set([
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com"
]);

const urlShorteners = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "rebrand.ly",
  "cutt.ly",
  "is.gd"
]);

const suspiciousUrlWords = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "payment",
  "support",
  "refund",
  "unlock",
  "confirm"
];

const dangerousExecutableExtensions = new Set([
  ".exe",
  ".bat",
  ".cmd",
  ".scr",
  ".js",
  ".vbs",
  ".ps1",
  ".msi",
  ".jar",
  ".apk",
  ".com",
  ".pif"
]);

const suspiciousArchiveExtensions = new Set([".zip", ".rar", ".7z", ".iso"]);
const macroEnabledOfficeExtensions = new Set([".docm", ".xlsm", ".pptm"]);

const messageRules = [
  {
    label: "Urgency or fear language",
    score: 20,
    patterns: [
      "urgent",
      "immediately",
      "act now",
      "final warning",
      "last chance",
      "account suspended",
      "account locked",
      "verify now",
      "within 24 hours",
      "payment failed",
      "your package is blocked",
      "your account will be closed"
    ]
  },
  {
    label: "Requests sensitive information",
    score: 40,
    patterns: [
      "password",
      "login",
      "verification code",
      "otp",
      "two-factor code",
      "2fa",
      "ssn",
      "social security",
      "bank account",
      "bank info",
      "credit card",
      "debit card",
      "security question",
      "confirm your identity",
      "id photo",
      "passport",
      "driver license"
    ]
  },
  {
    label: "Requests money or payment through risky channels",
    score: 40,
    patterns: [
      "gift card",
      "crypto",
      "bitcoin",
      "wire transfer",
      "western union",
      "zelle",
      "cash app",
      "venmo",
      "payment required",
      "refund",
      "unpaid invoice",
      "processing fee"
    ]
  },
  {
    label: "Too-good-to-be-true offer",
    score: 20,
    patterns: [
      "you won",
      "free iphone",
      "guaranteed prize",
      "easy money",
      "no interview required",
      "work from home $300/day",
      "$300/day",
      "double your money",
      "guaranteed investment",
      "scholarship approved"
    ]
  },
  {
    label: "Dangerous action instructions",
    score: 30,
    patterns: [
      "click this link",
      "open attachment",
      "download the file",
      "enable macros",
      "disable antivirus",
      "run as administrator",
      "install this app",
      "allow remote access",
      "do not tell anyone"
    ]
  },
  {
    label: "Attachment mentioned",
    score: 20,
    patterns: [
      "attachment",
      "attached file",
      "invoice attached",
      "resume attached",
      "document attached",
      "see attached",
      "download attachment"
    ]
  }
];

function normalizeText(value) {
  return String(value || "").toLowerCase();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasPhrase(text, phrase) {
  const normalizedPhrase = phrase.toLowerCase();
  if (/^[a-z0-9]+$/i.test(normalizedPhrase)) {
    return new RegExp(`\\b${escapeRegExp(normalizedPhrase)}\\b`, "i").test(text);
  }
  return text.includes(normalizedPhrase);
}

function findMatchedPhrases(text, patterns) {
  return patterns.filter((pattern) => hasPhrase(text, pattern));
}

function addScore(result, score, flag) {
  result.score += score;
  result.redFlags.push(flag);
}

function analyzeMessage(message = "") {
  const result = { score: 0, redFlags: [] };
  const text = normalizeText(message);

  if (!text.trim()) {
    return result;
  }

  // Message scoring is category based so repeated scare words do not inflate the score endlessly.
  for (const rule of messageRules) {
    const matches = findMatchedPhrases(text, rule.patterns);
    if (matches.length > 0) {
      addScore(result, rule.score, `${rule.label}: ${matches.slice(0, 4).join(", ")}`);
    }
  }

  return result;
}

function extractUrls(message = "") {
  const urlPattern = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
  return Array.from(new Set(String(message || "").match(urlPattern) || [])).map((url) =>
    url.replace(/[.,!?;:]+$/, "")
  );
}

function isIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function getRegisteredDomain(hostname) {
  const host = normalizeText(hostname).replace(/\.$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return host;
  }

  const publicSuffixPairs = new Set(["co.uk", "com.au", "com.br", "co.jp", "com.mx"]);
  const suffixPair = parts.slice(-2).join(".");
  if (publicSuffixPairs.has(suffixPair) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

function isTrustedDomainOrSubdomain(hostname, officialDomain) {
  const host = normalizeText(hostname);
  const official = normalizeText(officialDomain);
  return host === official || host.endsWith(`.${official}`);
}

function getMentionedBrands(text) {
  const normalized = normalizeText(text).replace(/[^a-z0-9]+/g, " ");
  const compact = normalized.replace(/\s+/g, "");
  return Object.entries(brandDomains)
    .filter(([brand]) => {
      const brandWords = normalizeText(brand);
      const compactBrand = brandWords.replace(/\s+/g, "");
      return normalized.includes(brandWords) || compact.includes(compactBrand);
    })
    .map(([brand, domain]) => ({ brand, domain }));
}

function analyzeUrls(message = "") {
  const extractedLinks = extractUrls(message);
  const result = { score: 0, redFlags: [], extractedLinks };

  for (const link of extractedLinks) {
    let parsed;
    try {
      parsed = new URL(link);
    } catch {
      addScore(result, 20, `Malformed or unusual URL: ${link}`);
      continue;
    }

    const hostname = parsed.hostname.toLowerCase();
    const registeredDomain = getRegisteredDomain(hostname);

    if (urlShorteners.has(registeredDomain)) {
      addScore(result, 25, `Shortened link hides the final destination: ${link}`);
    }

    if (isIpAddress(hostname)) {
      addScore(result, 30, `Link uses a raw IP address instead of a normal domain: ${link}`);
    }

    const wordHits = suspiciousUrlWords.filter((word) =>
      normalizeText(`${hostname} ${parsed.pathname} ${parsed.search}`).includes(word)
    );
    if (wordHits.length > 0) {
      const cappedScore = Math.min(wordHits.length * 10, 30);
      addScore(
        result,
        cappedScore,
        `Link contains suspicious words (${wordHits.slice(0, 3).join(", ")}): ${link}`
      );
    }

    if (registeredDomain.includes("-")) {
      addScore(result, 10, `Hyphenated domain can be used for impersonation: ${registeredDomain}`);
    }

    if (link.length > 100) {
      addScore(result, 10, `Very long link may be hiding tracking or redirects: ${link}`);
    }

    if (link.includes("@")) {
      addScore(result, 30, `Link contains an @ symbol, which can hide the real destination: ${link}`);
    }

    const hostAndPath = normalizeText(`${hostname} ${parsed.pathname}`);
    const compactHostAndPath = hostAndPath.replace(/[^a-z0-9]+/g, "");
    const impersonatedBrand = Object.entries(brandDomains).find(([brand, officialDomain]) => {
      const compactBrand = brand.replace(/\s+/g, "");
      const brandAppears = compactHostAndPath.includes(compactBrand);
      return brandAppears && !isTrustedDomainOrSubdomain(hostname, officialDomain);
    });

    if (impersonatedBrand) {
      addScore(
        result,
        35,
        `Possible ${impersonatedBrand[0]} impersonation: ${registeredDomain} is not ${impersonatedBrand[1]}`
      );
    }
  }

  return result;
}

function analyzeSender(senderEmail = "", message = "", source = "") {
  const result = { score: 0, redFlags: [] };
  const normalizedSource = normalizeText(source);
  const combinedContext = `${message} ${source}`;
  const mentionedBrands = getMentionedBrands(combinedContext);

  const senderDomain = normalizeText(String(senderEmail).split("@").pop() || "").trim();
  const hasSenderEmail = senderEmail.includes("@") && senderDomain.includes(".");

  if (hasSenderEmail && mentionedBrands.length > 0 && freeEmailDomains.has(senderDomain)) {
    addScore(
      result,
      30,
      `Sender uses a free email domain while the message appears to reference ${mentionedBrands[0].brand}`
    );
  }

  if (hasSenderEmail && mentionedBrands.length > 0) {
    const matchingBrand = mentionedBrands.find(
      ({ domain }) => !isTrustedDomainOrSubdomain(senderDomain, domain)
    );
    if (matchingBrand) {
      addScore(
        result,
        30,
        `Sender domain (${senderDomain}) does not match the claimed organization (${matchingBrand.domain})`
      );
    }
  }

  const unknownSources = [
    "unknown email",
    "discord dm",
    "telegram",
    "random website",
    "craigslist",
    "facebook marketplace",
    "unknown recruiter"
  ];
  const matchedUnknownSource = unknownSources.find((item) => normalizedSource.includes(item));
  if (matchedUnknownSource) {
    addScore(result, 15, `Source is higher risk or hard to verify: ${matchedUnknownSource}`);
  }

  return result;
}

function getExtension(fileName) {
  const match = normalizeText(fileName).match(/(\.[a-z0-9]+)$/);
  return match ? match[1] : "";
}

function hasDoubleExtension(fileName) {
  const lowerName = normalizeText(fileName);
  const parts = lowerName.split(".").filter(Boolean);
  if (parts.length < 3) {
    return false;
  }

  const finalExtension = `.${parts[parts.length - 1]}`;
  const priorExtension = `.${parts[parts.length - 2]}`;
  const commonDocumentOrMediaExtensions = new Set([
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".txt"
  ]);

  return (
    commonDocumentOrMediaExtensions.has(priorExtension) &&
    (dangerousExecutableExtensions.has(finalExtension) ||
      macroEnabledOfficeExtensions.has(finalExtension))
  );
}

function analyzeFileMetadata(file = {}) {
  const result = { score: 0, redFlags: [], fileWarnings: [], criticalTriggered: false };
  const fileName = String(file.fileName || "").trim();
  const extension = getExtension(fileName);

  if (!fileName) {
    return result;
  }

  // File analysis intentionally uses metadata only. The app must never upload, scan, or execute suspicious files.
  if (hasDoubleExtension(fileName)) {
    addScore(result, 70, `File uses a deceptive double extension: ${fileName}`);
    result.fileWarnings.push("The file name appears to disguise its true file type.");
  }

  if (dangerousExecutableExtensions.has(extension)) {
    addScore(result, 60, `File has a dangerous executable extension: ${extension}`);
    result.fileWarnings.push("Executable files can install malware or make system changes.");
  }

  if (suspiciousArchiveExtensions.has(extension)) {
    addScore(result, 20, `File is a compressed archive: ${extension}`);
    result.fileWarnings.push("Archives can hide risky files inside them.");
  }

  if (macroEnabledOfficeExtensions.has(extension)) {
    addScore(result, 40, `File is a macro-enabled Office document: ${extension}`);
    result.fileWarnings.push("Macro-enabled Office files can run scripts when opened.");
  }

  const fileWords = [
    "invoice",
    "payment",
    "receipt",
    "refund",
    "resume",
    "job offer",
    "tax",
    "scholarship",
    "urgent",
    "password",
    "bank",
    "statement"
  ];
  const matchedFileWords = findMatchedPhrases(normalizeText(fileName), fileWords);
  if (matchedFileWords.length > 0) {
    addScore(
      result,
      Math.min(matchedFileWords.length * 10, 30),
      `File name uses common scam lure words: ${matchedFileWords.slice(0, 3).join(", ")}`
    );
  }

  if (file.fileSizeBytes && Number(file.fileSizeBytes) <= 0) {
    result.fileWarnings.push("The file size looks invalid or empty.");
  }

  if (file.source) {
    const sourceResult = analyzeSender("", "", file.source);
    result.score += sourceResult.score;
    result.redFlags.push(...sourceResult.redFlags);
  }

  if (file.userAlreadyDownloaded) {
    addScore(result, 20, "You already downloaded the suspicious file.");
    result.fileWarnings.push(
      "Do not open the file. Delete it if you do not trust the source and run a security scan."
    );
  }

  if (file.userAlreadyOpened) {
    result.criticalTriggered = true;
    result.fileWarnings.push("You already opened the suspicious file, so treat this as urgent.");
  }

  return result;
}

function getRiskLevel(score, criticalTriggered = false) {
  if (criticalTriggered || score >= 80) {
    return "Critical Risk";
  }
  if (score >= 50) {
    return "High Risk";
  }
  if (score >= 25) {
    return "Medium Risk";
  }
  return "Low Risk";
}

function buildSafeActions(riskLevel, context = {}) {
  const actionsByRisk = {
    "Low Risk": [
      "No major red flags were found.",
      "Still verify directly through the official website or app before sharing sensitive information."
    ],
    "Medium Risk": [
      "Do not click links until you verify the sender.",
      "Contact the company/person through an official website, app, or known phone number.",
      "Do not share passwords, verification codes, or payment details."
    ],
    "High Risk": [
      "Do not click links.",
      "Do not reply.",
      "Do not download or open attachments.",
      "Go directly to the official website or app instead.",
      "Report or mark the message as phishing/spam."
    ],
    "Critical Risk": [
      "Stop interacting with the message/file immediately.",
      "If you entered a password, change it from the official website or app.",
      "If you shared a verification code, secure that account immediately.",
      "If you sent money, contact your bank/payment provider immediately.",
      "If you opened a suspicious file, disconnect from the internet temporarily and run a full security scan."
    ]
  };

  const actions = [...actionsByRisk[riskLevel]];

  if (context.userAlreadyDownloaded) {
    actions.push("Do not open the file. Delete it if you do not trust the source and run a security scan.");
  }

  if (context.userAlreadyOpened) {
    actions.push("Disconnect from the internet temporarily if you suspect malware.");
    actions.push("Run Windows Security or trusted antivirus full scan.");
    actions.push("Change important passwords from a different trusted device.");
    actions.push("Enable 2FA on important accounts.");
    actions.push("Check bank/payment accounts for suspicious activity.");
    actions.push("Consider getting professional help if money/accounts are affected.");
  }

  return Array.from(new Set(actions));
}

function getCriticalActionFlags(userActions = {}) {
  const labels = {
    clickedLink: "You already clicked a suspicious link.",
    downloadedFile: "You already downloaded a suspicious file.",
    openedFile: "You already opened a suspicious file.",
    enteredPassword: "You already entered a password.",
    sharedCode: "You already shared a verification code.",
    sentMoney: "You already sent money.",
    installedSoftware: "You already installed software.",
    gaveRemoteAccess: "You already gave remote access."
  };

  return Object.entries(labels)
    .filter(([key]) => Boolean(userActions[key]))
    .map(([, label]) => label);
}

function buildSummary(riskLevel, redFlags) {
  if (riskLevel === "Low Risk") {
    return "No major red flags were found, but verify directly through the official website or app before taking sensitive action.";
  }

  const issueCount = redFlags.length;
  if (riskLevel === "Medium Risk") {
    return `This looks questionable and has ${issueCount} risk indicator${issueCount === 1 ? "" : "s"}. Verify it through an official channel before clicking, replying, or sharing information.`;
  }

  if (riskLevel === "High Risk") {
    return `This has strong scam or security warning signs. Avoid interacting with it and use official websites, apps, or known phone numbers to verify.`;
  }

  return "Treat this as urgent. The message, link, file metadata, or actions already taken indicate a serious risk that needs immediate protective steps.";
}

function analyzeRisk(input = {}) {
  const message = String(input.message || "");
  const senderEmail = String(input.senderEmail || "");
  const source = String(input.source || "");
  const file = input.file || {};
  const userActions = input.userActions || {};

  const messageResult = analyzeMessage(message);
  const urlResult = analyzeUrls(message);
  const senderResult = analyzeSender(senderEmail, message, source);
  const fileResult = analyzeFileMetadata(file);
  const criticalActionFlags = getCriticalActionFlags({
    ...userActions,
    downloadedFile: Boolean(file.userAlreadyDownloaded),
    openedFile: Boolean(file.userAlreadyOpened)
  });

  let score =
    messageResult.score + urlResult.score + senderResult.score + fileResult.score;
  const redFlags = [
    ...messageResult.redFlags,
    ...urlResult.redFlags,
    ...senderResult.redFlags,
    ...fileResult.redFlags,
    ...criticalActionFlags
  ];

  if (criticalActionFlags.length > 0) {
    score += 20;
  }

  const criticalTriggered = criticalActionFlags.length > 0 || fileResult.criticalTriggered;
  const cappedScore = Math.min(score, 100);
  const riskLevel = getRiskLevel(cappedScore, criticalTriggered);

  return {
    riskLevel,
    score: cappedScore,
    summary: buildSummary(riskLevel, redFlags),
    redFlags,
    safeActions: buildSafeActions(riskLevel, {
      userAlreadyDownloaded: Boolean(file.userAlreadyDownloaded),
      userAlreadyOpened: Boolean(file.userAlreadyOpened)
    }),
    extractedLinks: urlResult.extractedLinks,
    fileWarnings: fileResult.fileWarnings,
    disclaimer: DISCLAIMER
  };
}

module.exports = {
  analyzeRisk,
  analyzeMessage,
  analyzeUrls,
  analyzeSender,
  analyzeFileMetadata,
  getRiskLevel,
  buildSafeActions
};

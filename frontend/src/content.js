export const demoReport = {
  label: "Demo threat report",
  riskLevel: "High Risk",
  score: 87,
  threatType: "Phishing / Credential Theft",
  attackerIntent: "Steal login credentials by pushing the user toward a fake account warning page.",
  redFlags: [
    "Suspicious login link",
    "Urgent wording",
    "Sender does not match official domain",
    "Possible fake account warning"
  ],
  safeActions: [
    "Do not click the link",
    "Visit the official website directly",
    "Change your password if you already entered info",
    "Enable two-factor authentication"
  ],
  disclaimer:
    "This is sample output. CyberThreatDetector provides risk indicators, not a guarantee."
};

export const features = [
  {
    title: "Suspicious URL Analysis",
    description:
      "Paste a link and check for phishing, fake login pages, suspicious redirects, and risky domains."
  },
  {
    title: "Email & Message Scam Detection",
    description:
      "Analyze suspicious emails, texts, and social messages for scam patterns and social engineering."
  },
  {
    title: "Screenshot Threat Review",
    description:
      "Upload a screenshot of a message, email, or website and receive a beginner-friendly threat explanation."
  },
  {
    title: "Clear Threat Report",
    description:
      "Get a risk level, threat type, red flags, attacker intent, and safe next steps."
  }
];

export const stories = [
  {
    title: "The Fake PayPal Login",
    text:
      "Maria received an urgent email claiming her PayPal account was locked. CyberThreatDetector flagged the suspicious sender, fake login link, and panic-based wording as signs of credential theft.",
    tags: ["Phishing", "Fake Login", "High Risk"]
  },
  {
    title: "The Remote Job Scam",
    text:
      "A student received a high-paying remote job offer that asked for personal information and an upfront payment. CyberThreatDetector identified vague company details, pressure tactics, and payment requests.",
    tags: ["Job Scam", "Identity Theft", "Social Engineering"]
  },
  {
    title: "The Delivery Text Trap",
    text:
      "A fake delivery message claimed a package could not be delivered. The link led to a fake tracking page. CyberThreatDetector flagged it as a phishing attempt.",
    tags: ["SMS Scam", "Fake Delivery", "Suspicious Link"]
  },
  {
    title: "The School Account Warning",
    text:
      "A student received an email saying their school account would be disabled unless they logged in immediately. CyberThreatDetector detected impersonation, urgency, and a fake login page.",
    tags: ["Account Theft", "Impersonation", "Credential Harvesting"]
  }
];

export const howItWorks = [
  "Paste or upload suspicious content.",
  "AI checks scam language, suspicious links, phishing patterns, and warning signs.",
  "Receive a clear cyber threat report with risk score and safe next steps."
];

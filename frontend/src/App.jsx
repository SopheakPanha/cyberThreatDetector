import { useMemo, useState } from "react";
import {
  Button,
  FeatureCard,
  ReportList,
  SectionHeading,
  ShellCard,
  StepCard,
  StoryCard,
  ThreatReportPreview
} from "./components.jsx";
import { demoReport, features, howItWorks, stories } from "./content";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";
const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024;
const ALLOWED_SCREENSHOT_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

const actionLabels = [
  ["clickedLink", "I clicked a link"],
  ["enteredPassword", "I entered my password"],
  ["sharedCode", "I shared a verification code"],
  ["sentMoney", "I sent money"],
  ["installedSoftware", "I installed software"],
  ["gaveRemoteAccess", "I gave remote access"]
];

const emptyResult = {
  riskLevel: "Demo",
  score: demoReport.score,
  summary: "This panel shows sample output until you run a scan.",
  redFlags: demoReport.redFlags,
  safeActions: demoReport.safeActions,
  extractedLinks: [],
  fileWarnings: [],
  disclaimer: demoReport.disclaimer
};

function makeActions() {
  return {
    clickedLink: false,
    enteredPassword: false,
    sharedCode: false,
    sentMoney: false,
    installedSoftware: false,
    gaveRemoteAccess: false
  };
}

function deriveThreatNarrative(result) {
  const flags = `${result.redFlags?.join(" ")} ${result.summary || ""}`.toLowerCase();

  if (flags.includes("password") || flags.includes("credential") || flags.includes("login")) {
    return {
      threatType: "Phishing / Credential Theft",
      attackerIntent: "Push you toward a fake login or account page to steal access."
    };
  }
  if (flags.includes("payment") || flags.includes("money") || flags.includes("bank")) {
    return {
      threatType: "Payment Scam / Financial Fraud",
      attackerIntent: "Pressure you into sending money or exposing payment details."
    };
  }
  if (flags.includes("file") || flags.includes("download") || flags.includes("attachment")) {
    return {
      threatType: "Malicious File / Attachment Risk",
      attackerIntent: "Convince you to open or run something risky on your device."
    };
  }
  if (result.riskLevel === "Low Risk") {
    return {
      threatType: "No Major Pattern Detected",
      attackerIntent: "No clear attacker goal was detected, but verification is still important."
    };
  }
  return {
    threatType: "Suspicious Social Engineering",
    attackerIntent: "Create urgency, confusion, or trust so you take a risky action."
  };
}

function ActionCheckboxes({ actions, onToggle }) {
  return (
    <div className="checkbox-grid">
      {actionLabels.map(([key, label]) => (
        <label key={key}>
          <input type="checkbox" checked={actions[key]} onChange={() => onToggle(key)} />
          {label}
        </label>
      ))}
    </div>
  );
}

function ThreatReport({ result, mode, extractedText, ocrConfidence }) {
  const narrative = deriveThreatNarrative(result);
  const isDemo = mode === "demo";
  const riskKey = result.riskLevel?.toLowerCase().split(" ")[0] || "demo";

  return (
    <ShellCard className="live-report">
      <div className="panel-topline">
        <span className="status-dot" />
        <span>{isDemo ? "Demo/sample output" : "Live analyzer output"}</span>
      </div>
      <div className="score-row">
        <div>
          <span className="metric-label">Risk Score</span>
          <strong>{result.score} / 100</strong>
        </div>
        <span className={`risk-badge risk-${riskKey}`}>{result.riskLevel}</span>
      </div>
      <div className="meter-track">
        <span style={{ width: `${Math.min(result.score || 0, 100)}%` }} />
      </div>
      <div className="report-grid">
        <div>
          <span className="metric-label">Threat Type</span>
          <strong>{isDemo ? demoReport.threatType : narrative.threatType}</strong>
        </div>
        <div>
          <span className="metric-label">Attacker Intent</span>
          <strong>{isDemo ? demoReport.attackerIntent : narrative.attackerIntent}</strong>
        </div>
      </div>
      <p className="summary">{result.summary}</p>
      {mode === "screenshot" ? (
        <section className="extracted-block">
          <div>
            <h3>Extracted Text</h3>
            {ocrConfidence !== null ? <span>OCR confidence: {ocrConfidence}%</span> : null}
          </div>
          <pre>{extractedText}</pre>
        </section>
      ) : null}
      <ReportList title="Red Flags" items={result.redFlags} emptyText="No red flags found." />
      <ReportList title="Safe Next Steps" items={result.safeActions} emptyText="Run a scan to see next steps." />
      <ReportList title="Extracted Links" items={result.extractedLinks} emptyText="No links detected." />
      <ReportList title="File Warnings" items={result.fileWarnings} emptyText="No file warnings." />
      <p className="disclaimer">{result.disclaimer}</p>
    </ShellCard>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [senderOrSource, setSenderOrSource] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileSize, setFileSize] = useState("");
  const [fileSource, setFileSource] = useState("");
  const [fileDownloaded, setFileDownloaded] = useState(false);
  const [fileOpened, setFileOpened] = useState(false);
  const [actions, setActions] = useState(makeActions);
  const [screenshot, setScreenshot] = useState(null);
  const [screenshotSource, setScreenshotSource] = useState("");
  const [result, setResult] = useState(emptyResult);
  const [resultMode, setResultMode] = useState("demo");
  const [extractedText, setExtractedText] = useState("");
  const [ocrConfidence, setOcrConfidence] = useState(null);
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState("");

  const sourceFields = useMemo(() => {
    const value = senderOrSource.trim();
    return {
      senderEmail: value.includes("@") ? value : "",
      source: value.includes("@") ? "" : value
    };
  }, [senderOrSource]);

  function toggleAction(action) {
    setActions((current) => ({ ...current, [action]: !current[action] }));
  }

  function validateScreenshotFile(file) {
    if (!file) return "Choose a screenshot or photo first.";
    if (!ALLOWED_SCREENSHOT_TYPES.has(file.type)) return "Only JPG, PNG, and WEBP screenshots are allowed.";
    if (file.size > MAX_SCREENSHOT_BYTES) return "Image is too large. Maximum allowed size is 5MB.";
    return "";
  }

  async function analyzeTextPayload(payload, mode) {
    setStatus("loading");
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze-risk`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The risk checker API returned an error.");
      setResult(data);
      setResultMode(mode);
      setExtractedText("");
      setOcrConfidence(null);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setStatus("idle");
    }
  }

  function scanUrl() {
    analyzeTextPayload({ message: url, ...sourceFields, userActions: actions }, "url");
  }

  function analyzeMessage() {
    analyzeTextPayload({ message, ...sourceFields, userActions: actions }, "message");
  }

  function analyzeFileName() {
    analyzeTextPayload({
      message,
      ...sourceFields,
      file: {
        fileName,
        fileSizeBytes: Number(fileSize) || 0,
        source: fileSource,
        userAlreadyDownloaded: fileDownloaded,
        userAlreadyOpened: fileOpened
      },
      userActions: actions
    }, "file");
  }

  async function analyzeScreenshot() {
    const validationError = validateScreenshotFile(screenshot);
    if (validationError) {
      setError(validationError);
      return;
    }
    setStatus("loading");
    setError("");
    const screenshotSenderEmail = screenshotSource.includes("@") ? screenshotSource.trim() : "";
    const screenshotSourceLabel = screenshotSource.includes("@") ? "" : screenshotSource.trim();
    const formData = new FormData();
    formData.append("screenshot", screenshot);
    formData.append("senderEmail", screenshotSenderEmail);
    formData.append("source", screenshotSourceLabel);
    Object.entries(actions).forEach(([key, value]) => formData.append(key, String(value)));

    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze-screenshot`, {
        method: "POST",
        body: formData
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Screenshot analysis failed.");
      setResult(data);
      setResultMode("screenshot");
      setExtractedText(data.extractedText || "");
      setOcrConfidence(data.ocrConfidence ?? null);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setStatus("idle");
    }
  }

  const scanTabs = [
    ["url", "URL"],
    ["message", "Email / Message"],
    ["screenshot", "Screenshot Upload"],
    ["file", "File Name"]
  ];

  return (
    <main className="app-shell">
      <div className="grid-backdrop" aria-hidden="true" />
      <nav className="navbar" aria-label="Main navigation">
        <a className="brand" href="#home">CyberThreatDetector</a>
        <div className="nav-links">
          <a href="#home">Home</a>
          <a href="#analyze">Analyze</a>
          <a href="#stories">Stories</a>
          <a href="#how-it-works">How It Works</a>
        </div>
        <Button as="a" href="#analyze" className="nav-cta">Launch Scanner</Button>
      </nav>

      <section className="hero-section" id="home">
        <div className="hero-copy">
          <p className="eyebrow">AI-assisted cyber safety scanner</p>
          <h1>Detect Cyber Threats Before They Detect You</h1>
          <p>
            Analyze suspicious links, scam emails, text messages, and screenshots with AI. Get a clear risk score,
            red flags, and safe next steps in seconds.
          </p>
          <div className="hero-actions">
            <Button as="a" href="#analyze">Analyze Threat</Button>
            <Button as="a" href="#demo" variant="secondary">Watch Demo</Button>
          </div>
        </div>
        <ThreatReportPreview />
      </section>

      <section className="analyzer-section" id="analyze">
        <SectionHeading
          eyebrow="Launch Scanner"
          title="Analyze a threat signal"
          subtitle="Use the real backend scanner for URLs, messages, file-name metadata, and screenshot OCR."
        />
        <div className="scanner-layout">
          <ShellCard className="scanner-panel">
            <div className="tab-row" role="tablist" aria-label="Analyzer modes">
              {scanTabs.map(([key, label]) => (
                <button
                  key={key}
                  className={activeTab === key ? "active" : ""}
                  type="button"
                  onClick={() => {
                    setActiveTab(key);
                    setError("");
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            {activeTab === "url" ? (
              <div className="scan-form">
                <label htmlFor="url-input">Suspicious URL</label>
                <input
                  id="url-input"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="Paste suspicious URL here..."
                />
                <Button type="button" onClick={scanUrl} disabled={status === "loading"}>
                  {status === "loading" ? "Scanning..." : "Scan URL"}
                </Button>
              </div>
            ) : null}

            {activeTab === "message" ? (
              <div className="scan-form">
                <label htmlFor="message-input">Email, text, or message</label>
                <textarea
                  id="message-input"
                  value={message}
                  onChange={(event) => setMessage(event.target.value)}
                  placeholder="Paste suspicious email, text, or message here..."
                />
                <input
                  value={senderOrSource}
                  onChange={(event) => setSenderOrSource(event.target.value)}
                  placeholder="Sender email or source optional"
                  aria-label="Sender email or source optional"
                />
                <Button type="button" onClick={analyzeMessage} disabled={status === "loading"}>
                  {status === "loading" ? "Analyzing..." : "Analyze Message"}
                </Button>
              </div>
            ) : null}

            {activeTab === "screenshot" ? (
              <div className="scan-form">
                <p className="privacy-warning">
                  Upload screenshots only. Do not upload IDs, bank statements, passwords, private documents, or
                  suspicious executable files. Images are analyzed temporarily and not stored.
                </p>
                <label
                  className="upload-zone"
                  htmlFor="screenshot-input"
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault();
                    const file = event.dataTransfer.files?.[0] || null;
                    setScreenshot(file);
                    setError(file ? validateScreenshotFile(file) : "");
                  }}
                >
                  <span>Drop a screenshot here</span>
                  <strong>{screenshot ? screenshot.name : "or choose JPG, PNG, or WEBP"}</strong>
                  <small>Maximum 5MB. Screenshots/photos only.</small>
                </label>
                <input
                  id="screenshot-input"
                  className="visually-hidden"
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={(event) => {
                    const file = event.target.files?.[0] || null;
                    setScreenshot(file);
                    setError(file ? validateScreenshotFile(file) : "");
                  }}
                />
                <input
                  value={screenshotSource}
                  onChange={(event) => setScreenshotSource(event.target.value)}
                  placeholder="Sender or source optional, e.g. SMS, Gmail, Discord, PayPal email"
                  aria-label="Screenshot sender or source optional"
                />
                <Button type="button" onClick={analyzeScreenshot} disabled={status === "loading"}>
                  {status === "loading" ? "Extracting text..." : "Analyze Screenshot"}
                </Button>
              </div>
            ) : null}

            {activeTab === "file" ? (
              <div className="scan-form">
                <p className="privacy-warning">
                  File checking uses metadata only. Do not upload or open suspicious executable files.
                </p>
                <label htmlFor="file-name">File name</label>
                <input
                  id="file-name"
                  value={fileName}
                  onChange={(event) => setFileName(event.target.value)}
                  placeholder="invoice.pdf.exe"
                />
                <div className="two-column">
                  <input
                    value={fileSize}
                    onChange={(event) => setFileSize(event.target.value)}
                    type="number"
                    min="0"
                    placeholder="File size in bytes"
                    aria-label="File size in bytes"
                  />
                  <input
                    value={fileSource}
                    onChange={(event) => setFileSource(event.target.value)}
                    placeholder="File source optional"
                    aria-label="File source optional"
                  />
                </div>
                <div className="checkbox-grid">
                  <label>
                    <input
                      type="checkbox"
                      checked={fileDownloaded}
                      onChange={() => setFileDownloaded((value) => !value)}
                    />
                    I already downloaded this file
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={fileOpened}
                      onChange={() => setFileOpened((value) => !value)}
                    />
                    I already opened this file
                  </label>
                </div>
                <Button type="button" onClick={analyzeFileName} disabled={status === "loading"}>
                  {status === "loading" ? "Checking..." : "Analyze File Name"}
                </Button>
              </div>
            ) : null}

            <section className="action-context">
              <h3>Emergency context</h3>
              <ActionCheckboxes actions={actions} onToggle={toggleAction} />
            </section>
            {error ? <p className="error-message">{error}</p> : null}
          </ShellCard>

          <ThreatReport
            result={result}
            mode={resultMode}
            extractedText={extractedText}
            ocrConfidence={ocrConfidence}
          />
        </div>
      </section>

      <section className="feature-section">
        <SectionHeading eyebrow="Capabilities" title="Built for everyday cyber decisions" />
        <div className="card-grid">
          {features.map((feature, index) => (
            <FeatureCard key={feature.title} {...feature} index={index} />
          ))}
        </div>
      </section>

      <section className="stories-section" id="stories">
        <SectionHeading
          eyebrow="Threat Stories"
          title="Real Threat Stories"
          subtitle="Common scams that CyberThreatDetector is designed to explain."
        />
        <div className="story-grid">
          {stories.map((story) => (
            <StoryCard key={story.title} {...story} />
          ))}
        </div>
      </section>

      <section className="how-section" id="how-it-works">
        <SectionHeading eyebrow="Flow" title="How It Works" />
        <div className="step-grid">
          {howItWorks.map((step, index) => (
            <StepCard key={step} step={index + 1} text={step} />
          ))}
        </div>
      </section>

      <footer className="footer">
        <div>
          <strong>CyberThreatDetector</strong>
          <p>Beginner-friendly cyber risk reports for suspicious links, messages, screenshots, and file names.</p>
        </div>
        <div>
          <a href="https://github.com/" target="_blank" rel="noreferrer">GitHub</a>
          <span>Built for Codex Creator Challenge</span>
        </div>
        <p>
          CyberThreatDetector is an educational tool. Always verify important security decisions through official
          sources.
        </p>
      </footer>
    </main>
  );
}

import { demoReport } from "./content";

export function Button({ children, variant = "primary", as = "button", className = "", ...props }) {
  const Component = as;
  return (
    <Component className={`btn btn-${variant} ${className}`.trim()} {...props}>
      {children}
    </Component>
  );
}

export function ShellCard({ children, className = "" }) {
  return <div className={`shell-card ${className}`.trim()}>{children}</div>;
}

export function SectionHeading({ eyebrow, title, subtitle }) {
  return (
    <div className="section-heading">
      {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      <h2>{title}</h2>
      {subtitle ? <p>{subtitle}</p> : null}
    </div>
  );
}

export function ThreatReportPreview() {
  return (
    <ShellCard className="demo-panel" id="demo">
      <div className="panel-topline">
        <span className="status-dot" />
        <span>Sample scanner output</span>
      </div>
      <div className="score-meter" aria-label="Demo risk score 87 out of 100">
        <div>
          <span className="metric-label">Risk Score</span>
          <strong>{demoReport.score} / 100</strong>
        </div>
        <div className="meter-track">
          <span style={{ width: `${demoReport.score}%` }} />
        </div>
      </div>
      <div className="report-grid">
        <div>
          <span className="metric-label">Risk Level</span>
          <strong className="risk-word high">High</strong>
        </div>
        <div>
          <span className="metric-label">Threat Type</span>
          <strong>{demoReport.threatType}</strong>
        </div>
      </div>
      <ReportList title="Red Flags" items={demoReport.redFlags} />
      <ReportList title="Safe Next Steps" items={demoReport.safeActions} />
    </ShellCard>
  );
}

export function ReportList({ title, items, emptyText = "Nothing to show yet." }) {
  return (
    <section className="report-list">
      <h3>{title}</h3>
      {items?.length ? (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted">{emptyText}</p>
      )}
    </section>
  );
}

export function FeatureCard({ title, description, index }) {
  return (
    <ShellCard className="feature-card">
      <span className="card-index">0{index + 1}</span>
      <h3>{title}</h3>
      <p>{description}</p>
    </ShellCard>
  );
}

export function StoryCard({ title, text, tags }) {
  return (
    <ShellCard className="story-card">
      <h3>{title}</h3>
      <p>{text}</p>
      <div className="tag-row">
        {tags.map((tag) => (
          <span key={tag}>{tag}</span>
        ))}
      </div>
    </ShellCard>
  );
}

export function StepCard({ step, text }) {
  return (
    <ShellCard className="step-card">
      <span>Step {step}</span>
      <h3>{text}</h3>
    </ShellCard>
  );
}

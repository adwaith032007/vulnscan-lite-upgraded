import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";

function App() {
  const [user, setUser] = useState(null);
  const [login, setLogin] = useState({
    username: "admin",
    password: "admin123",
  });

  const [url, setUrl] = useState("https://example.com");
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [active, setActive] = useState("dashboard");

  async function api(path, options = {}) {
    const response = await fetch(API + path, {
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      ...options,
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.error || "Request failed");
    }

    return data;
  }

  async function refresh() {
    try {
      const data = await api("/api/history");
      setHistory(data);
    } catch (error) {
      console.error("History error:", error);
    }
  }

  useEffect(() => {
    api("/api/me")
      .then((data) => {
        if (data.authenticated) {
          setUser(data.username);
          refresh();
        }
      })
      .catch(() => {});
  }, []);

  async function doLogin(event) {
    event.preventDefault();
    setError("");

    try {
      const data = await api("/api/login", {
        method: "POST",
        body: JSON.stringify(login),
      });

      setUser(data.username);
      refresh();
    } catch (error) {
      setError(error.message);
    }
  }

  async function doScan(event) {
    event.preventDefault();
    setLoading(true);
    setError("");

    try {
      const data = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({ url }),
      });

      setScan(data);
      setActive("dashboard");
      refresh();
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function openHistory(id) {
    try {
      const data = await api("/api/scans/" + id);
      setScan(data);
      setActive("dashboard");
    } catch (error) {
      setError(error.message);
    }
  }

  async function logout() {
    try {
      await api("/api/logout", {
        method: "POST",
      });

      setUser(null);
      setScan(null);
      setHistory([]);
    } catch (error) {
      setError(error.message);
    }
  }

  const stats = useMemo(
    () => ({
      total: history.length,
      high: history.filter(
        (item) => item.risk_level?.toLowerCase() === "high"
      ).length,
      medium: history.filter(
        (item) => item.risk_level?.toLowerCase() === "medium"
      ).length,
      low: history.filter(
        (item) => item.risk_level?.toLowerCase() === "low"
      ).length,
    }),
    [history]
  );

  if (!user) {
    return (
      <main className="auth-shell">
        <div className="auth-glow"></div>

        <form className="login card" onSubmit={doLogin}>
          <div className="brand-mark">V</div>

          <h1>
            VulnScan<span>-Lite</span>
          </h1>

          <p className="muted">
            Passive web security intelligence
          </p>

          <input
            placeholder="Username"
            value={login.username}
            onChange={(event) =>
              setLogin({
                ...login,
                username: event.target.value,
              })
            }
          />

          <input
            type="password"
            placeholder="Password"
            value={login.password}
            onChange={(event) =>
              setLogin({
                ...login,
                password: event.target.value,
              })
            }
          />

          <button type="submit">
            Sign in to console <span>→</span>
          </button>

          {error && <div className="error">{error}</div>}

          <small>Demo access: admin / admin123</small>
        </form>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="side-brand">
          <div className="brand-mark small">V</div>

          <div>
            <strong>
              VulnScan<span>-Lite</span>
            </strong>
            <small>Security Console</small>
          </div>
        </div>

        <nav>
          <button
            className={active === "dashboard" ? "active" : ""}
            onClick={() => setActive("dashboard")}
          >
            ⌂ <span>Dashboard</span>
          </button>

          <button
            className={active === "scan" ? "active" : ""}
            onClick={() => setActive("scan")}
          >
            ⌁ <span>New Scan</span>
          </button>

          <button
            className={active === "history" ? "active" : ""}
            onClick={() => setActive("history")}
          >
            ◷ <span>Scan History</span>
          </button>
        </nav>

        <div className="side-bottom">
          <div className="status-dot">
            ● <span>Scanner online</span>
          </div>

          <button className="logout" onClick={logout}>
            ↪ Logout
          </button>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS</p>

            <h1>
              {active === "history"
                ? "Scan History"
                : active === "scan"
                ? "New Security Scan"
                : "Security Overview"}
            </h1>
          </div>

          <div className="profile">
            <div className="avatar">
              {user[0]?.toUpperCase()}
            </div>

            <div>
              <strong>{user}</strong>
              <small>Administrator</small>
            </div>
          </div>
        </header>

        {error && <div className="error banner">{error}</div>}

        {active === "scan" && (
          <section className="card scan-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">PASSIVE ASSESSMENT</p>

                <h2>Start a new scan</h2>

                <p className="muted">
                  Analyze security headers and publicly visible
                  configuration.
                </p>
              </div>

              <span className="pill blue">Safe mode</span>
            </div>

            <form onSubmit={doScan} className="scan-form">
              <input
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://target-you-own.com"
                required
              />

              <button type="submit" disabled={loading}>
                {loading ? "Scanning…" : "Start Scan →"}
              </button>
            </form>

            <small className="notice">
              Only scan websites you own or have explicit permission
              to assess.
            </small>
          </section>
        )}

        {active !== "history" && (
          <>
            <section className="stats-grid">
              <Stat
                label="Total scans"
                value={stats.total}
                icon="⌁"
              />

              <Stat
                label="High risk"
                value={stats.high}
                icon="!"
                tone="high"
              />

              <Stat
                label="Medium risk"
                value={stats.medium}
                icon="△"
                tone="medium"
              />

              <Stat
                label="Low risk"
                value={stats.low}
                icon="✓"
                tone="low"
              />
            </section>

            {active === "dashboard" && (
              <section className="card quick">
                <div>
                  <p className="eyebrow">GET STARTED</p>

                  <h2>Assess your next target</h2>

                  <p className="muted">
                    Run a passive scan to identify missing security
                    headers and configuration weaknesses.
                  </p>
                </div>

                <button onClick={() => setActive("scan")}>
                  New Scan →
                </button>
              </section>
            )}

            {scan && (
              <section className="card results">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">ASSESSMENT COMPLETE</p>

                    <h2>Scan Results</h2>

                    <p className="muted target">
                      {scan.final_url}
                    </p>
                  </div>

                  <a
                    className="button"
                    href={`${API}/api/scans/${scan.id}/report`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    ↓ PDF Report
                  </a>
                </div>

                <div className="metrics">
                  <Metric
                    label="Risk Score"
                    value={`${scan.risk_score}/100`}
                  />

                  <Metric
                    label="Risk Level"
                    value={scan.risk_level}
                    tone={scan.risk_level?.toLowerCase()}
                  />

                  <Metric
                    label="Findings"
                    value={scan.findings.length}
                  />

                  <Metric
                    label="HTTP Status"
                    value={scan.status_code}
                  />
                </div>

                <h3>
                  Security findings{" "}
                  <span>{scan.findings.length}</span>
                </h3>

                {scan.findings.length === 0 ? (
                  <p className="muted">
                    No passive findings detected.
                  </p>
                ) : (
                  scan.findings.map((finding, index) => (
                    <details className="finding" key={index}>
                      <summary>
                        <b className={finding.severity.toLowerCase()}>
                          {finding.severity}
                        </b>

                        <span>{finding.title}</span>

                        <i>+</i>
                      </summary>

                      <p>{finding.description}</p>

                      <p>
                        <strong>Remediation:</strong>{" "}
                        {finding.remediation}
                      </p>

                      {finding.evidence && (
                        <code>{finding.evidence}</code>
                      )}
                    </details>
                  ))
                )}
              </section>
            )}
          </>
        )}

        {active === "history" && (
          <section className="card history">
            <div className="section-heading">
              <div>
                <p className="eyebrow">AUDIT TRAIL</p>

                <h2>Previous assessments</h2>
              </div>

              <button onClick={() => setActive("scan")}>
                New Scan →
              </button>
            </div>

            {history.length === 0 ? (
              <div className="empty">
                No scans yet. Start your first assessment.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Risk</th>
                    <th>Score</th>
                    <th>Date</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => openHistory(item.id)}
                    >
                      <td>{item.target}</td>

                      <td>
                        <b className={item.risk_level.toLowerCase()}>
                          {item.risk_level}
                        </b>
                      </td>

                      <td>{item.risk_score}</td>

                      <td>
                        {new Date(
                          item.scanned_at
                        ).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

function Stat({ label, value, icon, tone }) {
  return (
    <div className="stat card">
      <div className={`stat-icon ${tone || ""}`}>
        {icon}
      </div>

      <div>
        <small>{label}</small>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div className="metric">
      <small>{label}</small>
      <strong className={tone || ""}>{value}</strong>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
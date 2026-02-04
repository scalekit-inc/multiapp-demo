import { useEffect, useMemo, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { verifyJwt } from "./auth/jwt";
import { getTokens } from "./auth/oauth";
import { clearTokens } from "./auth/storage";
import Callback from "./pages/Callback";
import Home from "./pages/Home";
import LoggedOut from "./pages/LoggedOut";

const styles = {
  page: {
    minHeight: "100vh",
    fontFamily: "system-ui",
    background: "#f6f8fb",
    color: "#0f172a",
  },
  topBar: {
    padding: "22px 28px",
  },
  topBarRow: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
    maxWidth: 1180,
    margin: "0 auto",
  },
  title: {
    fontSize: 28,
    fontWeight: 900,
    margin: 0,
    letterSpacing: "-0.02em",
  },
  statusPill: (isLoggedIn) => ({
    display: "inline-flex",
    alignItems: "center",
    gap: 10,
    padding: "8px 14px",
    borderRadius: 999,
    fontWeight: 800,
    fontSize: 14,
    border: "1px solid #dbeafe",
    background: isLoggedIn ? "#e9f8ee" : "#eef2f6",
    color: isLoggedIn ? "#15803d" : "#64748b",
  }),
  statusDot: (isLoggedIn) => ({
    width: 10,
    height: 10,
    borderRadius: "50%",
    background: isLoggedIn ? "#16a34a" : "#64748b",
  }),
  content: {
    maxWidth: 1180,
    margin: "0 auto",
    padding: "0 28px 40px",
  },
};

export default function App() {
  const [tokens, setTokens] = useState(() => getTokens());
  const [authError, setAuthError] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  const isLoggedIn = useMemo(() => Boolean(tokens?.access_token), [tokens]);

  useEffect(() => {
    let cancelled = false;

    if (window.location.pathname === "/callback") {
      setAuthChecked(true);
      return;
    }

    const failAuth = (msg) => {
      clearTokens();
      if (!cancelled) {
        setTokens(null);
        setAuthError(msg || "Session invalid. Please log in again.");
      }
    };

    // ✅ Catch ANY unhandled promise rejection (including verifyJwt called elsewhere)
    const onUnhandledRejection = (event) => {
      const reason = event?.reason;
      const message = String(reason?.message || reason || "");
      if (message.includes("JWSSignatureVerificationFailed")) {
        event.preventDefault?.(); // stops the "Uncaught (in promise)" noise in many browsers
        failAuth("Invalid token signature. Please log in again.");
      }
    };
    window.addEventListener("unhandledrejection", onUnhandledRejection);

    const validateAndSync = async () => {
      try {
        const t = getTokens();

        if (!t) {
          if (!cancelled) {
            setTokens(null);
            setAuthError(null);
            setAuthChecked(true);
          }
          return;
        }

        if (t.access_token) {
          await verifyJwt(t.access_token);
        }

        if (!cancelled) {
          setTokens(t);
          setAuthError(null);
          setAuthChecked(true);
        }
      } catch (e) {
        console.error("Token validation failed:", e);
        failAuth("Session invalid or tampered. Please log in again.");
        if (!cancelled) setAuthChecked(true);
      }
    };

    validateAndSync();

    const onFocus = () => validateAndSync();
    window.addEventListener("focus", onFocus);

    return () => {
      cancelled = true;
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
    };
  }, []);

  // ✅ Don’t render Home until we’ve validated storage at least once
  if (!authChecked) {
    return (
      <div style={styles.page}>
        <div style={styles.topBar}>
          <div style={styles.topBarRow}>
            <h1 style={styles.title}>Example Single Page App</h1>
            <span style={styles.statusPill(false)}>
              <span style={styles.statusDot(false)} />
              Checking session…
            </span>
          </div>
        </div>
        <div style={styles.content}>Loading…</div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.topBar}>
        <div style={styles.topBarRow}>
          <h1 style={styles.title}>Example Single Page App</h1>
          <span style={styles.statusPill(isLoggedIn)}>
            <span style={styles.statusDot(isLoggedIn)} />
            {isLoggedIn ? "Logged in" : "Logged out"}
          </span>
        </div>

        {authError ? (
          <div
            style={{
              maxWidth: 1180,
              margin: "10px auto 0",
              padding: "10px 14px",
              borderRadius: 12,
              border: "1px solid #fecdd3",
              background: "#fff1f2",
              color: "#9f1239",
              fontWeight: 800,
            }}
          >
            {authError}
          </div>
        ) : null}
      </div>

      <div style={styles.content}>
        <Routes>
          <Route path="/" element={<Home tokens={tokens} setTokens={setTokens} />} />
          <Route path="/callback" element={<Callback onDone={() => setTokens(getTokens())} />} />
          <Route path="/logged-out" element={<LoggedOut onRelogin={() => setTokens(getTokens())} />} />
        </Routes>
      </div>
    </div>
  );
}

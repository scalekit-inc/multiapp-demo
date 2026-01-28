import { useEffect, useMemo, useRef, useState } from "react";
import { logout, refreshIfNeeded, startLogin } from "../auth/oauth";

const styles = {
  card: {
    background: "white",
    border: "1px solid #e2e8f0",
    borderRadius: 14,
    padding: 18,
    boxShadow: "0 6px 18px rgba(15, 23, 42, 0.04)",
    marginTop: 16,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 900,
    margin: "2px 0 12px",
    letterSpacing: "-0.01em",
  },
  actionsRow: {
    display: "flex",
    gap: 12,
    flexWrap: "wrap",
  },
  btnPrimary: {
    background: "#0b5ea8",
    color: "white",
    border: "1px solid #0b5ea8",
    padding: "10px 14px",
    borderRadius: 10,
    fontWeight: 800,
    cursor: "pointer",
  },
  btnDangerOutline: {
    background: "white",
    color: "#dc2626",
    border: "1px solid #dc2626",
    padding: "10px 14px",
    borderRadius: 10,
    fontWeight: 800,
    cursor: "pointer",
  },
  btnLoginBig: {
    background: "#0b5ea8",
    color: "white",
    border: "1px solid #0b5ea8",
    padding: "14px 26px",
    borderRadius: 14,
    fontSize: 18,
    fontWeight: 900,
    cursor: "pointer",
    boxShadow: "0 0 0 3px #e6f1fb",
  },
  center: {
    display: "grid",
    placeItems: "center",
    padding: "36px 0",
  },
  pre: {
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: 12,
    padding: 14,
    overflowX: "auto",
    fontSize: 13,
    lineHeight: 1.45,
    margin: 0,
  },
  debugList: {
    display: "grid",
    gap: 12,
  },
  debugRow: {
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: 12,
    padding: 14,
  },
  label: {
    color: "#64748b",
    fontWeight: 800,
    fontSize: 14,
    marginBottom: 6,
  },
  value: {
    fontWeight: 700,
    fontSize: 14,
    wordBreak: "break-word",
  },
  err: {
    marginTop: 12,
    background: "#fff1f2",
    border: "1px solid #fecdd3",
    color: "#9f1239",
    padding: 12,
    borderRadius: 12,
    fontWeight: 700,
    whiteSpace: "pre-wrap",
  },
  toast: {
    position: "fixed",
    bottom: 24,
    left: "50%",
    transform: "translateX(-50%)",
    background: "#0f172a",
    color: "white",
    padding: "14px 24px",
    borderRadius: 14,
    fontSize: 16,
    fontWeight: 800,
    boxShadow: "0 12px 30px rgba(0,0,0,0.25)",
    zIndex: 1000,
    display: "flex",
    alignItems: "center",
    gap: 10
  }
};

export default function Home({ tokens, setTokens }) {
  const [err, setErr] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = (msg) => {
    setToast(msg);
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => setToast(null), 3000);
  };

  const isCallback = window.location.pathname === "/callback";
  const isLoggedIn = Boolean(tokens?.access_token);

  // keep these env keys flexible (use what you already have)
  const debug = useMemo(() => {
    const authDomain =
      import.meta.env.VITE_ISSUER_BASE_URL || "—";
    const clientId = import.meta.env.VITE_CLIENT_ID || "—";
    const redirectUri =
      import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/callback`;
    const scope =
      import.meta.env.VITE_SCOPE || "openid email profile offline_access";

    // optional: if you can detect logout support in your oauth helper, wire it here
    const oidcLogoutSupport = "Yes";

    return { authDomain, clientId, redirectUri, scope, oidcLogoutSupport };
  }, []);

  const refreshDisabled = useRef(false);
  const reloadTimerRef = useRef(null);

  const handleRefreshFailure = (message) => {
    if (refreshDisabled.current) return; // ✅ prevent loops
    refreshDisabled.current = true;
    showToast(message || "❌ Session expired. Reloading…");
    if (reloadTimerRef.current) window.clearTimeout(reloadTimerRef.current);

    reloadTimerRef.current = window.setTimeout(() => {
      window.location.assign(`/`);
    }, 3000);
  };

  const ranOnceRef = useRef(false);

  useEffect(() => {
    if (ranOnceRef.current) return;
    ranOnceRef.current = true;
    (async () => {
      if (isCallback) return;
      if (refreshDisabled.current) return;
      try {
        const t = await refreshIfNeeded();
        if (t) {
          setTokens(t);
        }
      } catch (e) {
        console.error(e);
        if (tokens?.access_token || tokens?.refresh_token) {
          handleRefreshFailure("❌ Session expired. Reloading…");
        } else {
          setTokens(null);
        }
        handleRefreshFailure("❌ Session expired. Redirecting…");
      }
    })();
  }, [setTokens]);

  useEffect(() => {
    return () => {
      if (reloadTimerRef.current) window.clearTimeout(reloadTimerRef.current);
    };
  }, []);


  if (!isLoggedIn) {
    return (
      <div>
        {/* Actions */}
        <div style={styles.card}>
          <div style={styles.cardTitle}>Actions</div>

          {!isLoggedIn ? (
            <div style={styles.actionsRow}>
              <button style={styles.btnPrimary} onClick={() => startLogin()}>
                Login
              </button>
            </div>
          ) : (
            <div style={styles.actionsRow}>
              <button
                style={styles.btnPrimary}
                onClick={async () => {
                  try {
                    const localTokens = await refreshIfNeeded({ force: true }) 
                    setTokens(localTokens);
                    showToast("✅ Token refreshed");
                  } catch (e) {
                    setErr(String(e));
                    handleRefreshFailure("❌ Token refresh failed. Redirecting…");
                  }
                }}
              >
                Refresh token
              </button>

              <button
                style={styles.btnDangerOutline}
                onClick={async () => {
                  try {
                    await logout();
                  } catch (e) {
                    setErr(String(e));
                  }
                }}
              >
                Logout
              </button>
            </div>
          )}
        </div>

        {/* Debug Information */}
        <div style={styles.card}>
          <div style={styles.cardTitle}>Debug Information</div>

          <div style={styles.debugList}>
            <div style={styles.debugRow}>
              <div style={styles.label}>Auth Domain</div>
              <div style={styles.value}>{debug.authDomain}</div>
            </div>

            <div style={styles.debugRow}>
              <div style={styles.label}>Client ID</div>
              <div style={styles.value}>{debug.clientId}</div>
            </div>

            <div style={styles.debugRow}>
              <div style={styles.label}>Redirect URI</div>
              <div style={styles.value}>{debug.redirectUri}</div>
            </div>

            <div style={styles.debugRow}>
              <div style={styles.label}>Scopes</div>
              <div style={styles.value}>{debug.scope}</div>
            </div>

            <div style={styles.debugRow}>
              <div style={styles.label}>OIDC Logout Support</div>
              <div style={styles.value}>{debug.oidcLogoutSupport}</div>
            </div>
          </div>
        </div>

        {err ? <div style={styles.err}>{err}</div> : null}
        {toast ? <div style={styles.toast}>{toast}</div> : null}
      </div>
    );
  }

  return (
    <div>
      {/* Actions */}
      <div style={styles.card}>
        <div style={styles.cardTitle}>Actions</div>
        <div style={styles.actionsRow}>
          <button
            style={styles.btnPrimary}
            onClick={async () => {
              try {
                setTokens(await refreshIfNeeded({ force: true }));
                showToast("✅ Token refreshed");
                setTimeout(() => setToast(null), 3000);
              } catch (e) {
                setErr(String(e));
                handleRefreshFailure("❌ Token refresh failed. Redirecting…");
              }
            }}
          >
            Refresh token
          </button>


          <button
            style={styles.btnDangerOutline}
            onClick={async () => {
              try {
                await logout();
              } catch (e) {
                setErr(String(e));
              }
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Access token payload */}
      <div style={styles.card}>
        <div style={styles.cardTitle}>Access Token (decoded)</div>
        <pre style={styles.pre}>
          {JSON.stringify(tokens?.access_payload ?? {}, null, 2)}
        </pre>
      </div>

      {/* Token metadata */}
      <div style={styles.card}>
        <div style={styles.cardTitle}>Token Metadata</div>
        <pre style={styles.pre}>
          {JSON.stringify(
            {
              expires_at: tokens?.expires_at,
              obtained_at: tokens?.obtained_at,
            },
            null,
            2
          )}
        </pre>
      </div>

      {/* Debug Information */}
      <div style={styles.card}>
        <div style={styles.cardTitle}>Debug Information</div>

        <div style={styles.debugList}>
          <div style={styles.debugRow}>
            <div style={styles.label}>Auth Domain</div>
            <div style={styles.value}>{debug.authDomain}</div>
          </div>

          <div style={styles.debugRow}>
            <div style={styles.label}>Client ID</div>
            <div style={styles.value}>{debug.clientId}</div>
          </div>

          <div style={styles.debugRow}>
            <div style={styles.label}>Redirect URI</div>
            <div style={styles.value}>{debug.redirectUri}</div>
          </div>

          <div style={styles.debugRow}>
            <div style={styles.label}>Scopes</div>
            <div style={styles.value}>{debug.scope}</div>
          </div>

          <div style={styles.debugRow}>
            <div style={styles.label}>OIDC Logout Support</div>
            <div style={styles.value}>{debug.oidcLogoutSupport}</div>
          </div>
        </div>
      </div>

      {err ? <div style={styles.err}>{err}</div> : null}
      {toast && <div style={styles.toast}>{toast}</div>}
    </div>
  );
}


import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { verifyJwt } from "../auth/jwt";
import { handleCallback } from "../auth/oauth";

const styles = {
  wrap: { marginTop: 10 },
  title: { fontSize: 14, fontWeight: 800, margin: "18px 0 8px" },
  pre: {
    background: "#0b1220",
    color: "#e5e7eb",
    padding: 14,
    borderRadius: 12,
    overflowX: "auto",
    fontSize: 13,
    border: "1px solid rgba(255,255,255,0.06)",
  },
};

export default function Callback({ onDone }) {
  const [status, setStatus] = useState("Handling callback...");
  const [details, setDetails] = useState(null);
  const nav = useNavigate();
  const ranRef = useRef(false);

  useEffect(() => {
    if (ranRef.current) return;
    ranRef.current = true;
    (async () => {
      try {
        const t = await handleCallback();
        if (t?.access_token) {
          await verifyJwt(t.access_token);
        } else {
          throw new Error("no access token found");
        }
        setStatus("✅ Logged in!");
        setDetails(t?.access_payload ?? t);
        onDone?.();
        setTimeout(() => nav("/"), 350);
      } catch (e) {
        setStatus("❌ Callback failed");
        setDetails(String(e));
        window.location.replace("/");
      }
    })();
  }, [nav, onDone]);

  return (
    <div style={styles.wrap}>
      <div style={styles.title}>{status}</div>
      {details ? <pre style={styles.pre}>{JSON.stringify(details, null, 2)}</pre> : null}
    </div>
  );
}

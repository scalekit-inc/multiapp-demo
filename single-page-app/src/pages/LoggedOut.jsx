import { useNavigate } from "react-router-dom";

const styles = {
  title: {
    fontSize: 22,
    fontWeight: 900,
    marginBottom: 16,
  },
  button: {
    background: "#0b5ea8",
    color: "white",
    border: "none",
    padding: "10px 16px",
    borderRadius: 12,
    fontSize: 14,
    fontWeight: 800,
    cursor: "pointer",
  },
};

export default function LoggedOut() {
  const navigate = useNavigate();

  return (
    <div>
      <div style={styles.title}>✅ Logged out</div>
      <button style={styles.button} onClick={() => navigate("/")}>
        Home
      </button>
    </div>
  );
}

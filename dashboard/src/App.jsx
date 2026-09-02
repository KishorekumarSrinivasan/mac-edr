import { useEffect, useState, useCallback } from "react";
import { api } from "./api";

const RESPONSE_FOR_RULE = {
  MALWARE_HASH_MATCH: "quarantine_file",
  SUSPICIOUS_NETWORK_PORT: "block_connection",
  SUSPICIOUS_PROCESS_PATH: "kill_process",
};

function targetFor(alert) {
  const action = RESPONSE_FOR_RULE[alert.rule];
  if (action === "quarantine_file") return alert.source_path;
  if (action === "block_connection") return alert.source_path; // "ip:port"
  if (action === "kill_process") return String(alert.source_pid);
  return null;
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [network, setNetwork] = useState([]);
  const [connected, setConnected] = useState(false);
  const [pendingIds, setPendingIds] = useState(new Set());

  const poll = useCallback(async () => {
    try {
      await api.health();
      setConnected(true);
      const [a, p, n] = await Promise.all([api.alerts(), api.processes(), api.network()]);
      setAlerts(a);
      setProcesses(p);
      setNetwork(n);
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, [poll]);

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  async function respond(alert) {
    const action = RESPONSE_FOR_RULE[alert.rule];
    const target = targetFor(alert);
    if (!action || !target) return;
    setPendingIds((s) => new Set(s).add(alert.id));
    try {
      await api.triggerResponse(alert.id, action, target);
    } finally {
      poll();
    }
  }

  return (
    <div className="app">
      <div className="header">
        <div className="title">MAC EDR</div>
        <div className="status">
          <span className={`dot ${connected ? "up" : "down"}`} />
          {connected ? "backend connected" : "backend unreachable"}
        </div>
      </div>

      <div className="counters">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
          <div className="counter" key={sev}>
            <div className="n">{counts[sev] || 0}</div>
            <div className="label">{sev}</div>
          </div>
        ))}
      </div>

      <div className="panel">
        <h2>Alerts</h2>
        {alerts.length === 0 ? (
          <div className="empty">No alerts.</div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th className="col-sev">Severity</th>
                  <th className="col-rule">Rule</th>
                  <th>Message</th>
                  <th className="col-response">Response</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => {
                  const action = RESPONSE_FOR_RULE[a.rule];
                  return (
                    <tr key={a.id}>
                      <td className="col-time">{new Date(a.timestamp).toLocaleTimeString()}</td>
                      <td className="col-sev"><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                      <td className="col-rule" title={a.rule}>{a.rule}</td>
                      <td title={a.message}>{a.message}</td>
                      <td className="col-response">
                        {action ? (
                          <button
                            disabled={pendingIds.has(a.id)}
                            onClick={() => respond(a)}
                          >
                            {action.replace("_", " ")}
                          </button>
                        ) : (
                          <span style={{ color: "var(--dim)" }}>—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Processes ({processes.length})</h2>
        {processes.length === 0 ? (
          <div className="empty">No data yet.</div>
        ) : (
          <table>
            <thead><tr><th>PID</th><th>Name</th><th>User</th><th>Path</th></tr></thead>
            <tbody>
              {processes.slice(0, 50).map((p) => (
                <tr key={`${p.pid}-${p.timestamp}`}>
                  <td>{p.pid}</td><td>{p.name}</td><td>{p.user}</td><td>{p.path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Network ({network.length})</h2>
        {network.length === 0 ? (
          <div className="empty">No data yet.</div>
        ) : (
          <table>
            <thead><tr><th>PID</th><th>Local</th><th>Remote</th><th>Status</th></tr></thead>
            <tbody>
              {network.slice(0, 50).map((c) => (
                <tr key={`${c.id}`}>
                  <td>{c.pid}</td>
                  <td>{c.local_addr}:{c.local_port}</td>
                  <td>{c.remote_addr ? `${c.remote_addr}:${c.remote_port}` : "—"}</td>
                  <td>{c.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

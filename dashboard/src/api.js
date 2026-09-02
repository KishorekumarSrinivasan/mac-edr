const BASE = "http://127.0.0.1:8000";

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

async function post(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE}${path}${qs ? `?${qs}` : ""}`, { method: "POST" });
  if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
  return res.json();
}

export const api = {
  health: () => get("/"),
  alerts: () => get("/alerts"),
  processes: () => get("/processes"),
  network: () => get("/network"),
  actions: () => get("/response"),
  triggerResponse: (alertId, actionType, target) =>
    post("/response/trigger", { alert_id: alertId, action_type: actionType, target }),
};

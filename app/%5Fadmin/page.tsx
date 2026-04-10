"use client";

import { useCallback, useEffect, useRef, useState } from "react";

// Judge/admin dashboard. Ugly on purpose — this is event plumbing.
// Blue teams should NOT modify this file.

type LogRecord = {
  timestamp: string;
  request_id: string;
  tenant_id: string;
  route: string;
  method: string;
  status: number;
  actor: string | null;
  duration_ms: number;
};

type Filters = {
  route: string;
  method: string;
  status: string;
  actor: string;
};

const EMPTY_FILTERS: Filters = { route: "", method: "", status: "", actor: "" };

export default function AdminPage() {
  const [token, setToken] = useState("");
  const [tokenInput, setTokenInput] = useState("");
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [events, setEvents] = useState<LogRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [auto, setAuto] = useState(true);
  const [lastFetch, setLastFetch] = useState<string>("");
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchEvents = useCallback(async () => {
    if (!token) return;
    const params = new URLSearchParams();
    if (filters.route) params.set("route", filters.route);
    if (filters.method) params.set("method", filters.method);
    if (filters.status) params.set("status", filters.status);
    if (filters.actor) params.set("actor", filters.actor);
    params.set("limit", "500");
    try {
      const res = await fetch(`/api/_admin/events?${params.toString()}`, {
        headers: { "x-admin-token": token },
        cache: "no-store",
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(`${res.status}: ${body.error || res.statusText}`);
        return;
      }
      const data = (await res.json()) as { events: LogRecord[] };
      setEvents(data.events || []);
      setError(null);
      setLastFetch(new Date().toLocaleTimeString());
    } catch (e) {
      setError(String(e));
    }
  }, [token, filters]);

  useEffect(() => {
    if (!auto || !token) return;
    fetchEvents();
    timerRef.current = setInterval(fetchEvents, 3000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [auto, token, fetchEvents]);

  const doReset = async () => {
    if (!token) return;
    if (!confirm("Wipe all users, actions, sessions, and logs?")) return;
    const res = await fetch("/api/_admin/reset", {
      method: "POST",
      headers: { "x-admin-token": token },
    });
    if (res.ok) {
      setEvents([]);
      alert("reset ok");
    } else {
      alert("reset failed: " + res.status);
    }
  };

  const inputStyle: React.CSSProperties = {
    background: "#111",
    color: "#eaeaea",
    border: "1px solid #444",
    padding: "0.35rem 0.5rem",
    fontFamily: "inherit",
    fontSize: "0.85rem",
  };
  const btnStyle: React.CSSProperties = {
    ...inputStyle,
    cursor: "pointer",
  };

  return (
    <main>
      <h1 style={{ fontSize: "1.2rem", margin: "0 0 0.5rem" }}>
        _admin — judge dashboard
      </h1>
      <p style={{ opacity: 0.7, fontSize: "0.8rem", margin: "0 0 1rem" }}>
        event plumbing — do not modify. enter the admin token to load logs.
      </p>

      {!token ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setToken(tokenInput);
          }}
          style={{ display: "flex", gap: "0.5rem" }}
        >
          <input
            type="password"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="admin token"
            style={{ ...inputStyle, width: 260 }}
            autoFocus
          />
          <button type="submit" style={btnStyle}>
            load
          </button>
        </form>
      ) : (
        <>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "0.5rem",
              alignItems: "center",
              marginBottom: "0.5rem",
            }}
          >
            <input
              value={filters.route}
              onChange={(e) => setFilters({ ...filters, route: e.target.value })}
              placeholder="route contains"
              style={inputStyle}
            />
            <input
              value={filters.method}
              onChange={(e) => setFilters({ ...filters, method: e.target.value })}
              placeholder="method"
              style={{ ...inputStyle, width: 80 }}
            />
            <input
              value={filters.status}
              onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              placeholder="status"
              style={{ ...inputStyle, width: 80 }}
            />
            <input
              value={filters.actor}
              onChange={(e) => setFilters({ ...filters, actor: e.target.value })}
              placeholder="actor"
              style={inputStyle}
            />
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.25rem",
                fontSize: "0.8rem",
              }}
            >
              <input
                type="checkbox"
                checked={auto}
                onChange={(e) => setAuto(e.target.checked)}
              />
              auto-refresh (3s)
            </label>
            <button onClick={fetchEvents} style={btnStyle} type="button">
              refresh
            </button>
            <button
              onClick={doReset}
              style={{ ...btnStyle, borderColor: "#a33", color: "#f88" }}
              type="button"
            >
              reset store + logs
            </button>
            <span style={{ opacity: 0.5, fontSize: "0.75rem" }}>
              {lastFetch && `last fetch: ${lastFetch}`}
            </span>
          </div>

          {error && (
            <div
              style={{
                color: "#f88",
                border: "1px solid #a33",
                padding: "0.5rem",
                marginBottom: "0.5rem",
                fontSize: "0.85rem",
              }}
            >
              {error}
            </div>
          )}

          <div
            style={{
              border: "1px solid #333",
              maxHeight: "70vh",
              overflow: "auto",
            }}
          >
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "0.78rem",
              }}
            >
              <thead
                style={{
                  position: "sticky",
                  top: 0,
                  background: "#1a1a1a",
                  textAlign: "left",
                }}
              >
                <tr>
                  <th style={{ padding: "0.4rem" }}>timestamp</th>
                  <th style={{ padding: "0.4rem" }}>method</th>
                  <th style={{ padding: "0.4rem" }}>route</th>
                  <th style={{ padding: "0.4rem" }}>status</th>
                  <th style={{ padding: "0.4rem" }}>actor</th>
                  <th style={{ padding: "0.4rem" }}>dur&nbsp;ms</th>
                  <th style={{ padding: "0.4rem" }}>req_id</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr>
                    <td colSpan={7} style={{ padding: "1rem", opacity: 0.5 }}>
                      no events
                    </td>
                  </tr>
                )}
                {events
                  .slice()
                  .reverse()
                  .map((ev, i) => (
                    <tr
                      key={ev.request_id + ":" + i}
                      style={{
                        borderTop: "1px solid #222",
                        background:
                          ev.status >= 500
                            ? "#2a0f0f"
                            : ev.status >= 400
                            ? "#2a1f0f"
                            : "transparent",
                      }}
                    >
                      <td style={{ padding: "0.35rem", whiteSpace: "nowrap" }}>
                        {ev.timestamp.replace("T", " ").replace("Z", "")}
                      </td>
                      <td style={{ padding: "0.35rem" }}>{ev.method}</td>
                      <td style={{ padding: "0.35rem" }}>{ev.route}</td>
                      <td style={{ padding: "0.35rem" }}>{ev.status}</td>
                      <td style={{ padding: "0.35rem" }}>{ev.actor || "—"}</td>
                      <td style={{ padding: "0.35rem" }}>{ev.duration_ms}</td>
                      <td
                        style={{
                          padding: "0.35rem",
                          fontSize: "0.7rem",
                          opacity: 0.6,
                        }}
                      >
                        {ev.request_id}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </main>
  );
}

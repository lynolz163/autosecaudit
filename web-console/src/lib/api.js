const JSON_HEADERS = {
  "Content-Type": "application/json",
};

export async function apiFetch(path, { method = "GET", token = "", body, headers = {}, signal } = {}) {
  const finalHeaders = { ...JSON_HEADERS, ...headers };
  if (!body) {
    delete finalHeaders["Content-Type"];
  }
  if (token) {
    finalHeaders.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(path, {
    method,
    headers: finalHeaders,
    body,
    signal,
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();
  if (!response.ok) {
    const detail =
      typeof payload === "string"
        ? payload
        : payload?.detail || payload?.error || `HTTP ${response.status}`;
    throw new Error(detail);
  }
  return payload;
}

export function buildAuthedUrl(path, token = "") {
  if (!token) {
    return path;
  }
  const url = new URL(path, window.location.origin);
  url.searchParams.set("api_token", token);
  return url.toString();
}

export function buildAuthedWebSocketUrl(path, token = "") {
  const url = new URL(path, window.location.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (token) {
    url.searchParams.set("api_token", token);
  }
  return url.toString();
}

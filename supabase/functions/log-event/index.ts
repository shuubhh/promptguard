import { authDevice, client } from "../_shared/device.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
};

const EVENT_TYPES = new Set(["silent", "warned", "override", "redacted", "blocked"]);
const MATCH_TYPES = new Set([
  "package_name", "class_name", "secret", "internal_url", "internal_ip",
  "vocabulary", "rules", "ai_context", "log_signature", "other",
]);

function json(res: unknown, status = 200): Response {
  return new Response(JSON.stringify(res), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const device = await authDevice(req);
  if (!device) return json({ error: "unauthorized" }, 401);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid json" }, 400);
  }

  const eventType = String(body.event_type || "").toLowerCase();
  if (!EVENT_TYPES.has(eventType)) return json({ error: "invalid event_type" }, 400);

  const confidence = Number(body.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return json({ error: "invalid confidence" }, 400);
  }

  const matchType = String(body.match_type || "other").toLowerCase();
  const preview = String(body.match_preview || "").slice(0, 30); // never full values
  const platform = String(body.platform || "unknown").slice(0, 60);
  const projectId = body.project_id ? String(body.project_id) : null;

  const supabase = client();
  const { data, error } = await supabase
    .from("events")
    .insert({
      org_id: device.org_id,
      project_id: projectId,
      user_email: device.user_email,
      event_type: eventType,
      confidence,
      match_type: MATCH_TYPES.has(matchType) ? matchType : "other",
      match_preview: preview,
      platform,
      device_id: device.id,
      device_name: device.device_name,
      timestamp: body.timestamp ? String(body.timestamp) : new Date().toISOString(),
    })
    .select("id")
    .single();

  if (error || !data) return json({ error: "insert failed" }, 500);
  return json({ ok: true, id: data.id }, 201);
});

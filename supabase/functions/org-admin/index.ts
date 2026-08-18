import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
};

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// 8-char code, unambiguous alphabet (no 0/O/1/I)
function randCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const out = new Array(8);
  const rand = new Uint8Array(8);
  crypto.getRandomValues(rand);
  for (let i = 0; i < 8; i++) out[i] = alphabet[rand[i] % alphabet.length];
  return out.join("");
}

function json(res: unknown, status = 200): Response {
  return new Response(JSON.stringify(res), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  // Authenticate the dashboard user with their JWT
  const authHeader = req.headers.get("authorization") || "";
  const userJwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!userJwt) return json({ error: "unauthorized" }, 401);

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: `Bearer ${userJwt}` } }, auth: { persistSession: false } },
  );

  const { data: { user }, error: userErr } = await supabase.auth.getUser();
  if (userErr || !user) return json({ error: "unauthorized" }, 401);

  const { data: profile } = await supabase
    .from("user_profiles")
    .select("org_id, role")
    .eq("id", user.id)
    .single();
  if (!profile?.org_id) return json({ error: "no org" }, 403);

  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid json" }, 400);
  }
  const action = String(body.action || "");

  if (action === "create_code") {
    const minutes = Math.min(Math.max(Number(body.minutes) || 60, 5), 1440);
    const code = randCode();
    const expiresAt = new Date(Date.now() + minutes * 60_000).toISOString();
    const { error: insErr } = await admin
      .from("extension_join_codes")
      .insert({ org_id: profile.org_id, created_by: user.email, code_hash: await sha256Hex(code), expires_at: expiresAt });
    if (insErr) return json({ error: "create failed" }, 500);
    return json({ code, expires_at: expiresAt, minutes });
  }

  if (action === "list_devices") {
    const { data: devices } = await admin
      .from("extension_devices")
      .select("id, user_email, device_name, created_at, last_seen_at, revoked_at")
      .eq("org_id", profile.org_id)
      .order("created_at", { ascending: false });
    return json({ devices: devices ?? [] });
  }

  if (action === "revoke_device") {
    const deviceId = String(body.device_id || "");
    const { data: device } = await admin
      .from("extension_devices")
      .select("id")
      .eq("id", deviceId)
      .eq("org_id", profile.org_id)
      .single();
    if (!device) return json({ error: "device not found" }, 404);
    const { error: updErr } = await admin
      .from("extension_devices")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", deviceId);
    if (updErr) return json({ error: "revoke failed" }, 500);
    return json({ ok: true });
  }

  if (action === "update_policy") {
    const patch: Record<string, unknown> = {};
    if (body.warn_threshold !== undefined) {
      const w = Number(body.warn_threshold);
      if (!Number.isFinite(w) || w < 0 || w > 1) return json({ error: "invalid warn_threshold" }, 400);
      patch.warn_threshold = w;
    }
    if (body.block_threshold !== undefined) {
      const b = Number(body.block_threshold);
      if (!Number.isFinite(b) || b < 0 || b > 1) return json({ error: "invalid block_threshold" }, 400);
      patch.block_threshold = b;
    }
    if (body.monitor_only !== undefined) patch.monitor_only = Boolean(body.monitor_only);
    if (body.feature_flags !== undefined) patch.feature_flags = body.feature_flags;
    if (Object.keys(patch).length === 0) return json({ error: "nothing to update" }, 400);

    const { data: org, error: updErr } = await admin
      .from("organisations")
      .update(patch)
      .eq("id", profile.org_id)
      .select("warn_threshold, block_threshold, monitor_only, feature_flags")
      .single();
    if (updErr || !org) return json({ error: "update failed" }, 500);
    return json({ ok: true, policy: org });
  }

  return json({ error: "unknown action" }, 400);
});

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

function randToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );

  let body: { code?: string; device_name?: string; user_email?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid json" }, 400);
  }

  const code = (body.code || "").trim().toUpperCase();
  if (code.length < 6) return json({ error: "invalid code" }, 400);

  const codeHash = await sha256Hex(code);
  const { data: joinCode } = await supabase
    .from("extension_join_codes")
    .select("id, org_id, created_by, expires_at, used_at")
    .eq("code_hash", codeHash)
    .single();

  if (!joinCode) return json({ error: "code not found" }, 404);
  if (joinCode.used_at) return json({ error: "code already used" }, 409);
  if (new Date(joinCode.expires_at) < new Date()) return json({ error: "code expired" }, 410);

  await supabase
    .from("extension_join_codes")
    .update({ used_at: new Date().toISOString() })
    .eq("id", joinCode.id);

  const deviceToken = randToken(32);
  const deviceName = (body.device_name || "Chrome").slice(0, 100);
  const userEmail = (body.user_email || "unknown").slice(0, 320);
  const tokenHash = await sha256Hex(deviceToken);

  const { data: device, error: devErr } = await supabase
    .from("extension_devices")
    .insert({
      org_id: joinCode.org_id,
      user_email: userEmail,
      device_name: deviceName,
      token_hash: tokenHash,
      last_seen_at: new Date().toISOString(),
    })
    .select("id")
    .single();

  if (devErr || !device) return json({ error: "device registration failed" }, 500);

  const { data: org } = await supabase
    .from("organisations")
    .select("id, name, warn_threshold, block_threshold, monitor_only, feature_flags")
    .eq("id", joinCode.org_id)
    .single();

  return json({
    device_token: deviceToken,
    device_id: device.id,
    org_id: org?.id ?? joinCode.org_id,
    org_name: org?.name ?? null,
    policy: {
      warn_threshold: org?.warn_threshold ?? 0.7,
      block_threshold: org?.block_threshold ?? 0.9,
      monitor_only: org?.monitor_only ?? false,
    },
    feature_flags: org?.feature_flags ?? {},
  }, 201);
});

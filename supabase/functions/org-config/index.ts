import { authDevice, client, touchDevice } from "../_shared/device.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
};

function json(res: unknown, status = 200): Response {
  return new Response(JSON.stringify(res), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "GET") return json({ error: "method not allowed" }, 405);

  const device = await authDevice(req);
  if (!device) return json({ error: "unauthorized" }, 401);
  touchDevice(device.id);

  const supabase = client();

  const { data: org } = await supabase
    .from("organisations")
    .select("id, name, warn_threshold, block_threshold, monitor_only, feature_flags")
    .eq("id", device.org_id)
    .single();

  const { data: projects } = await supabase
    .from("projects")
    .select("id, name, fingerprint, last_scanned_at")
    .eq("org_id", device.org_id);

  return json({
    device_id: device.id,
    org_id: device.org_id,
    user_email: device.user_email,
    org_name: org?.name ?? null,
    policy: {
      warn_threshold: org?.warn_threshold ?? 0.7,
      block_threshold: org?.block_threshold ?? 0.9,
      monitor_only: org?.monitor_only ?? false,
    },
    feature_flags: org?.feature_flags ?? {},
    projects: projects ?? [],
  });
});

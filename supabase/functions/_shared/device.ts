// Shared helper: authenticate a request with a device token (Bearer) and
// return the matching extension_devices row, or null.
// Note: edge functions are deployed as isolated bundles; this file is inlined
// into each function by the deploy step, so import it with a relative path.

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function client(): SupabaseClient {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );
}

export interface DeviceRow {
  id: string;
  org_id: string;
  user_email: string;
  device_name: string | null;
  revoked_at: string | null;
  expires_at: string | null;
}

export async function authDevice(req: Request): Promise<DeviceRow | null> {
  const header = req.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  const supabase = client();
  const { data } = await supabase
    .from("extension_devices")
    .select("id, org_id, user_email, device_name, revoked_at, expires_at")
    .eq("token_hash", await sha256Hex(token))
    .single();
  if (!data) return null;
  if (data.revoked_at) return null;
  if (data.expires_at && new Date(data.expires_at) < new Date()) return null;
  return data as DeviceRow;
}

export function touchDevice(deviceId: string): void {
  client()
    .from("extension_devices")
    .update({ last_seen_at: new Date().toISOString() })
    .eq("id", deviceId)
    .then(() => {})
    .catch(() => {});
}

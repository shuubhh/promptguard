import { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import { useApp } from '../lib/AppContext';
import { getProjects, getTeam, updateOrganisation } from '../lib/api';
import { Badge, Button, Card, CardHeader, Input } from '../components/ui';

export default function Settings() {
  const { org, profile, reload } = useApp();
  const orgId = org ? org.id : null;

  const [orgName, setOrgName] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  const [usage, setUsage] = useState({ projects: 0, users: 0 });
  const [apiKey, setApiKey] = useState('');
  const [refreshToken, setRefreshToken] = useState('');
  const [copied, setCopied] = useState('');

  // v2: org-management (device join codes, connected devices, org policy)
  const [joinCode, setJoinCode] = useState('');
  const [codeExpiry, setCodeExpiry] = useState('');
  const [devices, setDevices] = useState([]);
  const [warnThreshold, setWarnThreshold] = useState('0.7');
  const [blockThreshold, setBlockThreshold] = useState('0.9');
  const [monitorOnly, setMonitorOnly] = useState(false);
  const [orgBusy, setOrgBusy] = useState(false);
  const [orgMsg, setOrgMsg] = useState('');
  const [orgMsgError, setOrgMsgError] = useState(false);

  /** Call the org-admin edge function with the signed-in user's JWT. */
  async function callOrgAdmin(action, payload) {
    const { data: sessionData } = await supabase.auth.getSession();
    const token = sessionData && sessionData.session ? sessionData.session.access_token : null;
    if (!token) throw new Error('Not signed in');
    const base = import.meta.env.VITE_SUPABASE_URL + '/functions/v1/org-admin';
    const res = await fetch(base, {
      method: 'POST',
      headers: {
        apikey: import.meta.env.VITE_SUPABASE_ANON_KEY,
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token
      },
      body: JSON.stringify({ action: action, ...payload })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
    return data;
  }

  function flashOrgMsg(text, isError) {
    setOrgMsg(text);
    setOrgMsgError(!!isError);
  }

  async function loadOrgManagement() {
    if (!orgId) return;
    try {
      const r = await callOrgAdmin('list_devices', {});
      setDevices(Array.isArray(r.devices) ? r.devices : []);
    } catch (err) {
      /* device list is non-fatal */
    }
    try {
      const { data: orgRow } = await supabase
        .from('organisations')
        .select('warn_threshold, block_threshold, monitor_only')
        .eq('id', orgId)
        .single();
      if (orgRow) {
        setWarnThreshold(String(orgRow.warn_threshold ?? 0.7));
        setBlockThreshold(String(orgRow.block_threshold ?? 0.9));
        setMonitorOnly(!!orgRow.monitor_only);
      }
    } catch (err) {
      /* policy load is non-fatal */
    }
  }

  async function generateJoinCode() {
    setOrgBusy(true);
    flashOrgMsg('', false);
    try {
      const r = await callOrgAdmin('create_code', {});
      setJoinCode(r.code);
      setCodeExpiry(new Date(r.expires_at).toLocaleString());
      flashOrgMsg('Code generated — single use, expires ' + new Date(r.expires_at).toLocaleTimeString());
    } catch (err) {
      flashOrgMsg(err && err.message ? err.message : 'Failed to generate code', true);
    } finally {
      setOrgBusy(false);
    }
  }

  async function revokeDevice(id) {
    try {
      await callOrgAdmin('revoke_device', { device_id: id });
      await loadOrgManagement();
    } catch (err) {
      flashOrgMsg(err && err.message ? err.message : 'Revoke failed', true);
    }
  }

  async function savePolicy(e) {
    e.preventDefault();
    setOrgBusy(true);
    flashOrgMsg('', false);
    try {
      const r = await callOrgAdmin('update_policy', {
        warn_threshold: parseFloat(warnThreshold),
        block_threshold: parseFloat(blockThreshold),
        monitor_only: monitorOnly
      });
      flashOrgMsg('Policy saved — pushed to connected extensions within ~3 minutes');
    } catch (err) {
      flashOrgMsg(err && err.message ? err.message : 'Save failed', true);
    } finally {
      setOrgBusy(false);
    }
  }

  useEffect(() => {
    if (org) setOrgName(org.name || '');
  }, [org]);

  useEffect(() => {
    if (!orgId) return;
    Promise.all([getProjects(orgId), getTeam(orgId)])
      .then(([projects, team]) => setUsage({ projects: projects.length, users: team.length }))
      .catch(() => {});
  }, [orgId]);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) {
        setApiKey(data.session.access_token);
        setRefreshToken(data.session.refresh_token);
      }
    });
  }, []);

  useEffect(() => {
    if (orgId) loadOrgManagement();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  async function handleSaveOrg(e) {
    e.preventDefault();
    if (!orgId || !orgName.trim()) return;
    setSaving(true);
    setSaved(false);
    setError('');
    try {
      await updateOrganisation(orgId, orgName.trim());
      setSaved(true);
      await reload();
    } catch (err) {
      setError(err && err.message ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  async function copy(text, key) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(''), 2000);
    } catch (err) {
      /* ignore */
    }
  }

  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
  const maxProjects = org ? org.max_projects : 1;
  const maxUsers = org ? org.max_users : 5;

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white">Settings</h1>
        <p className="mt-1 text-sm text-muted">Organisation, plan and extension connection</p>
      </div>

      <Card>
        <CardHeader title="Organisation" subtitle="Name shown across the dashboard" />
        <form onSubmit={handleSaveOrg} className="flex flex-wrap items-end gap-3">
          <div className="min-w-[240px] flex-1">
            <Input
              label="Organisation name"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
            />
          </div>
          <Button type="submit" disabled={saving || !orgName.trim()}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
          {saved ? <span className="text-sm text-emerald-400">Saved ✓</span> : null}
        </form>
        {error ? <p className="mt-2 text-sm text-accent">{error}</p> : null}
      </Card>

      <Card>
        <CardHeader
          title="Plan & usage"
          subtitle={`Current plan: ${org ? org.plan : 'free'}`}
          action={<Badge tone="blue">{org ? org.plan : 'free'}</Badge>}
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <div className="mb-1 flex justify-between text-xs text-muted">
              <span>Projects</span>
              <span>
                {usage.projects} / {maxProjects}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full bg-accent"
                style={{ width: `${Math.min(100, (usage.projects / Math.max(1, maxProjects)) * 100)}%` }}
              />
            </div>
          </div>
          <div>
            <div className="mb-1 flex justify-between text-xs text-muted">
              <span>Users</span>
              <span>
                {usage.users} / {maxUsers}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full bg-success"
                style={{ width: `${Math.min(100, (usage.users / Math.max(1, maxUsers)) * 100)}%` }}
              />
            </div>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Protect my browser"
          subtitle="One-time codes let your developers connect their extension with zero manual setup — no URL or keys to paste. Connected devices report heartbeats; a stopped heartbeat shows as 'protection off'."
        />
        <div className="space-y-6">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={generateJoinCode} disabled={orgBusy}>
                {orgBusy ? 'Generating…' : 'Generate org code'}
              </Button>
              {joinCode ? (
                <>
                  <code className="rounded-lg border border-line bg-navy px-4 py-2 text-xl font-extrabold tracking-[0.3em] text-warning">
                    {joinCode}
                  </code>
                  <Button variant="outline" onClick={() => copy(joinCode, 'code')}>
                    {copied === 'code' ? '✓ Copied' : 'Copy'}
                  </Button>
                  <span className="text-xs text-muted">Single use · expires {codeExpiry}</span>
                </>
              ) : null}
            </div>
            {orgMsg ? <p className={"mt-2 text-sm " + (orgMsgError ? 'text-accent' : 'text-emerald-400')}>{orgMsg}</p> : null}
            <p className="mt-2 text-xs text-muted">
              Give this code to one developer. They paste it into the extension popup →
              <b> Protect this browser</b>. Codes are single-use and expire after an hour.
            </p>
          </div>

          <div>
            <h3 className="mb-2 text-sm font-bold text-white">Connected devices</h3>
            {devices.length === 0 ? (
              <p className="text-xs text-muted">No extensions connected yet.</p>
            ) : (
              <div className="overflow-hidden rounded-lg border border-line">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy text-muted">
                    <tr>
                      <th className="px-3 py-2">User</th>
                      <th className="px-3 py-2">Device</th>
                      <th className="px-3 py-2">Last seen</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {devices.map((d) => {
                      const revoked = !!d.revoked_at;
                      const lastSeen = d.last_seen_at
                        ? new Date(d.last_seen_at).toLocaleString()
                        : '—';
                      const stale = !revoked && d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() > 10 * 60 * 1000;
                      return (
                        <tr key={d.id} className="text-soft">
                          <td className="px-3 py-2">{d.user_email}</td>
                          <td className="px-3 py-2">{d.device_name || '—'}</td>
                          <td className="px-3 py-2">{lastSeen}</td>
                          <td className="px-3 py-2">
                            {revoked ? (
                              <Badge tone="red">Revoked</Badge>
                            ) : stale ? (
                              <Badge tone="amber">Protection off</Badge>
                            ) : (
                              <Badge tone="green">Active</Badge>
                            )}
                          </td>
                          <td className="px-3 py-2 text-right">
                            {!revoked ? (
                              <button
                                className="text-xs font-bold text-accent hover:underline cursor-pointer"
                                onClick={() => revokeDevice(d.id)}
                              >
                                Revoke
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <p className="mt-2 text-xs text-muted">
              A device is flagged <b>Protection off</b> when no heartbeat has arrived for
              10+ minutes — a sign the user disabled or removed the extension.
            </p>
          </div>

          <form onSubmit={savePolicy} className="space-y-3">
            <h3 className="text-sm font-bold text-white">Org policy</h3>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <Input
                  label="Modal warning threshold (0–1)"
                  value={warnThreshold}
                  onChange={(e) => setWarnThreshold(e.target.value)}
                />
                <p className="mt-1 text-[11px] text-muted">
                  Confidence at/above which the modal warning shows. Default 0.7.
                </p>
              </div>
              <div>
                <Input
                  label="Critical block threshold (0–1)"
                  value={blockThreshold}
                  onChange={(e) => setBlockThreshold(e.target.value)}
                />
                <p className="mt-1 text-[11px] text-muted">
                  Confidence at/above which the send is blocked (3s lockout). Default 0.9.
                </p>
              </div>
            </div>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-soft">
              <input
                type="checkbox"
                checked={monitorOnly}
                onChange={(e) => setMonitorOnly(e.target.checked)}
                className="h-4 w-4 accent-[#e94560]"
              />
              Monitor-only mode — observe and log everything, never block or warn
            </label>
            <Button type="submit" disabled={orgBusy}>
              {orgBusy ? 'Saving…' : 'Save policy'}
            </Button>
            <span className="ml-3 text-xs text-muted">
              Changes reach connected extensions within ~3 minutes (config poll).
            </span>
          </form>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Extension download"
          subtitle="Install PromptGuard on your developers' browsers"
        />
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" onClick={() => copy('https://chrome.google.com/webstore (coming soon)', 'ext')}>
            {copied === 'ext' ? '✓ Link copied' : 'Chrome Web Store link'}
          </Button>
          <span className="text-xs text-muted">
            Until published: zip the <code className="text-warning">extension/</code> folder and load
            it unpacked via chrome://extensions.
          </span>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Extension API key"
          subtitle="Paste these into the PromptGuard browser extension popup to connect it to this dashboard"
        />
        <div className="space-y-4">
          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-semibold text-muted">Supabase URL</span>
              <button
                className="text-xs font-bold text-accent hover:underline cursor-pointer"
                onClick={() => copy(supabaseUrl, 'url')}
              >
                {copied === 'url' ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
            <code className="block break-all rounded-lg border border-line bg-navy px-3 py-2 text-xs text-soft">
              {supabaseUrl || '—'}
            </code>
          </div>

          <div className="rounded-lg border border-line bg-navy/60 p-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-semibold text-warning">Refresh token — recommended for the extension</span>
              <button
                className="text-xs font-bold text-accent hover:underline cursor-pointer"
                onClick={() => copy(refreshToken, 'refresh')}
              >
                {copied === 'refresh' ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
            <code className="block break-all rounded-lg border border-line bg-navy px-3 py-2 text-xs text-soft">
              {refreshToken ? refreshToken.slice(0, 60) + '…' : '—'}
            </code>
            <p className="mt-2 text-xs text-muted">
              Paste this into the extension's <b>Refresh token</b> field. It stays valid long-term,
              and the extension automatically exchanges it for fresh access tokens (no more
              "JWT expired" errors). Single-use — the extension stores the rotated token after
              each use, so if you ever clear extension storage, copy it again from here.
            </p>
          </div>

          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-semibold text-muted">Session JWT (expires after ~1 hour)</span>
              <button
                className="text-xs font-bold text-accent hover:underline cursor-pointer"
                onClick={() => copy(apiKey, 'key')}
              >
                {copied === 'key' ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
            <code className="block break-all rounded-lg border border-line bg-navy px-3 py-2 text-xs text-soft">
              {apiKey ? apiKey.slice(0, 60) + '…' : '—'}
            </code>
            <p className="mt-2 text-xs text-muted">
              Signed in as <span className="text-soft">{profile ? profile.email : ''}</span>. The
              anon key comes from Supabase Project Settings → API.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}

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

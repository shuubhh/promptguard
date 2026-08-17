import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { useApp } from '../lib/AppContext';
import { createOrganisation } from '../lib/api';
import { Button, Card, Input, Spinner } from './ui';

const NAV = [
  { to: '/', label: 'Dashboard', icon: '📊', end: true },
  { to: '/events', label: 'Events', icon: '📋' },
  { to: '/projects', label: 'Projects', icon: '🗂️' },
  { to: '/team', label: 'Team', icon: '👥' },
  { to: '/settings', label: 'Settings', icon: '⚙️' }
];

export default function Layout() {
  const { profile, org, user, loading, reload } = useApp();
  const navigate = useNavigate();
  const [orgName, setOrgName] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  async function handleLogout() {
    await supabase.auth.signOut();
    navigate('/login');
  }

  async function handleCreateOrg(e) {
    e.preventDefault();
    if (!orgName.trim()) return;
    setCreating(true);
    setError('');
    try {
      await createOrganisation(orgName.trim());
      await reload();
    } catch (err) {
      setError(err && err.message ? err.message : 'Failed to create organisation');
    } finally {
      setCreating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner label="Loading workspace…" />
      </div>
    );
  }

  // First login: prompt for an organisation name (brief: "On first signup:
  // create organisation, prompt for org name"). Only shown when the signed-in
  // account genuinely has no org attached.
  if (!profile || !profile.org_id) {
    return (
      <div className="flex h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <div className="mb-4 text-center text-3xl">🛡️</div>
          <h1 className="text-center text-xl font-bold text-white">Create your organisation</h1>
          <p className="mt-1 text-center text-sm text-muted">
            This groups your projects, team and audit events.
          </p>
          <p className="mt-3 text-center text-xs text-muted">
            Signed in as <span className="font-semibold text-soft">{user ? user.email : '…'}</span>.
            If this account already has an organisation, this screen should not appear —
            sign out and back in to re-load it.
          </p>
          <form onSubmit={handleCreateOrg} className="mt-6 space-y-4">
            <Input
              label="Organisation name"
              placeholder="Acme IT Services Pvt Ltd"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              autoFocus
            />
            {error ? <p className="text-sm text-accent">{error}</p> : null}
            <Button type="submit" disabled={creating || !orgName.trim()} className="w-full">
              {creating ? 'Creating…' : 'Create organisation'}
            </Button>
          </form>
        </Card>
      </div>
    );
  }

  const email = profile.email || profile.full_name || '';

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="flex w-60 flex-col border-r border-line bg-navy">
        <div className="flex items-center gap-2 border-b border-line px-5 py-4">
          <span className="text-2xl">🛡️</span>
          <div>
            <p className="text-sm font-extrabold text-white">PromptGuard</p>
            <p className="text-[11px] text-muted">{org ? org.name : ''}</p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto p-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${
                  isActive ? 'bg-accent/15 text-accent' : 'text-muted hover:bg-white/5 hover:text-white'
                }`
              }
            >
              <span>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line p-3">
          <div className="flex items-center gap-2 px-1 py-1">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-accent text-xs font-bold text-white">
              {(email || '?').slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-semibold text-soft">{email}</p>
              <p className="text-[11px] capitalize text-muted">{profile.role || 'developer'}</p>
            </div>
          </div>
          <Button variant="ghost" className="mt-2 w-full" onClick={handleLogout}>
            Sign out
          </Button>
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}

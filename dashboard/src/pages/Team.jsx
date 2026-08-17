import { useEffect, useState } from 'react';
import { useApp } from '../lib/AppContext';
import { getInvites, getTeam, inviteMember } from '../lib/api';
import { Badge, Button, Card, EmptyState, Input, Select, Spinner, formatTime } from '../components/ui';

export default function Team() {
  const { org, profile } = useApp();
  const orgId = org ? org.id : null;
  const isOwner = profile && profile.role === 'owner';

  const [members, setMembers] = useState([]);
  const [invites, setInvites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [email, setEmail] = useState('');
  const [role, setRole] = useState('developer');
  const [sending, setSending] = useState(false);
  const [notice, setNotice] = useState('');

  async function refresh() {
    if (!orgId) return;
    setLoading(true);
    setError('');
    try {
      const [rows, inviteRows] = await Promise.all([getTeam(orgId), getInvites(orgId)]);
      setMembers(rows);
      setInvites(inviteRows);
    } catch (err) {
      setError(err && err.message ? err.message : 'Failed to load team');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  async function handleInvite(e) {
    e.preventDefault();
    if (!email.trim() || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) {
      setError('Enter a valid work email');
      return;
    }
    setSending(true);
    setError('');
    setNotice('');
    try {
      await inviteMember(orgId, email.trim(), role);
      setEmail('');
      setNotice('Invite recorded for ' + email.trim() + '. Email delivery is a v2 feature.');
      refresh();
    } catch (err) {
      setError(err && err.message ? err.message : 'Failed to send invite');
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white">Team</h1>
        <p className="mt-1 text-sm text-muted">
          {members.length} member(s) in {org ? org.name : 'your org'}
        </p>
      </div>

      {error ? <p className="text-accent">{error}</p> : null}
      {notice ? <p className="text-sm text-emerald-400">{notice}</p> : null}

      {isOwner ? (
        <Card>
          <h3 className="mb-3 text-base font-bold text-white">Invite member</h3>
          <form onSubmit={handleInvite} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[220px] flex-1">
              <Input
                label="Email"
                type="email"
                placeholder="dev@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="w-40">
              <Select label="Role" value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="developer">Developer</option>
                <option value="admin">Admin</option>
                <option value="owner">Owner</option>
              </Select>
            </div>
            <Button type="submit" disabled={sending}>
              {sending ? 'Sending…' : 'Invite'}
            </Button>
          </form>
          <p className="mt-3 text-xs text-muted">
            Admin can manage projects · Developer is read-only. Email delivery ships with the
            invite pipeline in v2.
          </p>
        </Card>
      ) : null}

      {loading ? <Spinner label="Loading team…" /> : null}

      {!loading ? (
        members.length === 0 ? (
          <EmptyState title="No members yet" hint="Invite your first team member." />
        ) : (
          <Card className="overflow-x-auto p-0">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wide text-muted">
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Last active</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id} className="border-b border-line/60 hover:bg-white/[0.02]">
                    <td className="px-4 py-3 font-semibold text-soft">{m.full_name || '—'}</td>
                    <td className="px-4 py-3">{m.email || '—'}</td>
                    <td className="px-4 py-3">
                      <Badge tone={m.role === 'owner' ? 'red' : m.role === 'admin' ? 'amber' : 'neutral'}>
                        {m.role || 'developer'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-muted">—</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )
      ) : null}

      {!loading && invites.length > 0 ? (
        <Card>
          <h3 className="mb-3 text-base font-bold text-white">Pending invites</h3>
          <div className="space-y-2">
            {invites.map((inv) => (
              <div key={inv.id} className="flex items-center justify-between rounded-lg border border-line bg-navy px-3 py-2">
                <div>
                  <p className="text-sm font-semibold text-soft">{inv.email}</p>
                  <p className="text-[11px] text-muted">{formatTime(inv.created_at)}</p>
                </div>
                <Badge tone="amber">{inv.status}</Badge>
              </div>
            ))}
          </div>
        </Card>
      ) : null}
    </div>
  );
}

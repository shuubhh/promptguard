import { useEffect, useMemo, useState } from 'react';
import { useApp } from '../lib/AppContext';
import { getEvents, getProjects } from '../lib/api';
import { Badge, Button, Card, EmptyState, Input, Select, Spinner, formatTime } from '../components/ui';

const EVENT_TYPES = ['all', 'silent', 'warned', 'override', 'redacted', 'blocked'];

export default function Events() {
  const { org } = useApp();
  const orgId = org ? org.id : null;

  const [events, setEvents] = useState([]);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState(null);

  // Filters
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [projectId, setProjectId] = useState('');
  const [eventType, setEventType] = useState('all');
  const [userEmail, setUserEmail] = useState('');
  // Diagnostic "Test Connection" probe events are hidden by default — they
  // aren't real audit entries. Toggle to inspect them.
  const [showTestEvents, setShowTestEvents] = useState(false);

  useEffect(() => {
    if (!orgId) return;
    getProjects(orgId)
      .then(setProjects)
      .catch(() => {});
  }, [orgId]);

  useEffect(() => {
    if (!orgId) return;
    let mounted = true;
    setLoading(true);
    setError('');
    getEvents(orgId, {
      from: from || undefined,
      to: to ? new Date(new Date(to).getTime() + 24 * 60 * 60 * 1000).toISOString() : undefined,
      projectId: projectId || undefined,
      eventType: eventType === 'all' ? undefined : eventType,
      userEmail: userEmail || undefined
    })
      .then((rows) => {
        if (mounted) setEvents(rows);
      })
      .catch((err) => {
        if (mounted) setError(err && err.message ? err.message : 'Failed to load events');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [orgId, from, to, projectId, eventType, userEmail]);

  const projectName = useMemo(() => {
    const map = {};
    for (const p of projects) map[p.id] = p.name;
    return map;
  }, [projects]);

  const visibleEvents = useMemo(() => {
    return showTestEvents ? events : events.filter((ev) => ev.match_type !== 'connection_test');
  }, [events, showTestEvents]);

  function exportCsv() {
    const header = ['Timestamp', 'User', 'Platform', 'Match Type', 'Match Preview', 'Confidence', 'Action Taken'];
    const lines = visibleEvents.map((ev) =>
      [
        ev.timestamp || '',
        ev.user_email || '',
        ev.platform || '',
        ev.match_type || '',
        (ev.match_preview || '').replace(/"/g, '""'),
        ev.confidence != null ? String(Math.round(ev.confidence * 100)) + '%' : '',
        ev.event_type || ''
      ]
        .map((v) => `"${v}"`)
        .join(',')
    );
    const csv = [header.map((h) => `"${h}"`).join(','), ...lines].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'promptguard-events.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold text-white">Events / Audit Log</h1>
          <p className="mt-1 text-sm text-muted">
            {visibleEvents.length} event(s) matching the filters
          </p>
        </div>
        <div className="flex items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
            <input
              type="checkbox"
              checked={showTestEvents}
              onChange={(e) => setShowTestEvents(e.target.checked)}
              className="accent-[#e94560]"
            />
            Show test events
          </label>
          <Button variant="outline" onClick={exportCsv} disabled={visibleEvents.length === 0}>
            ⬇ Export CSV
          </Button>
        </div>
      </div>

      <Card>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
          <Input label="From" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
          <Input label="To" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
          <Select label="Project" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
          <Select label="Event type" value={eventType} onChange={(e) => setEventType(e.target.value)}>
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </Select>
          <Input
            label="User email"
            placeholder="dev@company.com"
            value={userEmail}
            onChange={(e) => setUserEmail(e.target.value)}
          />
        </div>
      </Card>

      {error ? <p className="text-accent">{error}</p> : null}
      {loading ? <Spinner label="Loading events…" /> : null}

      {!loading && !error ? (
        visibleEvents.length === 0 ? (
          <EmptyState title="No events match" hint="Adjust the filters or send a prompt from the extension." />
        ) : (
          <Card className="overflow-x-auto p-0">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wide text-muted">
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Platform</th>
                  <th className="px-4 py-3">Match Type</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Action Taken</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {visibleEvents.map((ev, i) => (
                  <EventRow
                    key={ev.id || i}
                    ev={ev}
                    projectName={projectName[ev.project_id] || '—'}
                    expanded={expanded === i}
                    onToggle={() => setExpanded(expanded === i ? null : i)}
                  />
                ))}
              </tbody>
            </table>
          </Card>
        )
      ) : null}
    </div>
  );
}

function EventRow({ ev, projectName, expanded, onToggle }) {
  return (
    <>
      <tr className="border-b border-line/60 hover:bg-white/[0.02]">
        <td className="whitespace-nowrap px-4 py-3 text-muted">{formatTime(ev.timestamp)}</td>
        <td className="px-4 py-3">{ev.user_email || '—'}</td>
        <td className="px-4 py-3 capitalize">{ev.platform || '—'}</td>
        <td className="px-4 py-3">{ev.match_label || ev.match_type || '—'}</td>
        <td className="px-4 py-3 font-semibold">{Math.round((ev.confidence || 0) * 100)}%</td>
        <td className="px-4 py-3">
          <Badge tone={badgeTone(ev.event_type)}>{ev.event_type}</Badge>
        </td>
        <td className="px-4 py-3 text-right">
          <button onClick={onToggle} className="text-xs font-bold text-muted hover:text-white cursor-pointer">
            {expanded ? 'Hide ▲' : 'Detail ▼'}
          </button>
        </td>
      </tr>
      {expanded ? (
        <tr className="border-b border-line/60 bg-navy/60">
          <td colSpan={7} className="px-4 py-3">
            <div className="grid gap-2 text-xs md:grid-cols-2">
              <div>
                <p className="font-bold text-muted">Project</p>
                <p className="text-soft">{projectName}</p>
              </div>
              <div>
                <p className="font-bold text-muted">Matched projects</p>
                <p className="text-soft">
                  {ev.matched_projects && ev.matched_projects.length
                    ? ev.matched_projects.join(', ')
                    : '—'}
                </p>
              </div>
              <div>
                <p className="font-bold text-muted">Match preview</p>
                <p className="break-all font-mono text-accent">{ev.match_preview || '—'}</p>
              </div>
              <div>
                <p className="font-bold text-muted">Regex / AI</p>
                <p className="text-soft">
                  {ev.regex_score != null ? Math.round(ev.regex_score * 100) + '% regex' : '—'}
                  {ev.ai_label ? ' · AI: ' + ev.ai_label : ''}
                </p>
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function badgeTone(type) {
  if (type === 'blocked') return 'red';
  if (type === 'silent') return 'green';
  return 'amber';
}

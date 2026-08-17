import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../lib/AppContext';
import { getEventsForChart, getEventsToday, getProjects, getEvents, getTeam } from '../lib/api';
import { Badge, Card, CardHeader, EmptyState, Spinner, formatTime } from '../components/ui';

function StatCard({ label, value, tone = '' }) {
  return (
    <Card className="flex items-center justify-between p-4">
      <div>
        <p className="text-xs font-semibold text-muted">{label}</p>
        <p className="mt-1 text-2xl font-extrabold text-white">{value}</p>
      </div>
      <span className={`text-2xl ${tone}`}>{tone === '' ? '' : '•'}</span>
    </Card>
  );
}

export default function DashboardHome() {
  const { profile, org } = useApp();
  const [stats, setStats] = useState(null);
  const [chart, setChart] = useState([]);
  const [recent, setRecent] = useState([]);
  const [projects, setProjects] = useState([]);
  const [teamCount, setTeamCount] = useState(0);
  const [error, setError] = useState('');

  const orgId = org ? org.id : null;

  useEffect(() => {
    if (!orgId) return;
    let mounted = true;
    (async () => {
      try {
        const [today, chartData, recentData, projectList, team] = await Promise.all([
          getEventsToday(orgId),
          getEventsForChart(orgId),
          getEvents(orgId, {}),
          getProjects(orgId),
          getTeam(orgId)
        ]);
        if (!mounted) return;
        const blocked = today.filter((e) => e.event_type === 'blocked').length;
        const flagged = today.filter((e) => e.event_type !== 'silent').length;
        setStats({
          eventsToday: today.length,
          blockedToday: blocked,
          flaggedToday: flagged,
          safeToday: today.length - flagged
        });
        setChart(buildWeeklyChart(chartData));
        setRecent(recentData.slice(0, 10));
        setProjects(projectList);
        setTeamCount(team.length);
      } catch (err) {
        if (mounted) setError(err && err.message ? err.message : 'Failed to load dashboard');
      }
    })();
    return () => {
      mounted = false;
    };
  }, [orgId]);

  const latestScanAlert = useMemo(() => {
    for (const p of projects) {
      if (
        p.fingerprint &&
        Array.isArray(p.fingerprint.secrets_found) &&
        p.fingerprint.secrets_found.length > 0
      ) {
        return p;
      }
    }
    return null;
  }, [projects]);

  if (!orgId) return null;
  if (error) return <p className="text-accent">{error}</p>;
  if (!stats) return <Spinner label="Loading dashboard…" />;

  const firstName = (profile && profile.full_name ? profile.full_name : profile.email || '').split(' ')[0];
  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  const maxBar = Math.max(1, ...chart.map((d) => Math.max(d.flagged, d.allowed)));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white">
          {greeting}, {firstName} <span className="text-muted">— {org ? org.name : ''}</span>
        </h1>
        <p className="mt-1 text-sm text-muted">
          {stats.flaggedToday} flagged · {stats.blockedToday} blocked today
          (silent scans stay in the extension, not the dashboard)
        </p>
      </div>

      {latestScanAlert ? (
        <div className="flex items-center gap-3 rounded-xl border border-warning/50 bg-warning/10 p-4">
          <span className="text-2xl">⚠️</span>
          <div className="flex-1">
            <p className="text-sm font-bold text-warning">
              Secrets were found in the latest scan of "{latestScanAlert.name}"
            </p>
            <p className="text-xs text-muted">
              {latestScanAlert.fingerprint.secrets_found.length} finding(s). Review and rotate before
              deploying to the team.
            </p>
          </div>
          <Link to="/projects" className="text-xs font-bold text-warning underline">
            Review
          </Link>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Events today" value={stats.eventsToday} />
        <StatCard label="Blocked today" value={stats.blockedToday} />
        <StatCard label="Active projects" value={projects.length} />
        <StatCard label="Team members" value={teamCount} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Last 7 days — flagged vs allowed"
            subtitle="Events from the extension across all platforms"
          />
          <div className="flex h-48 items-end gap-2">
            {chart.map((d) => (
              <div key={d.date} className="flex flex-1 flex-col items-center gap-1">
                <div className="flex w-full flex-1 items-end justify-center gap-1">
                  <div
                    className="w-3 rounded-t bg-accent/80"
                    style={{ height: `${(d.flagged / maxBar) * 100}%` }}
                    title={`Flagged: ${d.flagged}`}
                  />
                  <div
                    className="w-3 rounded-t bg-emerald-500/50"
                    style={{ height: `${(d.allowed / maxBar) * 100}%` }}
                    title={`Allowed: ${d.allowed}`}
                  />
                </div>
                <span className="text-[10px] text-muted">{d.label}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 flex items-center gap-4 text-xs text-muted">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-accent/80" /> Flagged
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-emerald-500/50" /> Allowed
            </span>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Recent events"
            subtitle="Latest 10 events from the extension"
            action={
              <Link to="/events" className="text-xs font-bold text-accent hover:underline">
                View all →
              </Link>
            }
          />
          {recent.length === 0 ? (
            <EmptyState title="No events yet" hint="Send a prompt from the extension to see events here." />
          ) : (
            <div className="space-y-2">
              {recent.map((ev, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-3 rounded-lg border border-line bg-navy px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-soft">
                      {ev.match_label || ev.match_type || 'scan'}
                    </p>
                    <p className="text-[11px] text-muted">
                      {ev.platform || '—'} · {formatTime(ev.timestamp)}
                    </p>
                  </div>
                  <Badge tone={badgeTone(ev.event_type)}>{ev.event_type}</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function buildWeeklyChart(events) {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    d.setHours(0, 0, 0, 0);
    const key = d.toISOString().slice(0, 10);
    days.push({ date: key, label: d.toLocaleDateString([], { weekday: 'short' }), flagged: 0, allowed: 0 });
  }
  const map = new Map(days.map((d) => [d.date, d]));
  for (const ev of events) {
    const key = (ev.timestamp || '').slice(0, 10);
    const day = map.get(key);
    if (!day) continue;
    if (ev.event_type === 'silent') day.allowed += 1;
    else day.flagged += 1;
  }
  return days;
}

function badgeTone(type) {
  if (type === 'blocked') return 'red';
  if (type === 'silent') return 'green';
  return 'amber';
}

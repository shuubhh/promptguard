import { useEffect, useState } from 'react';
import { useApp } from '../lib/AppContext';
import { createProject, getProjects, getTeam } from '../lib/api';
import { Badge, Button, Card, EmptyState, Input, Modal, Spinner, formatTime } from '../components/ui';

export default function Projects() {
  const { org } = useApp();
  const orgId = org ? org.id : null;

  const [projects, setProjects] = useState([]);
  const [teamCount, setTeamCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Add-project modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [fileName, setFileName] = useState('');
  const [fingerprint, setFingerprint] = useState(null);
  const [repoUrl, setRepoUrl] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  async function refresh() {
    if (!orgId) return;
    setLoading(true);
    setError('');
    try {
      const [rows, team] = await Promise.all([getProjects(orgId), getTeam(orgId)]);
      setProjects(rows);
      setTeamCount(team.length);
    } catch (err) {
      setError(err && err.message ? err.message : 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  function handleFile(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.packages)) {
          setFingerprint(null);
          setFormError('Invalid fingerprint.json — missing "packages" array');
          return;
        }
        setFingerprint(parsed);
        setFormError('');
      } catch (err) {
        setFingerprint(null);
        setFormError('Could not parse JSON: ' + (err && err.message ? err.message : err));
      }
    };
    reader.readAsText(file);
  }

  async function handleAdd(e) {
    e.preventDefault();
    if (!name.trim()) {
      setFormError('Project name is required');
      return;
    }
    if (!fingerprint) {
      setFormError('Upload a fingerprint.json first');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      await createProject(orgId, name.trim(), fingerprint);
      setModalOpen(false);
      setName('');
      setFileName('');
      setFingerprint(null);
      setRepoUrl('');
      refresh();
    } catch (err) {
      setFormError(err && err.message ? err.message : 'Failed to create project');
    } finally {
      setSaving(false);
    }
  }

  async function handleDeploy(projectId) {
    const link = window.location.origin + '/login';
    try {
      await navigator.clipboard.writeText(link);
      setCopiedId(projectId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      setFormError('Could not copy link');
    }
  }

  function countPatterns(fp) {
    if (!fp) return 0;
    return (
      (fp.packages || []).length +
      (fp.class_names || []).length +
      (fp.domain_vocabulary || []).length +
      (fp.internal_urls || []).length +
      (fp.internal_ips || []).length
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold text-white">Projects</h1>
          <p className="mt-1 text-sm text-muted">Client codebases fingerprinted for DLP scanning</p>
        </div>
        <Button onClick={() => setModalOpen(true)}>+ Add Project</Button>
      </div>

      {error ? <p className="text-accent">{error}</p> : null}
      {loading ? <Spinner label="Loading projects…" /> : null}

      {!loading && !error ? (
        projects.length === 0 ? (
          <EmptyState
            title="No projects yet"
            hint="Add your first client project by uploading its fingerprint.json (from the Python scanner)."
          />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {projects.map((p) => (
              <Card key={p.id} className="flex flex-col">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="truncate text-base font-bold text-white">{p.name}</h3>
                    <p className="mt-0.5 text-xs text-muted">
                      Last scanned: {formatTime(p.last_scanned_at)}
                    </p>
                  </div>
                  <span className="text-xl">🗂️</span>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <Badge tone="blue">{countPatterns(p.fingerprint)} patterns</Badge>
                  <Badge tone="neutral">{teamCount} users</Badge>
                  {p.fingerprint && Array.isArray(p.fingerprint.secrets_found) && p.fingerprint.secrets_found.length > 0 ? (
                    <Badge tone="red">{p.fingerprint.secrets_found.length} secrets</Badge>
                  ) : null}
                </div>

                <div className="mt-auto pt-4">
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => handleDeploy(p.id)}
                  >
                    {copiedId === p.id ? '✓ Invite link copied' : 'Deploy to Team →'}
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )
      ) : null}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Add Project">
        <form onSubmit={handleAdd} className="space-y-4">
          <Input
            label="Project name"
            placeholder="HDFC Wealth Platform"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />

          <div>
            <span className="mb-1.5 block text-xs font-semibold text-muted">Fingerprint file</span>
            <label className="block cursor-pointer rounded-lg border border-dashed border-line bg-navy px-4 py-6 text-center transition-colors hover:border-accent">
              <input type="file" accept=".json,application/json" className="hidden" onChange={handleFile} />
              <p className="text-sm font-semibold text-soft">
                {fileName || 'Click to upload fingerprint.json'}
              </p>
              <p className="mt-1 text-xs text-muted">Generated by the Python scanner (Component 1)</p>
            </label>
          </div>

          <div>
            <span className="mb-1.5 block text-xs font-semibold text-muted">Or scan from a repository</span>
            <Input
              placeholder="https://gitlab.com/org/repo.git (coming soon)"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled
            />
            <p className="mt-1 text-xs text-warning">Repo scanning is a v2 feature — upload the fingerprint for now.</p>
          </div>

          {formError ? <p className="text-sm text-accent">{formError}</p> : null}

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? 'Saving…' : 'Add project'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

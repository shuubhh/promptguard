import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { Button, Card, Input } from '../components/ui';

export default function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState('login'); // 'login' | 'signup'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      if (mode === 'signup') {
        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: { data: { full_name: fullName.trim() || email } }
        });
        if (error) throw error;
        // If email confirmation is enabled Supabase returns a session-less
        // user; if not, we land straight in the dashboard.
        setNotice('Account created. Check your inbox for a confirmation link, then sign in.');
        const { data } = await supabase.auth.getSession();
        if (data.session) navigate('/');
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        navigate('/');
      }
    } catch (err) {
      setError(err && err.message ? err.message : 'Authentication failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-screen items-center justify-center p-4" style={{ background: '#16213e' }}>
      <Card className="w-full max-w-md">
        <div className="mb-1 text-center text-4xl">🛡️</div>
        <h1 className="text-center text-2xl font-extrabold text-white">PromptGuard</h1>
        <p className="mb-6 text-center text-sm text-muted">Keep client code out of the cloud</p>

        <div className="mb-5 grid grid-cols-2 rounded-lg border border-line bg-navy p-1">
          {['login', 'signup'].map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setError('');
                setNotice('');
              }}
              className={`rounded-md py-2 text-sm font-bold transition-colors cursor-pointer ${
                mode === m ? 'bg-accent text-white' : 'text-muted hover:text-white'
              }`}
            >
              {m === 'login' ? 'Sign in' : 'Sign up'}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'signup' ? (
            <Input
              label="Full name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Ada Lovelace"
            />
          ) : null}
          <Input
            label="Work email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="dev@company.com"
          />
          <Input
            label="Password"
            type="password"
            required
            minLength={6}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
          />

          {error ? <p className="text-sm text-accent">{error}</p> : null}
          {notice ? <p className="text-sm text-emerald-400">{notice}</p> : null}

          <Button type="submit" disabled={busy} className="w-full">
            {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </Button>
        </form>
      </Card>
    </div>
  );
}

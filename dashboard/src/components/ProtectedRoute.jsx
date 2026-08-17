import { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { supabase, isSupabaseConfigured } from '../lib/supabase';
import { Button, Card } from './ui';

export default function ProtectedRoute({ children }) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isSupabaseConfigured()) {
      setLoading(false);
      return undefined;
    }
    let mounted = true;
    supabase.auth
      .getSession()
      .then(({ data }) => {
        if (mounted) {
          setSession(data.session);
          setLoading(false);
        }
      })
      .catch(() => {
        if (mounted) setLoading(false);
      });

    const { data: sub } = supabase.auth.onAuthStateChange((_event, s) => {
      if (mounted) {
        setSession(s);
        setLoading(false);
      }
    });
    return () => {
      mounted = false;
      if (sub && sub.subscription) sub.subscription.unsubscribe();
    };
  }, []);

  if (!isSupabaseConfigured()) {
    return (
      <div className="flex h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md text-center">
          <div className="text-3xl">🛡️</div>
          <h1 className="mt-2 text-lg font-bold text-white">Supabase not configured</h1>
          <p className="mt-2 text-sm text-muted">
            Copy <code className="text-warning">.env.example</code> to{' '}
            <code className="text-warning">.env</code> and fill in your Supabase project URL and
            anon key, then run the SQL in <code className="text-warning">supabase/schema.sql</code>.
          </p>
          <a
            href="https://supabase.com/docs/guides/getting-started"
            target="_blank"
            rel="noreferrer"
            className="mt-4 inline-block"
          >
            <Button variant="outline">Supabase setup guide</Button>
          </a>
        </Card>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center text-muted">
        <span className="mr-3 inline-block h-5 w-5 animate-spin rounded-full border-2 border-muted border-t-accent" />
        Checking session…
      </div>
    );
  }

  if (!session) return <Navigate to="/login" replace />;
  return children;
}

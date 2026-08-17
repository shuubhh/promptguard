import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { supabase } from './supabase';
import { getMyProfile, getOrg } from './api';

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [profile, setProfile] = useState(null);
  const [org, setOrg] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    try {
      const { data: { user: u } } = await supabase.auth.getUser();
      setUser(u || null);
      const p = await getMyProfile();
      setProfile(p);
      if (p && p.org_id) {
        const o = await getOrg(p.org_id);
        setOrg(o);
      } else {
        setOrg(null);
      }
    } catch (err) {
      console.error('Failed to load profile/org', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial load…
    reload();

    // …and reload whenever the auth session changes. Without this, the app
    // fetched the profile once at mount (while signed out → null) and never
    // again, so signing in with an EXISTING org still showed the
    // "Create your organisation" screen. SIGNED_IN must re-fetch.
    const { data: sub } = supabase.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_IN') {
        setLoading(true);
        reload();
      } else if (event === 'SIGNED_OUT') {
        setProfile(null);
        setOrg(null);
        setUser(null);
        setLoading(false);
      }
    });
    return () => {
      if (sub && sub.subscription) sub.subscription.unsubscribe();
    };
  }, [reload]);

  return (
    <AppContext.Provider value={{ profile, org, user, loading, reload }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}

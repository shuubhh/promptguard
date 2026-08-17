import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { getMyProfile, getOrg } from './api';

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [profile, setProfile] = useState(null);
  const [org, setOrg] = useState(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    try {
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
    reload();
  }, [reload]);

  return (
    <AppContext.Provider value={{ profile, org, loading, reload }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}

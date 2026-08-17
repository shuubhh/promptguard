import { createClient } from '@supabase/supabase-js';

// supabase-js throws synchronously if the URL is empty, which would crash
// module evaluation before the app can show its "not configured" screen.
// Use a placeholder so the client is always constructible; every real call
// is gated behind isSupabaseConfigured().
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'public-anon-key-placeholder';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export function isSupabaseConfigured() {
  return Boolean(
    supabaseUrl &&
      supabaseAnonKey &&
      supabaseUrl !== 'https://placeholder.supabase.co' &&
      !supabaseUrl.includes('your-project') &&
      supabaseAnonKey !== 'public-anon-key-placeholder'
  );
}

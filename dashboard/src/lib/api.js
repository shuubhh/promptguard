import { supabase } from './supabase';

// ------------------------------------------------------------------
// Profiles / orgs
// ------------------------------------------------------------------
export async function getMyProfile() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;
  const { data, error } = await supabase
    .from('user_profiles')
    .select('*')
    .eq('id', user.id)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function getOrg(orgId) {
  const { data, error } = await supabase
    .from('organisations')
    .select('*')
    .eq('id', orgId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

// Atomic first-login org creation: the security-definer RPC
// (supabase/migrations/002_org_creation_rpc.sql) creates the org AND attaches
// the calling user as owner in one transaction, so RLS never blocks reading
// back the brand-new org.
export async function createOrganisation(name) {
  const { data, error } = await supabase.rpc('create_organisation_with_owner', {
    org_name: name
  });
  if (error) throw error;
  return data;
}

export async function updateOrganisation(orgId, name) {
  const { data, error } = await supabase
    .from('organisations')
    .update({ name })
    .eq('id', orgId)
    .select()
    .single();
  if (error) throw error;
  return data;
}

// ------------------------------------------------------------------
// Projects
// ------------------------------------------------------------------
export async function getProjects(orgId) {
  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('org_id', orgId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data || [];
}

export async function createProject(orgId, name, fingerprint) {
  const { data, error } = await supabase
    .from('projects')
    .insert({ org_id: orgId, name, fingerprint })
    .select()
    .single();
  if (error) throw error;
  return data;
}

// ------------------------------------------------------------------
// Events
// ------------------------------------------------------------------
export async function getEvents(orgId, { from, to, projectId, eventType, userEmail } = {}) {
  let query = supabase
    .from('events')
    .select('*')
    .eq('org_id', orgId)
    .order('timestamp', { ascending: false })
    .limit(1000);

  if (from) query = query.gte('timestamp', from);
  if (to) query = query.lte('timestamp', to);
  if (projectId) query = query.eq('project_id', projectId);
  if (eventType) query = query.eq('event_type', eventType);
  if (userEmail) query = query.ilike('user_email', '%' + userEmail + '%');

  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

export async function getEventsForChart(orgId) {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await supabase
    .from('events')
    .select('timestamp,event_type')
    .eq('org_id', orgId)
    .neq('match_type', 'connection_test')
    .gte('timestamp', sevenDaysAgo)
    .order('timestamp', { ascending: true })
    .limit(10000);
  if (error) throw error;
  return data || [];
}

export async function getEventsToday(orgId) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const { data, error } = await supabase
    .from('events')
    .select('event_type,confidence')
    .eq('org_id', orgId)
    .neq('match_type', 'connection_test')
    .gte('timestamp', startOfDay.toISOString())
    .limit(10000);
  if (error) throw error;
  return data || [];
}

// ------------------------------------------------------------------
// Team + invites
// ------------------------------------------------------------------
export async function getTeam(orgId) {
  const { data, error } = await supabase
    .from('user_profiles')
    .select('id,email,full_name,role,created_at')
    .eq('org_id', orgId)
    .order('created_at', { ascending: true });
  if (error) throw error;
  return data || [];
}

export async function inviteMember(orgId, email, role) {
  const { data, error } = await supabase
    .from('invites')
    .insert({ org_id: orgId, email, role, status: 'pending' })
    .select()
    .single();
  if (error) throw error;
  return data;
}

export async function getInvites(orgId) {
  const { data, error } = await supabase
    .from('invites')
    .select('*')
    .eq('org_id', orgId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data || [];
}

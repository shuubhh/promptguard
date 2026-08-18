/**
 * config.js — baked-in defaults for the PromptGuard SaaS instance.
 *
 * The anon key is PUBLIC by design (Supabase's model): it only enables
 * connecting to the project, and Row Level Security protects the data.
 * The extension ships with these so users never have to paste the URL or
 * anon key manually — joining an org is a single code.
 *
 * Loaded via importScripts() in background.js and <script> in popup.html.
 */
'use strict';

const PROMPTGUARD_CONFIG = {
  SUPABASE_URL: 'https://aefujtgikbengcwwhlgq.supabase.co',
  SUPABASE_ANON_KEY: 'sb_publishable_HVMFcvCfuscDmTNpkJTEcQ_G-t4uNSQ',
  FUNCTIONS_BASE: 'https://aefujtgikbengcwwhlgq.supabase.co/functions/v1'
};

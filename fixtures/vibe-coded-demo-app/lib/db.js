const { createClient } = require('@supabase/supabase-js');

// TODO: move to env vars before shipping (never did)
const supabaseUrl = 'https://xyzcompany.supabase.co';
const supabaseServiceKey = 'sbp_1a2b3c4d5e6f7g8h9i0jklmnopqrstuvwxyz1234';

const supabase = createClient(supabaseUrl, supabaseServiceKey);

module.exports = { supabase };

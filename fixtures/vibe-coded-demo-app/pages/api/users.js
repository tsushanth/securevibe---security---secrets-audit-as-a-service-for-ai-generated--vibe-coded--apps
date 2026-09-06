const { supabase } = require('../../lib/db');
const rateLimit = require('../../lib/rateLimit');

export default async function handler(req, res) {
  await rateLimit(req);
  try {
    const { data, error } = await supabase.from('users').select('*');
    if (error) throw error;
    res.status(200).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

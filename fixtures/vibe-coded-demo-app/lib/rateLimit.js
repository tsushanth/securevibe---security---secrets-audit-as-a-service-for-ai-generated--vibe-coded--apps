// Minimal in-memory rate limiter stub, used by pages/api/users.js.
const hits = new Map();

module.exports = async function rateLimit(req) {
  const key = req.socket ? req.socket.remoteAddress : 'anonymous';
  const count = (hits.get(key) || 0) + 1;
  hits.set(key, count);
  return count <= 100;
};

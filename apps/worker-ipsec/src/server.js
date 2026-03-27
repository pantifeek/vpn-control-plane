const express = require('express');

const PORT = process.env.PORT || 3102;
const WORKER_TYPE = process.env.WORKER_TYPE || 'IPSEC';

const app = express();
app.use(express.json());

const states = new Map();

function ensure(profileId) {
  if (!states.has(profileId)) {
    states.set(profileId, {
      status: 'STOPPED',
      connectedAt: null,
      lastMessage: 'Profile is not connected yet',
      profileSummary: null
    });
  }
  return states.get(profileId);
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'worker-ipsec', workerType: WORKER_TYPE, runtime: 'strongswan-installed-in-container' });
});

app.get('/status', (req, res) => {
  const profileId = req.query.profileId;
  if (!profileId) {
    return res.json({ workerType: WORKER_TYPE, status: 'IDLE', connectedAt: null, lastMessage: 'No profileId provided' });
  }
  const state = ensure(String(profileId));
  res.json({ workerType: WORKER_TYPE, ...state });
});

app.post('/connect', async (req, res) => {
  const { profileId, name, host, port, username } = req.body || {};
  if (!profileId || !name || !host || !port) {
    return res.status(400).json({ message: 'profileId, name, host, port are required' });
  }

  const state = ensure(String(profileId));
  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastMessage = `Mock IPsec connection established to ${host}:${port}`;
  state.profileSummary = { profileId, name, host, port, username: username || '' };

  res.json({
    ok: true,
    workerType: WORKER_TYPE,
    note: 'This is MVP mock behavior. Replace with real strongSwan/VICI control in the next iteration.',
    state
  });
});

app.post('/disconnect', async (req, res) => {
  const { profileId } = req.body || {};
  if (!profileId) {
    return res.status(400).json({ message: 'profileId is required' });
  }

  const state = ensure(String(profileId));
  state.status = 'STOPPED';
  state.lastMessage = 'Mock IPsec connection closed';
  state.connectedAt = null;

  res.json({ ok: true, workerType: WORKER_TYPE, state });
});

app.post('/restart', async (req, res) => {
  const { profileId } = req.body || {};
  if (!profileId) {
    return res.status(400).json({ message: 'profileId is required' });
  }

  const state = ensure(String(profileId));
  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastMessage = 'Mock IPsec connection restarted';

  res.json({ ok: true, workerType: WORKER_TYPE, state });
});

app.get('/logs', (req, res) => {
  const profileId = req.query.profileId;
  if (!profileId) {
    return res.json({ logs: ['No profileId specified'] });
  }

  const state = ensure(String(profileId));
  const now = new Date().toISOString();
  res.json({
    logs: [
      `[${now}] workerType=${WORKER_TYPE}`,
      `[${now}] profileId=${profileId}`,
      `[${now}] status=${state.status}`,
      `[${now}] message=${state.lastMessage || ''}`
    ]
  });
});

app.listen(PORT, () => {
  console.log(`worker-ipsec listening on port ${PORT}`);
});

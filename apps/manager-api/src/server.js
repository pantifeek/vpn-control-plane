const express = require('express');
const cors = require('cors');
const Docker = require('dockerode');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3001);
const RUNTIME_NETWORK = process.env.RUNTIME_NETWORK || 'vpn-control-plane';
const RUNTIME_PORT = Number(process.env.RUNTIME_PORT || 8080);
const DOCKER_SOCKET_PATH = process.env.DOCKER_SOCKET_PATH || '/var/run/docker.sock';
const PROFILE_STORE_PATH = process.env.PROFILE_STORE_PATH || '/data/profiles.json';
const RUNTIME_STATUS_TIMEOUT_MS = Number(process.env.RUNTIME_STATUS_TIMEOUT_MS || 5000);
const RUNTIME_HEALTH_TIMEOUT_MS = Number(process.env.RUNTIME_HEALTH_TIMEOUT_MS || 30000);
const RUNTIME_PORT_FORWARDING_MODE = String(process.env.RUNTIME_PORT_FORWARDING_MODE || 'HOST').trim().toUpperCase();

const RUNTIME_IMAGES = {
  OPENVPN: process.env.RUNTIME_IMAGE_OPENVPN || 'vpn-runtime-openvpn:local',
  IPSEC: process.env.RUNTIME_IMAGE_IPSEC || 'vpn-runtime-ipsec:local',
  WIREGUARD: process.env.RUNTIME_IMAGE_WIREGUARD || 'vpn-runtime-wireguard:local'
};

const docker = new Docker({ socketPath: DOCKER_SOCKET_PATH });

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

/** @type {Map<string, any>} */
const profiles = new Map();

let persistenceReady = false;
let startupState = 'BOOTING';
let startupError = null;
let persistQueue = Promise.resolve();

function getPanelAuthSecret() {
  return process.env.PANEL_AUTH_SECRET || `${process.env.PANEL_AUTH_USERNAME || ''}:${process.env.PANEL_AUTH_PASSWORD || ''}`;
}

function isPanelAuthEnabled() {
  return Boolean(process.env.PANEL_AUTH_USERNAME && process.env.PANEL_AUTH_PASSWORD);
}

function getPanelAuthUsername() {
  return process.env.PANEL_AUTH_USERNAME || '';
}

function buildPanelAuthToken(username) {
  return crypto.createHmac('sha256', getPanelAuthSecret()).update(String(username || '')).digest('hex');
}

function parseCookieHeader(cookieHeader) {
  const cookies = {};
  for (const item of String(cookieHeader || '').split(';')) {
    const [rawKey, ...rest] = item.split('=');
    const key = String(rawKey || '').trim();
    if (!key) continue;
    cookies[key] = decodeURIComponent(rest.join('=').trim());
  }
  return cookies;
}

function isApiRequestAuthenticated(req) {
  if (!isPanelAuthEnabled()) return true;
  const cookies = parseCookieHeader(req.headers.cookie || '');
  const cookieValue = cookies.vpn_panel_auth || '';
  return cookieValue === buildPanelAuthToken(getPanelAuthUsername());
}

function isMonitoringTokenValid(req) {
  const expectedToken = String(process.env.MONITORING_TOKEN || '').trim();
  if (!expectedToken) {
    return isApiRequestAuthenticated(req);
  }

  const header = String(req.headers.authorization || '');
  const prefix = 'Bearer ';
  if (!header.startsWith(prefix)) {
    return false;
  }

  const candidateToken = header.slice(prefix.length).trim();
  if (!candidateToken) {
    return false;
  }

  const expectedBuffer = Buffer.from(expectedToken, 'utf8');
  const candidateBuffer = Buffer.from(candidateToken, 'utf8');
  return (
    expectedBuffer.length === candidateBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, candidateBuffer)
  );
}

function asPrometheusLabel(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"');
}

function appendMetricLine(lines, name, value, labels = null) {
  const suffix = labels && Object.keys(labels).length > 0
    ? `{${Object.entries(labels)
      .map(([key, labelValue]) => `${key}="${asPrometheusLabel(labelValue)}"`)
      .join(',')}}`
    : '';
  lines.push(`${name}${suffix} ${Number.isFinite(value) ? value : 0}`);
}

function toUnixTimestampSeconds(value) {
  if (!value) return 0;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return 0;
  return Math.floor(timestamp / 1000);
}

function toAgeSeconds(value) {
  if (!value) return 0;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return 0;
  return Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
}

function isContainerRunning(state) {
  return String(state || '').toLowerCase() === 'running' ? 1 : 0;
}

function isWorkerConnected(status) {
  return String(status || '').toUpperCase() === 'CONNECTED' ? 1 : 0;
}

function isWorkerProblem(status) {
  return ['ERROR', 'DEGRADED', 'UNREACHABLE', 'STOPPED'].includes(String(status || '').toUpperCase()) ? 1 : 0;
}

function isStatusApplied(status) {
  return String(status || '').toUpperCase() === 'APPLIED' ? 1 : 0;
}

async function collectInstanceStatuses() {
  const result = [];

  for (const profile of profiles.values()) {
    const containerName = profile.runtimeContainerName || getRuntimeContainerName(profile);
    const runtime = await fetchRuntimeStatus(containerName);

    result.push({
      profileId: profile.id,
      name: profile.name,
      type: profile.type,
      host: profile.host,
      port: profile.port,
      managerStatus: profile.status,
      runtimeContainerName: profile.runtimeContainerName,
      runtimeImage: profile.runtimeImage || RUNTIME_IMAGES[profile.type],
      runtimeContainerState: runtime.containerState,
      workerStatus: runtime.runtimeStatus,
      firewallStatus: runtime.firewallStatus || 'NOT_CONFIGURED',
      firewallMessage: runtime.firewallMessage || null,
      portForwardingStatus: runtime.portForwardingStatus || 'NOT_CONFIGURED',
      portForwardingMessage: runtime.portForwardingMessage || null,
      lastHandshakeAt: runtime.lastHandshakeAt || null,
      workerConnectedAt: runtime.connectedAt,
      workerLastMessage: runtime.lastMessage,
      lastError: profile.lastError || null
    });
  }

  return result;
}

async function buildMonitoringSnapshot() {
  const instances = await collectInstanceStatuses();

  const summary = {
    totalProfiles: profiles.size,
    desiredConnected: 0,
    desiredStopped: 0,
    desiredError: 0,
    runningContainers: 0,
    connectedWorkers: 0,
    workerProblems: 0
  };

  for (const item of instances) {
    if (item.managerStatus === 'CONNECTED') summary.desiredConnected += 1;
    else if (item.managerStatus === 'ERROR') summary.desiredError += 1;
    else summary.desiredStopped += 1;

    summary.runningContainers += isContainerRunning(item.runtimeContainerState);
    summary.connectedWorkers += isWorkerConnected(item.workerStatus);
    summary.workerProblems += isWorkerProblem(item.workerStatus);
  }

  return {
    service: {
      name: 'manager-api',
      startupState,
      startupError,
      persistenceReady,
      generatedAt: new Date().toISOString()
    },
    summary,
    profiles: instances
  };
}

async function buildPrometheusMetrics() {
  const snapshot = await buildMonitoringSnapshot();
  const lines = [];

  lines.push('# HELP vpn_control_plane_up manager-api process is alive.');
  lines.push('# TYPE vpn_control_plane_up gauge');
  appendMetricLine(lines, 'vpn_control_plane_up', 1);

  lines.push('# HELP vpn_control_plane_startup_state Current startup state of manager-api.');
  lines.push('# TYPE vpn_control_plane_startup_state gauge');
  for (const state of ['BOOTING', 'RECONCILING', 'READY', 'ERROR']) {
    appendMetricLine(lines, 'vpn_control_plane_startup_state', snapshot.service.startupState === state ? 1 : 0, { state });
  }

  lines.push('# HELP vpn_profiles_total Total number of VPN profiles.');
  lines.push('# TYPE vpn_profiles_total gauge');
  appendMetricLine(lines, 'vpn_profiles_total', snapshot.summary.totalProfiles);

  lines.push('# HELP vpn_profiles_desired_total Number of profiles by desired state.');
  lines.push('# TYPE vpn_profiles_desired_total gauge');
  appendMetricLine(lines, 'vpn_profiles_desired_total', snapshot.summary.desiredConnected, { state: 'CONNECTED' });
  appendMetricLine(lines, 'vpn_profiles_desired_total', snapshot.summary.desiredStopped, { state: 'STOPPED' });
  appendMetricLine(lines, 'vpn_profiles_desired_total', snapshot.summary.desiredError, { state: 'ERROR' });

  lines.push('# HELP vpn_runtime_containers_running Number of running runtime containers.');
  lines.push('# TYPE vpn_runtime_containers_running gauge');
  appendMetricLine(lines, 'vpn_runtime_containers_running', snapshot.summary.runningContainers);

  lines.push('# HELP vpn_workers_connected Number of connected VPN workers.');
  lines.push('# TYPE vpn_workers_connected gauge');
  appendMetricLine(lines, 'vpn_workers_connected', snapshot.summary.connectedWorkers);

  lines.push('# HELP vpn_workers_problem Number of workers with degraded, error, unreachable or stopped status.');
  lines.push('# TYPE vpn_workers_problem gauge');
  appendMetricLine(lines, 'vpn_workers_problem', snapshot.summary.workerProblems);

  lines.push('# HELP vpn_profile_desired_connected Desired profile state is CONNECTED.');
  lines.push('# TYPE vpn_profile_desired_connected gauge');
  lines.push('# HELP vpn_runtime_container_running Runtime container is running.');
  lines.push('# TYPE vpn_runtime_container_running gauge');
  lines.push('# HELP vpn_worker_connected Worker runtime status is CONNECTED.');
  lines.push('# TYPE vpn_worker_connected gauge');
  lines.push('# HELP vpn_worker_problem Worker runtime status indicates a problem.');
  lines.push('# TYPE vpn_worker_problem gauge');
  lines.push('# HELP vpn_port_forwarding_applied Port forwarding rules are applied.');
  lines.push('# TYPE vpn_port_forwarding_applied gauge');
  lines.push('# HELP vpn_firewall_applied Firewall rules are applied.');
  lines.push('# TYPE vpn_firewall_applied gauge');
  lines.push('# HELP vpn_profile_last_handshake_age_seconds Seconds since last handshake.');
  lines.push('# TYPE vpn_profile_last_handshake_age_seconds gauge');
  lines.push('# HELP vpn_profile_last_handshake_timestamp_seconds Unix timestamp of the last handshake.');
  lines.push('# TYPE vpn_profile_last_handshake_timestamp_seconds gauge');

  for (const item of snapshot.profiles) {
    const labels = {
      profile_id: item.profileId,
      profile_name: item.name,
      type: item.type,
      host: item.host
    };

    appendMetricLine(lines, 'vpn_profile_desired_connected', item.managerStatus === 'CONNECTED' ? 1 : 0, labels);
    appendMetricLine(lines, 'vpn_runtime_container_running', isContainerRunning(item.runtimeContainerState), labels);
    appendMetricLine(lines, 'vpn_worker_connected', isWorkerConnected(item.workerStatus), labels);
    appendMetricLine(lines, 'vpn_worker_problem', isWorkerProblem(item.workerStatus), labels);
    appendMetricLine(lines, 'vpn_port_forwarding_applied', isStatusApplied(item.portForwardingStatus), labels);
    appendMetricLine(lines, 'vpn_firewall_applied', isStatusApplied(item.firewallStatus), labels);
    appendMetricLine(lines, 'vpn_profile_last_handshake_age_seconds', toAgeSeconds(item.lastHandshakeAt), labels);
    appendMetricLine(lines, 'vpn_profile_last_handshake_timestamp_seconds', toUnixTimestampSeconds(item.lastHandshakeAt), labels);
  }

  lines.push('');
  return lines.join('\n');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchRuntimeJson(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeoutMs || RUNTIME_STATUS_TIMEOUT_MS);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error(`Runtime request timed out after ${options.timeoutMs || RUNTIME_STATUS_TIMEOUT_MS}ms: ${url}`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function sanitizeName(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '');
}

function getRuntimeContainerName(profile) {
  return `vpn-runtime-${profile.type.toLowerCase()}-${sanitizeName(profile.id)}`;
}

function buildRuntimeUrl(containerName) {
  return `http://${containerName}:${RUNTIME_PORT}`;
}

function normalizeCommaSeparated(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .join(',');
}

function sanitizeWireguardConfig(input) {
  if (!input || typeof input !== 'object') {
    return null;
  }

  const normalizeKey = (value) => String(value || '').replace(/\s+/g, '');

  return {
    tunnelAddress: String(input.tunnelAddress || '').trim(),
    privateKey: normalizeKey(input.privateKey),
    peerPublicKey: normalizeKey(input.peerPublicKey),
    presharedKey: normalizeKey(input.presharedKey),
    allowedIps: normalizeCommaSeparated(input.allowedIps || ''),
    dnsServers: normalizeCommaSeparated(input.dnsServers || ''),
    persistentKeepalive:
      input.persistentKeepalive === undefined || input.persistentKeepalive === null || input.persistentKeepalive === ''
        ? ''
        : String(input.persistentKeepalive).trim()
  };
}

function sanitizeOpenvpnConfig(input) {
  if (!input || typeof input !== 'object') {
    return null;
  }

  return {
    configText: String(input.configText || '').trim(),
    username: String(input.username || '').trim(),
    password: String(input.password || '').trim(),
    caText: String(input.caText || '').trim(),
    certText: String(input.certText || '').trim(),
    keyText: String(input.keyText || '').trim(),
    tlsAuthText: String(input.tlsAuthText || '').trim(),
    keyDirection: String(input.keyDirection || '').trim()
  };
}

function sanitizeIpsecConfig(input) {
  if (!input || typeof input !== 'object') {
    return null;
  }

  return {
    preSharedKey: String(input.preSharedKey || '').trim(),
    password: String(input.password || '').trim(),
    userId: String(input.userId || '').trim(),
    localIdentifier: String(input.localIdentifier || '').trim(),
    remoteIdentifier: String(input.remoteIdentifier || '').trim(),
    dnsServers: normalizeCommaSeparated(input.dnsServers || ''),
    mtu: String(input.mtu || '').trim(),
    mru: String(input.mru || '').trim()
  };
}

function mergeOpenvpnConfig(existingConfig, incomingConfig) {
  const existing = sanitizeOpenvpnConfig(existingConfig) || {};
  const incoming = sanitizeOpenvpnConfig(incomingConfig) || {};

  return {
    configText: incoming.configText || existing.configText || '',
    username: incoming.username !== undefined ? incoming.username : existing.username || '',
    password: incoming.password || existing.password || '',
    caText: incoming.caText || existing.caText || '',
    certText: incoming.certText || existing.certText || '',
    keyText: incoming.keyText || existing.keyText || '',
    tlsAuthText: incoming.tlsAuthText || existing.tlsAuthText || '',
    keyDirection: incoming.keyDirection || existing.keyDirection || ''
  };
}

function mergeIpsecConfig(existingConfig, incomingConfig) {
  const existing = sanitizeIpsecConfig(existingConfig) || {};
  const incoming = sanitizeIpsecConfig(incomingConfig) || {};

  return {
    preSharedKey: incoming.preSharedKey || existing.preSharedKey || '',
    password: incoming.password || existing.password || '',
    userId: incoming.userId !== undefined ? incoming.userId : existing.userId || '',
    localIdentifier: incoming.localIdentifier !== undefined ? incoming.localIdentifier : existing.localIdentifier || '',
    remoteIdentifier: incoming.remoteIdentifier !== undefined ? incoming.remoteIdentifier : existing.remoteIdentifier || '',
    dnsServers: incoming.dnsServers !== undefined ? incoming.dnsServers : existing.dnsServers || '',
    mtu: incoming.mtu !== undefined ? incoming.mtu : existing.mtu || '',
    mru: incoming.mru !== undefined ? incoming.mru : existing.mru || ''
  };
}

function sanitizeFirewallBasicRule(rule) {
  return {
    id: String(rule?.id || crypto.randomUUID()),
    table: String(rule?.table || 'filter').trim().toLowerCase(),
    chain: String(rule?.chain || 'OUTPUT').trim().toUpperCase(),
    action: String(rule?.action || 'ACCEPT').trim().toUpperCase(),
    protocol: String(rule?.protocol || 'all').trim().toLowerCase(),
    source: String(rule?.source || '').trim(),
    destination: String(rule?.destination || '').trim(),
    destinationPort: String(rule?.destinationPort || '').trim(),
    comment: String(rule?.comment || '').trim()
  };
}

function sanitizeFirewallConfig(input) {
  const firewall = input && typeof input === 'object' ? input : {};
  return {
    enabled: Boolean(firewall.enabled),
    mode: String(firewall.mode || 'BASIC').trim().toUpperCase() === 'ADVANCED' ? 'ADVANCED' : 'BASIC',
    basicRules: Array.isArray(firewall.basicRules) ? firewall.basicRules.map(sanitizeFirewallBasicRule) : [],
    advancedRules: String(firewall.advancedRules || '').trim()
  };
}

function sanitizePortForward(input) {
  return {
    id: String(input?.id || crypto.randomUUID()),
    enabled: input?.enabled !== false,
    protocol: String(input?.protocol || 'tcp').trim().toLowerCase() === 'udp' ? 'udp' : 'tcp',
    hostPort: String(input?.hostPort || '').trim(),
    targetAddress: String(input?.targetAddress || '').trim(),
    targetPort: String(input?.targetPort || '').trim(),
    description: String(input?.description || '').trim()
  };
}

function sanitizePortForwardingConfig(input) {
  const config = input && typeof input === 'object' ? input : {};
  return {
    enabled: Boolean(config.enabled),
    rules: Array.isArray(config.rules) ? config.rules.map(sanitizePortForward) : []
  };
}

function validateFirewallConfig(input) {
  const errors = [];
  const firewall = sanitizeFirewallConfig(input);
  const allowedChains = new Set(['INPUT', 'OUTPUT', 'FORWARD']);
  const allowedActions = new Set(['ACCEPT', 'DROP', 'REJECT']);
  const allowedProtocols = new Set(['all', 'tcp', 'udp', 'icmp']);

  if (!firewall.enabled) {
    return errors;
  }

  if (firewall.mode === 'BASIC') {
    for (const rule of firewall.basicRules) {
      if (rule.table !== 'filter') errors.push('firewall basic rules currently support only filter table');
      if (!allowedChains.has(rule.chain)) errors.push(`unsupported firewall chain: ${rule.chain}`);
      if (!allowedActions.has(rule.action)) errors.push(`unsupported firewall action: ${rule.action}`);
      if (!allowedProtocols.has(rule.protocol)) errors.push(`unsupported firewall protocol: ${rule.protocol}`);
    }
    return errors;
  }

  const lines = firewall.advancedRules
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    if (!/^ip6?tables\s+/.test(line)) {
      errors.push('advanced firewall rules must start with iptables or ip6tables');
      break;
    }
    if (/\s-F(\s|$)|\s-X(\s|$)|\s-P\s/.test(line)) {
      errors.push('advanced firewall rules must not flush, delete chains, or change default policies');
      break;
    }
  }

  return errors;
}

function validatePortForwardingConfig(input) {
  const errors = [];
  const config = sanitizePortForwardingConfig(input);
  const hostPorts = new Set();

  if (!config.enabled) {
    return errors;
  }

  for (const rule of config.rules.filter((item) => item.enabled)) {
    const hostPort = Number(rule.hostPort);
    const targetPort = Number(rule.targetPort);

    if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) {
      errors.push(`invalid portForward hostPort: ${rule.hostPort}`);
    }
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      errors.push(`invalid portForward targetPort: ${rule.targetPort}`);
    }
    if (!rule.targetAddress) {
      errors.push('portForward targetAddress is required');
    }

    const dedupeKey = `${rule.protocol}:${rule.hostPort}`;
    if (hostPorts.has(dedupeKey)) {
      errors.push(`duplicate published port: ${dedupeKey}`);
    }
    hostPorts.add(dedupeKey);
  }

  return errors;
}

function mergeWireguardConfig(existingConfig, incomingConfig) {
  const existing = sanitizeWireguardConfig(existingConfig) || {};
  const incoming = sanitizeWireguardConfig(incomingConfig) || {};

  return {
    tunnelAddress: incoming.tunnelAddress || existing.tunnelAddress || '',
    privateKey: incoming.privateKey || existing.privateKey || '',
    peerPublicKey: incoming.peerPublicKey || existing.peerPublicKey || '',
    presharedKey: incoming.presharedKey !== undefined ? incoming.presharedKey : existing.presharedKey || '',
    allowedIps: incoming.allowedIps || existing.allowedIps || '',
    dnsServers: incoming.dnsServers !== undefined ? incoming.dnsServers : existing.dnsServers || '',
    persistentKeepalive:
      incoming.persistentKeepalive !== undefined ? incoming.persistentKeepalive : existing.persistentKeepalive || ''
  };
}

function normalizeProfile(raw) {
  const type = String(raw?.type || '').trim();
  return {
    id: String(raw?.id || crypto.randomUUID()),
    name: String(raw?.name || '').trim(),
    type,
    host: String(raw?.host || '').trim(),
    port: Number(raw?.port || 0),
    username: String(raw?.username || '').trim(),
    status: raw?.status === 'CONNECTED' ? 'CONNECTED' : raw?.status === 'ERROR' ? 'ERROR' : 'STOPPED',
    lastError: raw?.lastError ? String(raw.lastError) : null,
    createdAt: raw?.createdAt || new Date().toISOString(),
    updatedAt: raw?.updatedAt || new Date().toISOString(),
    runtimeContainerName: raw?.runtimeContainerName ? String(raw.runtimeContainerName) : null,
    runtimeImage: raw?.runtimeImage || RUNTIME_IMAGES[type] || null,
    openvpn: type === 'OPENVPN' ? sanitizeOpenvpnConfig(raw?.openvpn) : null,
    ipsec: type === 'IPSEC' ? sanitizeIpsecConfig(raw?.ipsec) : null,
    wireguard: type === 'WIREGUARD' ? sanitizeWireguardConfig(raw?.wireguard) : null,
    firewall: sanitizeFirewallConfig(raw?.firewall),
    portForwarding: sanitizePortForwardingConfig(raw?.portForwarding)
  };
}

function validateProfileInput(body, isPatch = false) {
  const errors = [];
  const { name, type, host, port } = body || {};

  if (!isPatch || name !== undefined) {
    if (!String(name || '').trim()) {
      errors.push('name is required');
    }
  }

  if (!isPatch || type !== undefined) {
    if (!RUNTIME_IMAGES[type]) {
      errors.push(`type must be one of: ${Object.keys(RUNTIME_IMAGES).join(', ')}`);
    }
  }

  if (!isPatch || host !== undefined) {
    if (!String(host || '').trim()) {
      errors.push('host is required');
    }
  }

  if (!isPatch || port !== undefined) {
    if (!port || Number.isNaN(Number(port))) {
      errors.push('port must be a number');
    }
  }

  const effectiveType = type;
  if (effectiveType === 'OPENVPN') {
    const openvpn = sanitizeOpenvpnConfig(body.openvpn);
    if (!openvpn?.configText) errors.push('openvpn.configText is required for OPENVPN');
    if (!openvpn?.caText) errors.push('openvpn.caText is required for OPENVPN');
    if (!openvpn?.certText) errors.push('openvpn.certText is required for OPENVPN');
    if (!openvpn?.keyText) errors.push('openvpn.keyText is required for OPENVPN');
  }

  if (effectiveType === 'WIREGUARD') {
    const wireguard = sanitizeWireguardConfig(body.wireguard);
    if (!wireguard?.tunnelAddress) errors.push('wireguard.tunnelAddress is required for WIREGUARD');
    if (!wireguard?.privateKey) errors.push('wireguard.privateKey is required for WIREGUARD');
    if (!wireguard?.peerPublicKey) errors.push('wireguard.peerPublicKey is required for WIREGUARD');
    if (!wireguard?.allowedIps) errors.push('wireguard.allowedIps is required for WIREGUARD');
  }

  if (effectiveType === 'IPSEC') {
    const ipsec = sanitizeIpsecConfig(body.ipsec);
    if (!ipsec?.preSharedKey) errors.push('ipsec.preSharedKey is required for IPSEC');
    if (!ipsec?.password) errors.push('ipsec.password is required for IPSEC');
  }

  errors.push(...validateFirewallConfig(body.firewall));
  errors.push(...validatePortForwardingConfig(body.portForwarding));

  return errors;
}

function toDto(profile) {
  return {
    id: profile.id,
    name: profile.name,
    type: profile.type,
    host: profile.host,
    port: profile.port,
    username: profile.username || '',
    status: profile.status || 'STOPPED',
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
    lastError: profile.lastError || null,
    runtimeContainerName: profile.runtimeContainerName || null,
    runtimeImage: profile.runtimeImage || RUNTIME_IMAGES[profile.type] || null,
    openvpn:
      profile.type === 'OPENVPN'
        ? {
            hasConfig: Boolean(profile.openvpn?.configText),
            username: profile.openvpn?.username || '',
            hasCa: Boolean(profile.openvpn?.caText),
            hasCert: Boolean(profile.openvpn?.certText),
            hasKey: Boolean(profile.openvpn?.keyText),
            hasTlsAuth: Boolean(profile.openvpn?.tlsAuthText),
            keyDirection: profile.openvpn?.keyDirection || ''
          }
        : null,
    ipsec:
      profile.type === 'IPSEC'
        ? {
            userId: profile.ipsec?.userId || profile.username || '',
            hasPreSharedKey: Boolean(profile.ipsec?.preSharedKey),
            hasPassword: Boolean(profile.ipsec?.password),
            localIdentifier: profile.ipsec?.localIdentifier || '',
            remoteIdentifier: profile.ipsec?.remoteIdentifier || '',
            dnsServers: profile.ipsec?.dnsServers || '',
            mtu: profile.ipsec?.mtu || '',
            mru: profile.ipsec?.mru || ''
          }
        : null,
    firewall: sanitizeFirewallConfig(profile.firewall),
    portForwarding: sanitizePortForwardingConfig(profile.portForwarding),
    wireguard:
      profile.type === 'WIREGUARD'
        ? {
            tunnelAddress: profile.wireguard?.tunnelAddress || '',
            allowedIps: profile.wireguard?.allowedIps || '',
            dnsServers: profile.wireguard?.dnsServers || '',
            persistentKeepalive: profile.wireguard?.persistentKeepalive || ''
          }
        : null
  };
}

function getRuntimeEnv(profile) {
  const env = [
    `PORT=${RUNTIME_PORT}`,
    `VPN_TYPE=${profile.type}`,
    `VPN_PROFILE_ID=${profile.id}`,
    `VPN_PROFILE_NAME=${profile.name}`,
    `VPN_PROFILE_HOST=${profile.host}`,
    `VPN_PROFILE_PORT=${profile.port}`,
    `VPN_PROFILE_USERNAME=${profile.username || ''}`
  ];

  if (profile.type === 'OPENVPN' && profile.openvpn) {
    env.push(`OPENVPN_CONFIG_TEXT=${profile.openvpn.configText}`);
    env.push(`OPENVPN_USERNAME=${profile.openvpn.username || ''}`);
    env.push(`OPENVPN_PASSWORD=${profile.openvpn.password || ''}`);
    env.push(`OPENVPN_CA_TEXT=${profile.openvpn.caText || ''}`);
    env.push(`OPENVPN_CERT_TEXT=${profile.openvpn.certText || ''}`);
    env.push(`OPENVPN_KEY_TEXT=${profile.openvpn.keyText || ''}`);
    env.push(`OPENVPN_TLS_AUTH_TEXT=${profile.openvpn.tlsAuthText || ''}`);
    env.push(`OPENVPN_KEY_DIRECTION=${profile.openvpn.keyDirection || ''}`);
  }

  if (profile.type === 'IPSEC' && profile.ipsec) {
    env.push(`IPSEC_PSK=${profile.ipsec.preSharedKey}`);
    env.push(`IPSEC_PASSWORD=${profile.ipsec.password}`);
    env.push(`IPSEC_USER_ID=${profile.ipsec.userId || profile.username || ''}`);
    env.push(`IPSEC_LOCAL_ID=${profile.ipsec.localIdentifier || ''}`);
    env.push(`IPSEC_REMOTE_ID=${profile.ipsec.remoteIdentifier || ''}`);
    env.push(`IPSEC_DNS_SERVERS=${profile.ipsec.dnsServers || ''}`);
    env.push(`IPSEC_MTU=${profile.ipsec.mtu || ''}`);
    env.push(`IPSEC_MRU=${profile.ipsec.mru || ''}`);
  }

  if (profile.type === 'WIREGUARD' && profile.wireguard) {
    env.push(`WG_TUNNEL_ADDRESS=${profile.wireguard.tunnelAddress}`);
    env.push(`WG_PRIVATE_KEY=${profile.wireguard.privateKey}`);
    env.push(`WG_PEER_PUBLIC_KEY=${profile.wireguard.peerPublicKey}`);
    env.push(`WG_PRESHARED_KEY=${profile.wireguard.presharedKey || ''}`);
    env.push(`WG_ALLOWED_IPS=${profile.wireguard.allowedIps}`);
    env.push(`WG_DNS_SERVERS=${profile.wireguard.dnsServers || ''}`);
    env.push(`WG_PERSISTENT_KEEPALIVE=${profile.wireguard.persistentKeepalive || ''}`);
  }

  env.push(`FIREWALL_CONFIG_JSON=${JSON.stringify(sanitizeFirewallConfig(profile.firewall))}`);
  env.push(`PORT_FORWARDING_CONFIG_JSON=${JSON.stringify(sanitizePortForwardingConfig(profile.portForwarding))}`);
  if (process.env.RUNTIME_IPSEC_INTERFACE_MISSING_GRACE_MS) {
    env.push(`RUNTIME_IPSEC_INTERFACE_MISSING_GRACE_MS=${process.env.RUNTIME_IPSEC_INTERFACE_MISSING_GRACE_MS}`);
  }

  return env;
}

function getPortBindings(profile) {
  const portForwarding = sanitizePortForwardingConfig(profile.portForwarding);
  const exposedPorts = {
    [`${RUNTIME_PORT}/tcp`]: {}
  };
  const portBindings = {};
  const publishToHost = RUNTIME_PORT_FORWARDING_MODE !== 'CONTAINER';

  for (const rule of portForwarding.rules.filter((item) => portForwarding.enabled && item.enabled)) {
    const key = `${rule.hostPort}/${rule.protocol}`;
    exposedPorts[key] = {};
    if (publishToHost) {
      portBindings[key] = [{ HostPort: String(rule.hostPort) }];
    }
  }

  return { exposedPorts, portBindings };
}

async function ensureProfileStore() {
  await fs.mkdir(path.dirname(PROFILE_STORE_PATH), { recursive: true });
  persistenceReady = true;
}

async function persistProfiles() {
  await ensureProfileStore();
  const serialized = JSON.stringify(
    {
      version: 1,
      updatedAt: new Date().toISOString(),
      profiles: Array.from(profiles.values())
    },
    null,
    2
  );
  const tempPath = `${PROFILE_STORE_PATH}.tmp`;
  await fs.writeFile(tempPath, serialized, 'utf8');
  await fs.rename(tempPath, PROFILE_STORE_PATH);
}

function queuePersist() {
  persistQueue = persistQueue
    .then(() => persistProfiles())
    .catch((error) => {
      console.error('Failed to persist profiles', error);
    });

  return persistQueue;
}

async function loadProfiles() {
  await ensureProfileStore();

  try {
    const raw = await fs.readFile(PROFILE_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    for (const profile of parsed.profiles || []) {
      const normalized = normalizeProfile(profile);
      profiles.set(normalized.id, normalized);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

async function ensureRuntimeImage(type) {
  const imageName = RUNTIME_IMAGES[type];
  if (!imageName) {
    throw new Error(`No runtime image configured for VPN type ${type}`);
  }

  try {
    await docker.getImage(imageName).inspect();
    return imageName;
  } catch (error) {
    throw new Error(`Runtime image ${imageName} is not available. Build runtime images before connecting profiles.`);
  }
}

async function inspectRuntimeContainer(containerName) {
  try {
    return await docker.getContainer(containerName).inspect();
  } catch (error) {
    if (error.statusCode === 404) {
      return null;
    }
    throw error;
  }
}

async function removeRuntimeContainer(containerName) {
  const inspect = await inspectRuntimeContainer(containerName);
  if (!inspect) {
    return false;
  }

  const container = docker.getContainer(containerName);
  if (inspect.State?.Running) {
    await container.stop({ t: 5 });
  }
  await container.remove({ force: true });
  return true;
}

async function waitForRuntime(containerName) {
  let lastError = null;

  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetchRuntimeJson(`${buildRuntimeUrl(containerName)}/health`, {
        timeoutMs: RUNTIME_HEALTH_TIMEOUT_MS
      });
      if (response.ok) {
        return;
      }

      const text = await response.text();
      lastError = new Error(`Runtime health returned ${response.status}: ${text}`);
    } catch (error) {
      lastError = error;
    }

    await sleep(500);
  }

  throw lastError || new Error(`Runtime ${containerName} did not become healthy`);
}

async function createRuntimeContainer(profile) {
  const imageName = await ensureRuntimeImage(profile.type);
  const containerName = getRuntimeContainerName(profile);

  await removeRuntimeContainer(containerName);

  const hostConfig = {
    NetworkMode: RUNTIME_NETWORK,
    CapAdd: ['NET_ADMIN'],
    RestartPolicy: { Name: 'unless-stopped' },
    Sysctls: {
      'net.ipv4.ip_forward': '1'
    }
  };

  if (profile.type === 'IPSEC') {
    hostConfig.Privileged = true;
    hostConfig.CapAdd = Array.from(new Set([...(hostConfig.CapAdd || []), 'NET_ADMIN', 'NET_RAW', 'SYS_MODULE']));
    const modulesPath = process.env.RUNTIME_MODULES_PATH || '/lib/modules';
    hostConfig.Binds = [...(hostConfig.Binds || []), `${modulesPath}:/lib/modules:ro`];
  }
  const { exposedPorts, portBindings } = getPortBindings(profile);

  const tunDevicePath = process.env.RUNTIME_TUN_DEVICE_PATH || '/dev/net/tun';
  const pppDevicePath = process.env.RUNTIME_PPP_DEVICE_PATH || '/dev/ppp';
  if (tunDevicePath) {
    hostConfig.Devices = [
      {
        PathOnHost: tunDevicePath,
        PathInContainer: '/dev/net/tun',
        CgroupPermissions: 'rwm'
      }
    ];
  }

  if (pppDevicePath) {
    hostConfig.Devices = [
      ...(hostConfig.Devices || []),
      {
        PathOnHost: pppDevicePath,
        PathInContainer: '/dev/ppp',
        CgroupPermissions: 'rwm'
      }
    ];
  }

  const container = await docker.createContainer({
    name: containerName,
    Image: imageName,
    Env: getRuntimeEnv(profile),
    Labels: {
      'com.vpn-control-plane.runtime.managed': 'true',
      'com.vpn-control-plane.profile-id': profile.id,
      'com.vpn-control-plane.vpn-type': profile.type
    },
    ExposedPorts: exposedPorts,
    HostConfig: {
      ...hostConfig,
      PortBindings: Object.keys(portBindings).length > 0 ? portBindings : undefined
    }
  });

  await container.start();
  await waitForRuntime(containerName);

  return { containerName, imageName };
}

async function fetchRuntimeStatus(containerName) {
  const inspect = await inspectRuntimeContainer(containerName);
  if (!inspect) {
    return {
      containerExists: false,
      containerState: 'MISSING',
      runtimeStatus: 'STOPPED',
      firewallStatus: 'NOT_CONFIGURED',
      firewallMessage: null,
      portForwardingStatus: 'NOT_CONFIGURED',
      portForwardingMessage: null,
      lastHandshakeAt: null,
      connectedAt: null,
      lastMessage: 'Runtime container is absent'
    };
  }

  if (!inspect.State?.Running) {
    return {
      containerExists: true,
      containerState: inspect.State?.Status || 'stopped',
      runtimeStatus: 'STOPPED',
      firewallStatus: 'NOT_CONFIGURED',
      firewallMessage: null,
      portForwardingStatus: 'NOT_CONFIGURED',
      portForwardingMessage: null,
      lastHandshakeAt: null,
      connectedAt: null,
      lastMessage: 'Runtime container is not running'
    };
  }

  try {
    const response = await fetchRuntimeJson(`${buildRuntimeUrl(containerName)}/status`, { cache: 'no-store' });
    const data = await response.json();
    return {
      containerExists: true,
      containerState: inspect.State?.Status || 'running',
      runtimeStatus: data.status || 'UNKNOWN',
      firewallStatus: data.firewallStatus || 'NOT_CONFIGURED',
      firewallMessage: data.firewallMessage || null,
      portForwardingStatus: data.portForwardingStatus || 'NOT_CONFIGURED',
      portForwardingMessage: data.portForwardingMessage || null,
      lastHandshakeAt: data.lastHandshakeAt || null,
      connectedAt: data.connectedAt || null,
      lastMessage: data.lastMessage || null
    };
  } catch (error) {
    return {
      containerExists: true,
      containerState: inspect.State?.Status || 'running',
      runtimeStatus: 'UNREACHABLE',
      firewallStatus: 'ERROR',
      firewallMessage: error.message,
      portForwardingStatus: 'ERROR',
      portForwardingMessage: error.message,
      lastHandshakeAt: null,
      connectedAt: null,
      lastMessage: error.message
    };
  }
}

async function reconcileProfile(profile) {
  const containerName = profile.runtimeContainerName || getRuntimeContainerName(profile);

  if (profile.status === 'CONNECTED') {
    const runtime = await fetchRuntimeStatus(containerName);

    if (runtime.runtimeStatus === 'CONNECTED' || runtime.runtimeStatus === 'STARTING') {
      profile.runtimeContainerName = containerName;
      profile.runtimeImage = profile.runtimeImage || RUNTIME_IMAGES[profile.type];
      profile.lastError = null;
      profile.updatedAt = new Date().toISOString();
      return;
    }

    const recreated = await createRuntimeContainer(profile);
    profile.runtimeContainerName = recreated.containerName;
    profile.runtimeImage = recreated.imageName;
    profile.lastError = null;
    profile.updatedAt = new Date().toISOString();
    return;
  }

  await removeRuntimeContainer(containerName);
  profile.runtimeContainerName = null;
  if (profile.status !== 'ERROR') {
    profile.status = 'STOPPED';
  }
  profile.updatedAt = new Date().toISOString();
}

async function reconcileProfilesOnStartup() {
  startupState = 'RECONCILING';
  startupError = null;

  for (const profile of profiles.values()) {
    try {
      await reconcileProfile(profile);
    } catch (error) {
      profile.lastError = error.message;
      profile.updatedAt = new Date().toISOString();
      if (profile.status === 'CONNECTED') {
        profile.status = 'ERROR';
      }
      console.error(`Failed to reconcile profile ${profile.id}`, error);
    }
  }

  await queuePersist();
  startupState = 'READY';
}

app.get('/health', async (req, res) => {
  try {
    await docker.ping();
    res.json({
      status: startupState === 'READY' ? 'ok' : startupState === 'ERROR' ? 'error' : 'starting',
      service: 'manager-api',
      docker: 'reachable',
      persistenceReady,
      startupState,
      startupError
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      service: 'manager-api',
      docker: error.message,
      persistenceReady,
      startupState,
      startupError
    });
  }
});

app.use((req, res, next) => {
  if (req.path === '/health') {
    return next();
  }

  if (req.path === '/metrics' || req.path === '/monitoring/status') {
    if (!isMonitoringTokenValid(req)) {
      return res.status(401).json({
        message: 'Monitoring authentication required'
      });
    }
    return next();
  }

  if (!isApiRequestAuthenticated(req)) {
    return res.status(401).json({
      message: 'Authentication required'
    });
  }

  const isReadOnlyRequest = req.method === 'GET' && (
    req.path === '/vpn-profiles' ||
    req.path === '/vpn-instances' ||
    req.path === '/metrics' ||
    req.path === '/monitoring/status' ||
    /^\/vpn-profiles\/[^/]+$/.test(req.path)
  );

  if (isReadOnlyRequest && (startupState === 'BOOTING' || startupState === 'RECONCILING')) {
    return next();
  }

  if (startupState !== 'READY') {
    return res.status(503).json({
      message: 'manager-api is still initializing',
      startupState,
      startupError
    });
  }

  next();
});

app.get('/vpn-profiles', (req, res) => {
  res.json(Array.from(profiles.values()).map(toDto));
});

app.get('/vpn-profiles/:id', (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ message: 'Profile not found' });
  }
  res.json(toDto(profile));
});

app.post('/vpn-profiles', async (req, res) => {
  const errors = validateProfileInput(req.body, false);
  if (errors.length > 0) {
    return res.status(400).json({ message: errors.join('; ') });
  }

  const { name, type, host, port, username } = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const profile = {
    id,
    name: String(name).trim(),
    type,
    host: String(host).trim(),
    port: Number(port),
    username: String(username || '').trim(),
    status: 'STOPPED',
    lastError: null,
    createdAt: now,
    updatedAt: now,
    runtimeContainerName: null,
    runtimeImage: RUNTIME_IMAGES[type],
    openvpn: type === 'OPENVPN' ? sanitizeOpenvpnConfig(req.body.openvpn) : null,
    ipsec: type === 'IPSEC' ? sanitizeIpsecConfig(req.body.ipsec) : null,
    wireguard: type === 'WIREGUARD' ? sanitizeWireguardConfig(req.body.wireguard) : null,
    firewall: sanitizeFirewallConfig(req.body.firewall),
    portForwarding: sanitizePortForwardingConfig(req.body.portForwarding)
  };

  profiles.set(id, profile);
  await queuePersist();
  res.status(201).json(toDto(profile));
});

app.patch('/vpn-profiles/:id', async (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ message: 'Profile not found' });
  }

  if (profile.status === 'CONNECTED') {
    return res.status(409).json({ message: 'Disconnect the profile before editing it' });
  }

  const effectiveBody = {
    ...profile,
    ...req.body,
    type: req.body?.type !== undefined ? req.body.type : profile.type,
    openvpn: req.body?.openvpn !== undefined ? mergeOpenvpnConfig(profile.openvpn, req.body.openvpn) : profile.openvpn,
    ipsec: req.body?.ipsec !== undefined ? mergeIpsecConfig(profile.ipsec, req.body.ipsec) : profile.ipsec,
    wireguard: req.body?.wireguard !== undefined
      ? mergeWireguardConfig(profile.wireguard, req.body.wireguard)
      : profile.wireguard
  };

  const errors = validateProfileInput(effectiveBody, false);
  if (errors.length > 0) {
    return res.status(400).json({ message: errors.join('; ') });
  }

  const { name, type, host, port, username } = req.body || {};
  if (name !== undefined) profile.name = String(name).trim();
  if (type !== undefined) {
    profile.type = type;
    profile.runtimeImage = RUNTIME_IMAGES[type];
  }
  if (host !== undefined) profile.host = String(host).trim();
  if (port !== undefined) profile.port = Number(port);
  if (username !== undefined) profile.username = String(username || '').trim();
  profile.openvpn = profile.type === 'OPENVPN' ? mergeOpenvpnConfig(profile.openvpn, effectiveBody.openvpn) : null;
  profile.ipsec = profile.type === 'IPSEC' ? mergeIpsecConfig(profile.ipsec, effectiveBody.ipsec) : null;
  profile.wireguard = profile.type === 'WIREGUARD' ? mergeWireguardConfig(profile.wireguard, effectiveBody.wireguard) : null;
  profile.firewall = sanitizeFirewallConfig(req.body.firewall !== undefined ? req.body.firewall : profile.firewall);
  profile.portForwarding = sanitizePortForwardingConfig(
    req.body.portForwarding !== undefined ? req.body.portForwarding : profile.portForwarding
  );
  profile.updatedAt = new Date().toISOString();

  profiles.set(profile.id, profile);
  await queuePersist();
  res.json(toDto(profile));
});

app.delete('/vpn-profiles/:id', async (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ message: 'Profile not found' });
  }

  if (profile.runtimeContainerName) {
    await removeRuntimeContainer(profile.runtimeContainerName);
  }

  profiles.delete(req.params.id);
  await queuePersist();
  res.status(204).send();
});

app.post('/vpn-profiles/:id/connect', async (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ message: 'Profile not found' });
  }

  try {
    const runtime = await createRuntimeContainer(profile);
    profile.status = 'CONNECTED';
    profile.runtimeContainerName = runtime.containerName;
    profile.runtimeImage = runtime.imageName;
    profile.lastError = null;
    profile.updatedAt = new Date().toISOString();
    await queuePersist();

    const runtimeStatus = await fetchRuntimeStatus(runtime.containerName);
    res.json({ profile: toDto(profile), runtime: runtimeStatus });
  } catch (error) {
    profile.status = 'ERROR';
    profile.lastError = error.message;
    profile.updatedAt = new Date().toISOString();
    await queuePersist();
    res.status(502).json({ message: error.message, profile: toDto(profile) });
  }
});

app.post('/vpn-profiles/:id/disconnect', async (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ message: 'Profile not found' });
  }

  try {
    if (profile.runtimeContainerName) {
      await removeRuntimeContainer(profile.runtimeContainerName);
    }

    profile.status = 'STOPPED';
    profile.lastError = null;
    profile.updatedAt = new Date().toISOString();
    profile.runtimeContainerName = null;
    await queuePersist();

    res.json({ profile: toDto(profile) });
  } catch (error) {
    profile.status = 'ERROR';
    profile.lastError = error.message;
    profile.updatedAt = new Date().toISOString();
    await queuePersist();
    res.status(502).json({ message: error.message, profile: toDto(profile) });
  }
});

app.get('/vpn-instances', async (req, res) => {
  res.json(await collectInstanceStatuses());
});

app.get('/monitoring/status', async (req, res) => {
  res.json(await buildMonitoringSnapshot());
});

app.get('/metrics', async (req, res) => {
  res.type('text/plain; version=0.0.4; charset=utf-8');
  res.send(await buildPrometheusMetrics());
});

async function bootstrap() {
  await loadProfiles();
  await reconcileProfilesOnStartup();
}

app.listen(PORT, () => {
  console.log(`manager-api listening on port ${PORT}`);
  bootstrap().catch((error) => {
    startupState = 'ERROR';
    startupError = error.message;
    console.error('manager-api bootstrap failed', error);
  });
});

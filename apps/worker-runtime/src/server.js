const express = require('express');
const dns = require('dns').promises;
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const PORT = Number(process.env.PORT || 8080);
const VPN_TYPE = process.env.VPN_TYPE || 'UNKNOWN';
const PROFILE_ID = process.env.VPN_PROFILE_ID || 'unknown-profile';
const PROFILE_NAME = process.env.VPN_PROFILE_NAME || 'Unnamed profile';
const PROFILE_HOST = process.env.VPN_PROFILE_HOST || '';
const PROFILE_PORT = process.env.VPN_PROFILE_PORT || '';
const PROFILE_USERNAME = process.env.VPN_PROFILE_USERNAME || '';
const WATCHDOG_INTERVAL_MS = Number(process.env.RUNTIME_WATCHDOG_INTERVAL_MS || 15000);
const STALE_HANDSHAKE_SECONDS = Number(process.env.RUNTIME_STALE_HANDSHAKE_SECONDS || 180);
const OPENVPN_INTERFACE_TIMEOUT_MS = Number(process.env.RUNTIME_OPENVPN_INTERFACE_TIMEOUT_MS || 90000);
const OPENVPN_STARTUP_LOG_TAIL = Number(process.env.RUNTIME_OPENVPN_STARTUP_LOG_TAIL || 30);
const IPSEC_INTERFACE_MISSING_GRACE_MS = Number(process.env.RUNTIME_IPSEC_INTERFACE_MISSING_GRACE_MS || 300000);
const IPSEC_KEEPALIVE_ENABLED = String(process.env.RUNTIME_IPSEC_KEEPALIVE_ENABLED || 'true').toLowerCase() !== 'false';
const IPSEC_KEEPALIVE_INTERVAL_MS = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_INTERVAL_MS || 10000);
const IPSEC_KEEPALIVE_TIMEOUT_MS = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_TIMEOUT_MS || 3000);
const IPSEC_KEEPALIVE_FAILURE_THRESHOLD = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_FAILURE_THRESHOLD || 4);
const IPSEC_KEEPALIVE_SOFT_RESET_THRESHOLD = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_SOFT_RESET_THRESHOLD || 2);
const IPSEC_KEEPALIVE_L2TP_REDIAL_THRESHOLD = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_L2TP_REDIAL_THRESHOLD || 2);
const IPSEC_KEEPALIVE_MIN_RECOVERY_INTERVAL_MS = Number(process.env.RUNTIME_IPSEC_KEEPALIVE_MIN_RECOVERY_INTERVAL_MS || 180000);
const IPSEC_FAILFAST_RESET_ENABLED = String(process.env.RUNTIME_IPSEC_FAILFAST_RESET_ENABLED || 'true').toLowerCase() !== 'false';
const IS_IPSEC_TYPE = VPN_TYPE === 'IPSEC' || VPN_TYPE === 'IPSEC.B';

const app = express();
app.use(express.json());

const state = {
  status: VPN_TYPE === 'OPENVPN' || VPN_TYPE === 'WIREGUARD' || IS_IPSEC_TYPE ? 'STARTING' : 'CONNECTED',
  connectedAt: VPN_TYPE === 'OPENVPN' || VPN_TYPE === 'WIREGUARD' || IS_IPSEC_TYPE ? null : new Date().toISOString(),
  lastHandshakeAt: null,
  firewallStatus: 'NOT_CONFIGURED',
  firewallMessage: null,
  portForwardingStatus: 'NOT_CONFIGURED',
  portForwardingMessage: null,
  lastMessage: `${VPN_TYPE} runtime container started for ${PROFILE_HOST}:${PROFILE_PORT}`,
  profileSummary: {
    profileId: PROFILE_ID,
    name: PROFILE_NAME,
    host: PROFILE_HOST,
    port: PROFILE_PORT,
    username: PROFILE_USERNAME
  },
  logs: [],
  startupError: null,
  cleanupCommands: [],
  reconnectAttempts: 0,
  ipsec: {
    interfaceMissingSince: null,
    keepaliveFailing: false,
    keepaliveFailureCount: 0,
    keepaliveSoftResetAppliedAtFailure: 0,
    keepaliveL2tpRedialAppliedAtFailure: 0,
    redialInProgress: false,
    clientResetGateEnabled: false,
    lastRecoveryAt: null,
    lastL2tpRedialAt: null,
    activeInterface: null,
    lastNetworkReconcileAt: null
  },
  openvpn: {
    initializedAt: null,
    lastWriteErrorAt: null,
    writeErrorCount: 0,
    recentLogs: []
  }
};

let watchdogTimer = null;
let recoverInProgress = false;
let openvpnProcess = null;
let openvpnRuntime = null;
let xl2tpdProcess = null;
let ipsecRuntime = null;
let ipsecKeepaliveTimer = null;

function detectOpenvpnInterfaceFromConfig(configText) {
  const lines = String(configText || '').split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    const match = line.match(/^dev\s+(.+)$/i);
    if (!match) {
      continue;
    }
    const devValue = match[1].trim().replace(/^["']|["']$/g, '');
    if (devValue === 'tun') return 'tun0';
    if (devValue === 'tap') return 'tap0';
    return devValue;
  }
  return 'tun0';
}

function log(message) {
  const line = `[${new Date().toISOString()}] ${message}`;
  state.logs.push(line);
  if (state.logs.length > 400) state.logs.shift();
  console.log(line);
}

function run(command, args, options = {}) {
  log(`run: ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options
  });

  if (result.stdout?.trim()) log(`stdout: ${result.stdout.trim()}`);
  if (result.stderr?.trim()) log(`stderr: ${result.stderr.trim()}`);

  if (result.status !== 0) {
    const details = [result.stderr?.trim(), result.stdout?.trim()].filter(Boolean).join(' | ');
    throw new Error(`${command} ${args.join(' ')} failed with code ${result.status}${details ? `: ${details}` : ''}`);
  }

  return result.stdout || '';
}

function runSafe(command, args) {
  try {
    run(command, args);
  } catch (error) {
    log(`cleanup warning: ${error.message}`);
  }
}

function parseCsv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeKey(value) {
  return String(value || '').replace(/\s+/g, '');
}

function parseFirewallConfig() {
  try {
    const parsed = JSON.parse(process.env.FIREWALL_CONFIG_JSON || '{}');
    return {
      enabled: Boolean(parsed.enabled),
      mode: String(parsed.mode || 'BASIC').toUpperCase() === 'ADVANCED' ? 'ADVANCED' : 'BASIC',
      basicRules: Array.isArray(parsed.basicRules) ? parsed.basicRules : [],
      advancedRules: String(parsed.advancedRules || '')
    };
  } catch (error) {
    log(`Failed to parse firewall config: ${error.message}`);
    return { enabled: false, mode: 'BASIC', basicRules: [], advancedRules: '' };
  }
}

function parsePortForwardingConfig() {
  try {
    const parsed = JSON.parse(process.env.PORT_FORWARDING_CONFIG_JSON || '{}');
    return {
      enabled: Boolean(parsed.enabled),
      rules: Array.isArray(parsed.rules) ? parsed.rules : []
    };
  } catch (error) {
    log(`Failed to parse port forwarding config: ${error.message}`);
    return { enabled: false, rules: [] };
  }
}

function registerCleanup(command, args) {
  state.cleanupCommands.push(() => runSafe(command, args));
}

function registerDeleteVariant(command, addArgs) {
  const deleteArgs = [...addArgs];
  const actionIndex = deleteArgs.findIndex((item) => item === '-A' || item === '-I');
  if (actionIndex >= 0) deleteArgs[actionIndex] = '-D';
  registerCleanup(command, deleteArgs);
}

function enableIpForwarding() {
  const procPath = '/proc/sys/net/ipv4/ip_forward';

  try {
    const currentValue = fs.readFileSync(procPath, 'utf8').trim() || '0';
    if (currentValue === '1') {
      return;
    }
  } catch (error) {
    log(`ip_forward read warning: ${error.message}`);
  }

  try {
    fs.writeFileSync(procPath, '1\n');
    registerCleanup('sh', ['-lc', `printf '0\n' > ${procPath}`]);
    return;
  } catch (error) {
    log(`ip_forward write warning: ${error.message}`);
  }

  try {
    const currentValue = fs.readFileSync(procPath, 'utf8').trim() || '0';
    if (currentValue === '1') {
      return;
    }
  } catch (error) {
    log(`ip_forward reread warning: ${error.message}`);
  }

  throw new Error('IPv4 forwarding is disabled inside the runtime container');
}

function detectVpnInterface() {
  const candidates = ['tun0', 'tun1', 'tap0', 'wg0', 'ppp0', 'ppp1'];
  for (const iface of candidates) {
    try {
      run('ip', ['link', 'show', iface]);
      return iface;
    } catch {}
  }

  try {
    const output = run('sh', ['-lc', "ip -o link show | awk -F': ' '{print $2}' | grep -E '^(tun|tap|wg)' | head -n 1"]).trim();
    return output || null;
  } catch {
    return null;
  }
}

function applyBuiltInIptablesForOpenvpn(vpnInterface) {
  const rules = [
    ['iptables', ['-A', 'OUTPUT', '-o', vpnInterface, '-j', 'ACCEPT']],
    ['iptables', ['-A', 'INPUT', '-i', vpnInterface, '-j', 'ACCEPT']]
  ];

  for (const [command, args] of rules) {
    run(command, args);
    registerDeleteVariant(command, args);
  }
}

function applyBuiltInIptablesForIpsec(vpnInterface) {
  const rules = [
    ['iptables', ['-A', 'OUTPUT', '-o', vpnInterface, '-j', 'ACCEPT']],
    ['iptables', ['-A', 'INPUT', '-i', vpnInterface, '-j', 'ACCEPT']]
  ];

  for (const [command, args] of rules) {
    ensureIptablesRule(command, args);
  }
}

function buildBasicFirewallArgs(rule) {
  const args = ['-A', rule.chain];
  if (rule.protocol && rule.protocol !== 'all') args.push('-p', rule.protocol);
  if (rule.source) args.push('-s', rule.source);
  if (rule.destination) args.push('-d', rule.destination);
  if (rule.destinationPort && (rule.protocol === 'tcp' || rule.protocol === 'udp')) args.push('--dport', rule.destinationPort);
  if (rule.comment) args.push('-m', 'comment', '--comment', rule.comment);
  args.push('-j', rule.action);
  return args;
}

function applyAdvancedFirewallRule(line) {
  const parts = line.trim().split(/\s+/);
  const [command, ...args] = parts;
  if (!command || !['iptables', 'ip6tables'].includes(command)) throw new Error(`Unsupported advanced firewall command: ${line}`);
  run(command, args);
  registerDeleteVariant(command, args);
}

function applyCustomFirewall() {
  const firewall = parseFirewallConfig();
  if (!firewall.enabled) {
    state.firewallStatus = 'NOT_CONFIGURED';
    state.firewallMessage = 'Custom firewall rules are disabled';
    return;
  }

  try {
    if (firewall.mode === 'BASIC') {
      for (const rule of firewall.basicRules) {
        const args = buildBasicFirewallArgs(rule);
        run('iptables', args);
        registerDeleteVariant('iptables', args);
      }
      state.firewallStatus = 'APPLIED';
      state.firewallMessage = `${firewall.basicRules.length} basic firewall rule(s) applied`;
      return;
    }

    const lines = firewall.advancedRules.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    for (const line of lines) applyAdvancedFirewallRule(line);
    state.firewallStatus = 'APPLIED';
    state.firewallMessage = `${lines.length} advanced firewall rule(s) applied`;
  } catch (error) {
    state.firewallStatus = 'ERROR';
    state.firewallMessage = error.message;
    throw error;
  }
}

function applyPortForwarding(vpnInterface) {
  const config = parsePortForwardingConfig();
  if (!config.enabled) {
    state.portForwardingStatus = 'NOT_CONFIGURED';
    state.portForwardingMessage = 'Port forwarding is disabled';
    return;
  }

  try {
    enableIpForwarding();
    const activeRules = config.rules.filter((rule) => rule.enabled !== false);

    for (const rule of activeRules) {
      const protocol = rule.protocol === 'udp' ? 'udp' : 'tcp';
      const hostPort = String(rule.hostPort).trim();
      const targetAddress = String(rule.targetAddress).trim();
      const targetPort = String(rule.targetPort).trim() || hostPort;

      if (!hostPort || !targetAddress || !targetPort) throw new Error('Incomplete port forwarding rule');

      if (VPN_TYPE === 'WIREGUARD') {
        run('ip', ['route', 'replace', targetAddress, 'dev', vpnInterface]);
        registerCleanup('ip', ['route', 'del', targetAddress, 'dev', vpnInterface]);
      }

      const preroutingArgs = ['-t', 'nat', '-A', 'PREROUTING', '-i', 'eth0', '-p', protocol, '--dport', hostPort, '-j', 'DNAT', '--to-destination', `${targetAddress}:${targetPort}`];
      ensureIptablesRule('iptables', preroutingArgs);

      const forwardArgs = ['-A', 'FORWARD', '-i', 'eth0', '-o', vpnInterface, '-d', targetAddress, '-p', protocol, '--dport', targetPort, '-j', 'ACCEPT'];
      ensureIptablesRule('iptables', forwardArgs);

      const reverseForwardArgs = ['-A', 'FORWARD', '-i', vpnInterface, '-o', 'eth0', '-s', targetAddress, '-p', protocol, '--sport', targetPort, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'];
      ensureIptablesRule('iptables', reverseForwardArgs);

      const postroutingArgs = ['-t', 'nat', '-A', 'POSTROUTING', '-o', vpnInterface, '-d', targetAddress, '-p', protocol, '--dport', targetPort, '-j', 'MASQUERADE'];
      ensureIptablesRule('iptables', postroutingArgs);
    }

    state.portForwardingStatus = 'APPLIED';
    state.portForwardingMessage = `${activeRules.length} port forward(s) applied`;
  } catch (error) {
    state.portForwardingStatus = 'ERROR';
    state.portForwardingMessage = error.message;
    throw error;
  }
}

function cleanupNetworking() {
  for (const action of [...state.cleanupCommands].reverse()) action();
  state.cleanupCommands = [];
}

function buildWireguardConfigFile(config) {
  const lines = [
    '[Interface]',
    `PrivateKey = ${config.privateKey}`,
    '',
    '[Peer]',
    `PublicKey = ${config.peerPublicKey}`,
    `Endpoint = ${config.endpointHost}:${config.endpointPort}`,
    `AllowedIPs = ${config.allowedIps.join(', ')}`
  ];
  if (config.presharedKey) lines.push(`PresharedKey = ${config.presharedKey}`);
  if (config.persistentKeepalive) lines.push(`PersistentKeepalive = ${config.persistentKeepalive}`);
  return `${lines.join(os.EOL)}${os.EOL}`;
}

function getDefaultRouteInfo() {
  const output = run('sh', ['-lc', 'ip route show default | head -n 1']).trim();
  if (!output) throw new Error('No default route found before WireGuard bootstrap');
  const gatewayMatch = output.match(/\bvia\s+([0-9.]+)/);
  const devMatch = output.match(/\bdev\s+(\S+)/);
  return { gateway: gatewayMatch ? gatewayMatch[1] : null, dev: devMatch ? devMatch[1] : null };
}

async function resolveEndpointHost(host) {
  try {
    const result = await dns.lookup(host, { family: 4 });
    return result.address;
  } catch {
    return host;
  }
}

function bringInterfaceUpWithFallback(interfaceName) {
  try {
    run('ip', ['link', 'add', 'dev', interfaceName, 'type', 'wireguard']);
    return 'kernel';
  } catch (error) {
    log(`kernel WireGuard unavailable, falling back to wireguard-go: ${error.message}`);
    run('wireguard-go', [interfaceName]);
    return 'wireguard-go';
  }
}

function applyRoutes(config, endpointIp, defaultRoute) {
  if (endpointIp && defaultRoute.gateway && defaultRoute.dev) {
    run('ip', ['route', 'replace', endpointIp, 'via', defaultRoute.gateway, 'dev', defaultRoute.dev]);
    registerCleanup('ip', ['route', 'del', endpointIp, 'via', defaultRoute.gateway, 'dev', defaultRoute.dev]);
  }
  for (const allowedIp of config.allowedIps) {
    run('ip', ['route', 'replace', allowedIp, 'dev', config.interfaceName]);
    registerCleanup('ip', ['route', 'del', allowedIp, 'dev', config.interfaceName]);
  }
}

function applyBuiltInIptablesForWireguard(endpointIp) {
  const rules = [
    ['iptables', ['-A', 'OUTPUT', '-o', 'wg0', '-j', 'ACCEPT']],
    ['iptables', ['-A', 'INPUT', '-i', 'wg0', '-j', 'ACCEPT']]
  ];
  if (endpointIp) rules.push(['iptables', ['-A', 'OUTPUT', '-d', endpointIp, '-j', 'ACCEPT']]);
  for (const [command, args] of rules) {
    run(command, args);
    registerDeleteVariant(command, args);
  }
}

function collectWireguardHandshakeInfo() {
  try {
    const output = run('wg', ['show', 'wg0', 'latest-handshakes']).trim();
    const line = output.split(/\r?\n/).find(Boolean);
    if (!line) return { hasInterface: false, handshakeAt: null };
    const parts = line.trim().split(/\s+/);
    const latestHandshake = Number(parts[parts.length - 1] || 0);
    return { hasInterface: true, handshakeAt: latestHandshake > 0 ? new Date(latestHandshake * 1000).toISOString() : null };
  } catch {
    return { hasInterface: false, handshakeAt: null };
  }
}

async function configureWireguard() {
  const interfaceName = 'wg0';
  const config = {
    interfaceName,
    tunnelAddresses: parseCsv(process.env.WG_TUNNEL_ADDRESS),
    privateKey: normalizeKey(process.env.WG_PRIVATE_KEY),
    peerPublicKey: normalizeKey(process.env.WG_PEER_PUBLIC_KEY),
    presharedKey: normalizeKey(process.env.WG_PRESHARED_KEY),
    allowedIps: parseCsv(process.env.WG_ALLOWED_IPS),
    dnsServers: parseCsv(process.env.WG_DNS_SERVERS),
    endpointHost: String(process.env.VPN_PROFILE_HOST || '').trim(),
    endpointPort: String(process.env.VPN_PROFILE_PORT || '').trim(),
    persistentKeepalive: String(process.env.WG_PERSISTENT_KEEPALIVE || '').trim()
  };

  if (config.tunnelAddresses.length === 0 || !config.privateKey || !config.peerPublicKey || config.allowedIps.length === 0 || !config.endpointHost || !config.endpointPort) {
    throw new Error('Incomplete WireGuard configuration supplied to runtime container');
  }

  state.status = 'STARTING';
  state.lastMessage = 'Bootstrapping WireGuard tunnel';

  const defaultRoute = getDefaultRouteInfo();
  const endpointIp = await resolveEndpointHost(config.endpointHost);
  const transport = bringInterfaceUpWithFallback(interfaceName);
  registerCleanup('ip', ['link', 'del', 'dev', interfaceName]);

  const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-runtime-'));
  const configPath = path.join(configDir, 'wg0.conf');
  fs.writeFileSync(configPath, buildWireguardConfigFile(config), { mode: 0o600 });

  run('wg', ['setconf', interfaceName, configPath]);
  for (const address of config.tunnelAddresses) run('ip', ['address', 'add', address, 'dev', interfaceName]);
  run('ip', ['link', 'set', 'mtu', '1420', 'up', 'dev', interfaceName]);

  applyRoutes(config, endpointIp, defaultRoute);
  applyBuiltInIptablesForWireguard(endpointIp);
  applyCustomFirewall();
  applyPortForwarding(interfaceName);

  if (config.dnsServers.length > 0) log(`DNS servers requested but not applied automatically inside the container: ${config.dnsServers.join(', ')}`);

  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastMessage = `WireGuard tunnel is active via ${transport} to ${config.endpointHost}:${config.endpointPort}`;
  const handshakeInfo = collectWireguardHandshakeInfo();
  state.lastHandshakeAt = handshakeInfo.handshakeAt;
  log(state.lastMessage);
}

function buildOpenvpnConfigFiles() {
  const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ovpn-runtime-'));
  const configPath = path.join(runtimeDir, 'client.ovpn');
  const authPath = path.join(runtimeDir, 'auth.txt');
  const caPath = path.join(runtimeDir, 'ca.crt');
  const certPath = path.join(runtimeDir, 'client.crt');
  const keyPath = path.join(runtimeDir, 'client.key');
  const tlsAuthPath = path.join(runtimeDir, 'ta.key');

  let configText = String(process.env.OPENVPN_CONFIG_TEXT || '');
  const username = String(process.env.OPENVPN_USERNAME || '').trim();
  const password = String(process.env.OPENVPN_PASSWORD || '').trim();
  const caText = String(process.env.OPENVPN_CA_TEXT || '').trim();
  const certText = String(process.env.OPENVPN_CERT_TEXT || '').trim();
  const keyText = String(process.env.OPENVPN_KEY_TEXT || '').trim();
  const tlsAuthText = String(process.env.OPENVPN_TLS_AUTH_TEXT || '').trim();
  const keyDirection = String(process.env.OPENVPN_KEY_DIRECTION || '').trim();

  if (!configText.trim()) throw new Error('OPENVPN_CONFIG_TEXT is empty');
  if (!caText) throw new Error('OPENVPN_CA_TEXT is empty');
  if (!certText) throw new Error('OPENVPN_CERT_TEXT is empty');
  if (!keyText) throw new Error('OPENVPN_KEY_TEXT is empty');

  configText = configText.replace(/\r\n/g, '\n');
  configText = configText.replace(/^\s*daemon\s*$/gim, '');
  configText = configText.replace(/^\s*log\s+.+$/gim, '');
  configText = configText.replace(/^\s*log-append\s+.+$/gim, '');

  const expectedInterface = detectOpenvpnInterfaceFromConfig(configText);
  if (expectedInterface.startsWith('tun') && !/^\s*topology\s+\S+/gim.test(configText)) {
    configText = `${configText.trim()}\ntopology subnet\n`;
  }
  if (!/^\s*remote-cert-tls\s+server\s*$/gim.test(configText) && !/^\s*ns-cert-type\s+server\s*$/gim.test(configText)) {
    configText = `${configText.trim()}\nremote-cert-tls server\n`;
  }

  fs.writeFileSync(caPath, `${caText}\n`, { mode: 0o600 });
  fs.writeFileSync(certPath, `${certText}\n`, { mode: 0o600 });
  fs.writeFileSync(keyPath, `${keyText}\n`, { mode: 0o600 });
  if (tlsAuthText) {
    fs.writeFileSync(tlsAuthPath, `${tlsAuthText}\n`, { mode: 0o600 });
  }

  if (/^\s*ca\s+.+$/gim.test(configText)) {
    configText = configText.replace(/^\s*ca\s+.+$/gim, `ca ${caPath}`);
  } else {
    configText = `${configText.trim()}\nca ${caPath}\n`;
  }

  if (/^\s*cert\s+.+$/gim.test(configText)) {
    configText = configText.replace(/^\s*cert\s+.+$/gim, `cert ${certPath}`);
  } else {
    configText = `${configText.trim()}\ncert ${certPath}\n`;
  }

  if (/^\s*key\s+.+$/gim.test(configText)) {
    configText = configText.replace(/^\s*key\s+.+$/gim, `key ${keyPath}`);
  } else {
    configText = `${configText.trim()}\nkey ${keyPath}\n`;
  }
  if (/^\s*tls-auth\s+.+$/gim.test(configText)) {
    configText = configText.replace(/^\s*tls-auth\s+.+$/gim, `tls-auth ${tlsAuthPath}${keyDirection ? ` ${keyDirection}` : ''}`);
  } else if (tlsAuthText) {
    configText = `${configText.trim()}\ntls-auth ${tlsAuthPath}${keyDirection ? ` ${keyDirection}` : ''}\n`;
  }

  if (keyDirection) {
    if (/^\s*key-direction\s+.+$/gim.test(configText)) {
      configText = configText.replace(/^\s*key-direction\s+.+$/gim, `key-direction ${keyDirection}`);
    } else if (!/^\s*tls-auth\s+.+$/gim.test(configText)) {
      configText = `${configText.trim()}\nkey-direction ${keyDirection}\n`;
    }
  }

  if (username || password) {
    fs.writeFileSync(authPath, `${username}\n${password}\n`, { mode: 0o600 });
    if (/^\s*auth-user-pass\b/gm.test(configText)) {
      configText = configText.replace(/^\s*auth-user-pass\b.*$/gm, `auth-user-pass ${authPath}`);
    } else {
      configText = `${configText.trim()}\nauth-user-pass ${authPath}\n`;
    }
  }

  configText = `${configText.trim()}\nscript-security 2\nverb 3\n`;
  fs.writeFileSync(configPath, configText, { mode: 0o600 });
  return {
    runtimeDir,
    configPath,
    authPath: fs.existsSync(authPath) ? authPath : null,
    caPath,
    certPath,
    keyPath,
    tlsAuthPath: fs.existsSync(tlsAuthPath) ? tlsAuthPath : null,
    expectedInterface: detectOpenvpnInterfaceFromConfig(configText)
  };
}

function buildIpsecRuntimeFiles() {
  const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsec-runtime-'));
  const connectionName = 'l2tp-psk';
  const lacName = 'vpn-lac';
  const pppOptionsPath = '/etc/ppp/options.l2tpd.client';
  const chapSecretsPath = '/etc/ppp/chap-secrets';
  const xl2tpdConfPath = '/etc/xl2tpd/xl2tpd.conf';
  const ipsecConfPath = '/etc/ipsec.conf';
  const ipsecSecretsPath = '/etc/ipsec.secrets';
  const controlPath = '/var/run/xl2tpd/l2tp-control';

  const serverHost = String(process.env.VPN_PROFILE_HOST || '').trim();
  const userId = String(process.env.IPSEC_USER_ID || process.env.VPN_PROFILE_USERNAME || '').trim();
  const password = String(process.env.IPSEC_PASSWORD || '').trim();
  const preSharedKey = String(process.env.IPSEC_PSK || '').trim();
  const remoteIdentifier = String(process.env.IPSEC_REMOTE_ID || '').trim() || serverHost;
  const localIdentifier = String(process.env.IPSEC_LOCAL_ID || '').trim();
  const dnsServers = parseCsv(process.env.IPSEC_DNS_SERVERS || '');
  const mtu = String(process.env.IPSEC_MTU || '').trim() || '1410';
  const mru = String(process.env.IPSEC_MRU || '').trim() || '1410';

  if (!serverHost || !userId || !password || !preSharedKey) {
    throw new Error('Incomplete IPsec/L2TP configuration supplied to runtime container');
  }

  fs.mkdirSync('/etc/xl2tpd', { recursive: true });
  fs.mkdirSync('/etc/ppp', { recursive: true });
  fs.mkdirSync('/var/run/xl2tpd', { recursive: true });

  const ipsecConf = [
    'config setup',
    '  uniqueids=no',
    '',
    `conn ${connectionName}`,
    '  keyexchange=ikev1',
    '  authby=secret',
    '  type=transport',
    '  ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!',
    '  esp=aes256-sha1,aes128-sha1,3des-sha1!',
    '  ikelifetime=8h',
    '  keylife=1h',
    '  rekeymargin=3m',
    '  keyingtries=%forever',
    '  dpddelay=30s',
    '  dpdtimeout=120s',
    '  dpdaction=restart',
    '  left=%defaultroute',
    `  leftid=${localIdentifier || '%any'}`,
    '  leftprotoport=17/1701',
    `  right=${serverHost}`,
    `  rightid=${remoteIdentifier}`,
    '  rightprotoport=17/1701',
    '  auto=add',
    ''
  ].join('\n');

  const ipsecSecrets = `${localIdentifier || '%any'} ${remoteIdentifier} : PSK "${preSharedKey.replace(/"/g, '\\"')}"\n`;

  const xl2tpdConf = [
    '[global]',
    'access control = no',
    'port = 1701',
    '',
    `[lac ${lacName}]`,
    `lns = ${serverHost}`,
    `pppoptfile = ${pppOptionsPath}`,
    'length bit = yes',
    'redial = yes',
    'redial timeout = 5',
    'max redials = 1000',
    `name = ${userId}`,
    ''
  ].join('\n');

  const pppOptions = [
    `name "${userId}"`,
    `password "${password.replace(/"/g, '\\"')}"`,
    `remotename "${lacName}"`,
    'debug',
    'dump',
    'logfd 2',
    'kdebug 7',
    'ipcp-accept-local',
    'ipcp-accept-remote',
    'refuse-eap',
    'require-mschap-v2',
    'noccp',
    'nodeflate',
    'nobsdcomp',
    'noauth',
    'nodefaultroute',
    'persist',
    'maxfail 0',
    'holdoff 5',
    `mtu ${mtu}`,
    `mru ${mru}`,
    'usepeerdns',
    'connect-delay 5000',
    ''
  ].join('\n');

  const chapSecrets = `"${userId}" "${lacName}" "${password.replace(/"/g, '\\"')}" *\n`;

  fs.writeFileSync(ipsecConfPath, ipsecConf, { mode: 0o600 });
  fs.writeFileSync(ipsecSecretsPath, ipsecSecrets, { mode: 0o600 });
  fs.writeFileSync(xl2tpdConfPath, xl2tpdConf, { mode: 0o600 });
  fs.writeFileSync(pppOptionsPath, pppOptions, { mode: 0o600 });
  fs.writeFileSync(chapSecretsPath, chapSecrets, { mode: 0o600 });

  return {
    runtimeDir,
    connectionName,
    lacName,
    controlPath,
    dnsServers
  };
}

function stopOpenvpnProcess() {
  if (openvpnProcess && !openvpnProcess.killed) {
    openvpnProcess.kill('SIGTERM');
  }
  openvpnProcess = null;
  state.openvpn.initializedAt = null;
  state.openvpn.lastWriteErrorAt = null;
  state.openvpn.writeErrorCount = 0;
  state.openvpn.recentLogs = [];
}

function detectIpsecPppInterface() {
  const candidates = ['ppp0', 'ppp1', 'ppp2', 'ppp3'];
  for (const iface of candidates) {
    try {
      run('ip', ['link', 'show', iface]);
      return iface;
    } catch {}
  }

  try {
    const output = run('sh', ['-lc', "ip -o link show | awk -F': ' '$2 ~ /^ppp/ {print $2; exit}'"]).trim();
    return output || null;
  } catch {
    return null;
  }
}

function isInterfaceUp(interfaceName) {
  try {
    const line = run('sh', ['-lc', `ip -o link show ${interfaceName} | head -n 1`]).trim();
    if (!line) return false;
    return /<[^>]*\bUP\b[^>]*\bLOWER_UP\b[^>]*>/.test(line);
  } catch {
    return false;
  }
}

function commandSucceeds(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options
  });
  return result.status === 0;
}

function toCheckArgs(addArgs) {
  const checkArgs = [...addArgs];
  const actionIndex = checkArgs.findIndex((item) => item === '-A' || item === '-I');
  if (actionIndex >= 0) checkArgs[actionIndex] = '-C';
  return checkArgs;
}

function ensureIptablesRule(command, addArgs) {
  const checkArgs = toCheckArgs(addArgs);
  if (commandSucceeds(command, checkArgs)) {
    return false;
  }
  run(command, addArgs);
  registerDeleteVariant(command, addArgs);
  return true;
}

function getIpsecKeepaliveTargets() {
  const config = parsePortForwardingConfig();
  if (!config.enabled) {
    return [];
  }

  const targets = new Map();
  for (const rule of config.rules.filter((item) => item.enabled !== false)) {
    const protocol = rule.protocol === 'udp' ? 'udp' : 'tcp';
    if (protocol !== 'tcp') continue;
    const host = String(rule.targetAddress || '').trim();
    const port = Number(String(rule.targetPort || rule.hostPort || '').trim());
    if (!host || !Number.isFinite(port) || port <= 0 || port > 65535) continue;
    targets.set(`${host}:${port}`, { host, port });
  }

  return Array.from(targets.values());
}

function probeTcpTarget(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

function forceResetPortForwardTcpSessions() {
  if (!IS_IPSEC_TYPE || !IPSEC_FAILFAST_RESET_ENABLED) {
    return;
  }

  const targets = getIpsecKeepaliveTargets();
  if (targets.length === 0) {
    return;
  }

  for (const target of targets) {
    const port = String(target.port);
    const tempRules = [
      ['-I', 'FORWARD', '1', '-i', 'eth0', '-d', target.host, '-p', 'tcp', '--dport', port, '-j', 'REJECT', '--reject-with', 'tcp-reset'],
      ['-I', 'FORWARD', '1', '-o', 'eth0', '-s', target.host, '-p', 'tcp', '--sport', port, '-j', 'REJECT', '--reject-with', 'tcp-reset']
    ];

    for (const addArgs of tempRules) {
      runSafe('iptables', addArgs);
      // Deleting an inserted rule must not include its insertion index.
      const delArgs = ['-D', 'FORWARD', ...addArgs.slice(3)];
      setTimeout(() => runSafe('iptables', delArgs), 1500);
    }

    if (commandSucceeds('sh', ['-lc', 'command -v conntrack >/dev/null 2>&1'])) {
      runSafe('conntrack', ['-D', '-p', 'tcp', '-d', target.host, '--dport', port]);
      runSafe('conntrack', ['-D', '-p', 'tcp', '-s', target.host, '--sport', port]);
    }
  }
}

function getIpsecResetGateRules() {
  const targets = getIpsecKeepaliveTargets();
  const rules = [];
  for (const target of targets) {
    const port = String(target.port);
    rules.push(['-I', 'FORWARD', '1', '-i', 'eth0', '-d', target.host, '-p', 'tcp', '--dport', port, '-j', 'REJECT', '--reject-with', 'tcp-reset']);
    rules.push(['-I', 'FORWARD', '1', '-o', 'eth0', '-s', target.host, '-p', 'tcp', '--sport', port, '-j', 'REJECT', '--reject-with', 'tcp-reset']);
  }
  return rules;
}

function setIpsecClientResetGate(enabled) {
  if (!IS_IPSEC_TYPE) return;
  if (enabled === state.ipsec.clientResetGateEnabled) return;

  const rules = getIpsecResetGateRules();
  if (rules.length === 0) return;

  if (enabled) {
    for (const addArgs of rules) {
      runSafe('iptables', addArgs);
    }
    state.ipsec.clientResetGateEnabled = true;
    return;
  }

  for (const addArgs of rules) {
    const delArgs = ['-D', 'FORWARD', ...addArgs.slice(3)];
    // Best-effort cleanup: remove all duplicates if any were inserted.
    for (let i = 0; i < 5; i += 1) {
      if (!commandSucceeds('iptables', delArgs)) break;
      runSafe('iptables', delArgs);
    }
  }
  state.ipsec.clientResetGateEnabled = false;
}

async function redialL2tpSession(reason = 'unspecified') {
  if (!IS_IPSEC_TYPE || !ipsecRuntime?.controlPath || !ipsecRuntime?.lacName || state.ipsec.redialInProgress) {
    return false;
  }

  state.ipsec.redialInProgress = true;
  try {
    log(`Attempting L2TP session redial: ${reason}`);
    setIpsecClientResetGate(true);
    run('sh', ['-lc', `printf 'd ${ipsecRuntime.lacName}\n' > ${ipsecRuntime.controlPath}`]);
    await sleep(800);
    run('sh', ['-lc', `printf 'c ${ipsecRuntime.lacName}\n' > ${ipsecRuntime.controlPath}`]);
    state.ipsec.lastL2tpRedialAt = new Date().toISOString();
    return true;
  } catch (error) {
    log(`L2TP redial failed: ${error.message}`);
    return false;
  } finally {
    state.ipsec.redialInProgress = false;
  }
}

async function runIpsecKeepaliveTick() {
  if (!IS_IPSEC_TYPE || !IPSEC_KEEPALIVE_ENABLED) {
    return;
  }
  if (recoverInProgress) {
    return;
  }

  const iface = detectVpnInterface();
  if (!iface || !iface.startsWith('ppp')) {
    return;
  }

  const targets = getIpsecKeepaliveTargets();
  if (targets.length === 0) {
    return;
  }

  const results = await Promise.all(
    targets.map((target) => probeTcpTarget(target.host, target.port, IPSEC_KEEPALIVE_TIMEOUT_MS))
  );
  const failed = results.some((ok) => !ok);

  if (failed) {
    state.ipsec.keepaliveFailureCount += 1;
    if (!state.ipsec.keepaliveFailing) {
      state.ipsec.keepaliveFailing = true;
      setIpsecClientResetGate(true);
      log(`IPsec keepalive probe failed for one or more targets: ${targets.map((t) => `${t.host}:${t.port}`).join(', ')}`);
    }

    if (
      state.ipsec.keepaliveFailureCount >= Math.max(1, IPSEC_KEEPALIVE_SOFT_RESET_THRESHOLD)
      && state.ipsec.keepaliveSoftResetAppliedAtFailure !== state.ipsec.keepaliveFailureCount
    ) {
      state.ipsec.keepaliveSoftResetAppliedAtFailure = state.ipsec.keepaliveFailureCount;
      forceResetPortForwardTcpSessions();
    }

    if (
      !recoverInProgress
      && state.ipsec.keepaliveFailureCount >= Math.max(1, IPSEC_KEEPALIVE_L2TP_REDIAL_THRESHOLD)
      && state.ipsec.keepaliveL2tpRedialAppliedAtFailure !== state.ipsec.keepaliveFailureCount
    ) {
      state.ipsec.keepaliveL2tpRedialAppliedAtFailure = state.ipsec.keepaliveFailureCount;
      try {
        const redialed = await redialL2tpSession(`keepalive failed ${state.ipsec.keepaliveFailureCount} time(s)`);
        if (redialed) {
          await sleep(1500);
          const postRedialResults = await Promise.all(
            targets.map((target) => probeTcpTarget(target.host, target.port, IPSEC_KEEPALIVE_TIMEOUT_MS))
          );
          const stillFailedAfterRedial = postRedialResults.some((ok) => !ok);
          if (stillFailedAfterRedial && !recoverInProgress) {
            state.status = 'DEGRADED';
            state.lastMessage = 'IPsec keepalive still failing after L2TP redial, forcing full recovery';
            state.ipsec.lastRecoveryAt = new Date().toISOString();
            await recoverTunnel('keepalive failed after l2tp redial');
            return;
          }
        }
      } catch (error) {
        log(`L2TP redial warning: ${error.message}`);
      }
    }

    if (!recoverInProgress && state.ipsec.keepaliveFailureCount >= Math.max(1, IPSEC_KEEPALIVE_FAILURE_THRESHOLD)) {
      const now = Date.now();
      const lastRecoveryAt = state.ipsec.lastRecoveryAt ? new Date(state.ipsec.lastRecoveryAt).getTime() : 0;
      if (lastRecoveryAt > 0 && now - lastRecoveryAt < Math.max(0, IPSEC_KEEPALIVE_MIN_RECOVERY_INTERVAL_MS)) {
        state.status = 'DEGRADED';
        state.lastMessage = `IPsec keepalive failing ${state.ipsec.keepaliveFailureCount} time(s), waiting before full recovery`;
        return;
      }

      state.status = 'DEGRADED';
      state.lastMessage = `IPsec keepalive failed ${state.ipsec.keepaliveFailureCount} time(s), triggering fail-fast recovery`;
      state.ipsec.lastRecoveryAt = new Date().toISOString();
      await recoverTunnel('ipsec keepalive failed');
    }
    return;
  }

  state.ipsec.keepaliveFailureCount = 0;
  state.ipsec.keepaliveSoftResetAppliedAtFailure = 0;
  state.ipsec.keepaliveL2tpRedialAppliedAtFailure = 0;
  if (state.ipsec.keepaliveFailing) {
    state.ipsec.keepaliveFailing = false;
    setIpsecClientResetGate(false);
    log('IPsec keepalive probe recovered');
  }
}

function stopIpsecKeepalive() {
  if (ipsecKeepaliveTimer) {
    clearInterval(ipsecKeepaliveTimer);
    ipsecKeepaliveTimer = null;
  }
}

function startIpsecKeepalive() {
  if (!IS_IPSEC_TYPE || !IPSEC_KEEPALIVE_ENABLED) {
    return;
  }
  if (ipsecKeepaliveTimer) {
    return;
  }

  ipsecKeepaliveTimer = setInterval(() => {
    runIpsecKeepaliveTick().catch((error) => log(`ipsec keepalive error: ${error.message}`));
  }, IPSEC_KEEPALIVE_INTERVAL_MS);
}

function isIpv4Address(value) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(value || '').trim());
}

function ensureIpsecRoutesForPortForwarding(vpnInterface) {
  const config = parsePortForwardingConfig();
  if (!config.enabled) {
    return;
  }

  const uniqueTargets = new Set();
  for (const rule of config.rules.filter((item) => item.enabled !== false)) {
    const targetAddress = String(rule.targetAddress || '').trim();
    if (!targetAddress) continue;
    if (!isIpv4Address(targetAddress)) {
      log(`Skipping static route for non-IPv4 targetAddress: ${targetAddress}`);
      continue;
    }
    uniqueTargets.add(`${targetAddress}/32`);
  }

  for (const targetCidr of uniqueTargets) {
    const targetIp = targetCidr.split('/')[0];
    const routeInfo = spawnSync('ip', ['route', 'get', targetIp], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const hasExpectedInterface = routeInfo.status === 0 && new RegExp(`\\bdev\\s+${vpnInterface}\\b`).test(routeInfo.stdout || '');
    if (!hasExpectedInterface) {
      try {
        run('ip', ['route', 'replace', targetCidr, 'dev', vpnInterface]);
        registerCleanup('ip', ['route', 'del', targetCidr, 'dev', vpnInterface]);
        log(`Ensured IPsec route ${targetCidr} via ${vpnInterface}`);
      } catch (error) {
        if (/Device for nexthop is not up|Cannot find device|No such device/i.test(String(error.message || ''))) {
          log(`Deferring route ${targetCidr} via ${vpnInterface}: interface is not ready yet`);
          continue;
        }
        throw error;
      }
    }
  }
}

function reconcileIpsecNetworking(vpnInterface) {
  ensureIpsecRoutesForPortForwarding(vpnInterface);
  applyBuiltInIptablesForIpsec(vpnInterface);
  applyPortForwarding(vpnInterface);
  state.ipsec.lastNetworkReconcileAt = new Date().toISOString();
}

function pushOpenvpnRecentLog(line) {
  state.openvpn.recentLogs.push(line);
  if (state.openvpn.recentLogs.length > OPENVPN_STARTUP_LOG_TAIL) {
    state.openvpn.recentLogs.shift();
  }
}

function detectOpenvpnFailureHint() {
  const lines = state.openvpn.recentLogs;
  if (lines.length === 0) {
    return null;
  }

  const checks = [
    { regex: /AUTH_FAILED|auth failed/i, hint: 'authentication failed (check username/password/certificates)' },
    { regex: /TLS Error|TLS handshake failed|TLS key negotiation failed/i, hint: 'TLS handshake failed (server unreachable, blocked UDP/TCP, or tls-auth/key-direction mismatch)' },
    { regex: /cipher|data-ciphers|cipher negotiation/i, hint: 'cipher negotiation issue (set compatible data-ciphers/data-ciphers-fallback)' },
    { regex: /RESOLVE: Cannot resolve host address/i, hint: 'cannot resolve VPN hostname (DNS issue)' },
    { regex: /Connection reset|Connection refused|Network is unreachable|No route to host|Operation timed out/i, hint: 'network connectivity to VPN endpoint is failing' },
    { regex: /VERIFY ERROR|certificate verify failed/i, hint: 'certificate verification failed (CA/cert mismatch or invalid cert chain)' },
    { regex: /Options error/i, hint: 'invalid OpenVPN config option in the profile' }
  ];

  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    const match = checks.find((entry) => entry.regex.test(line));
    if (match) {
      return { hint: match.hint, evidence: line };
    }
  }

  return null;
}

function buildOpenvpnStartupDiagnostics() {
  const hint = detectOpenvpnFailureHint();
  const recent = state.openvpn.recentLogs.slice(-8);
  const parts = [];

  if (hint) {
    parts.push(`Likely cause: ${hint.hint}.`);
    parts.push(`OpenVPN evidence: ${hint.evidence}`);
  }
  if (recent.length > 0) {
    parts.push(`Recent OpenVPN logs: ${recent.join(' || ')}`);
  }

  return parts.join(' ');
}

function stopIpsecProcesses() {
  stopIpsecKeepalive();
  state.ipsec.activeInterface = null;

  try {
    runSafe('sh', ['-lc', "printf 'd vpn-lac\n' > /var/run/xl2tpd/l2tp-control"]);
  } catch {}

  if (xl2tpdProcess && !xl2tpdProcess.killed) {
    xl2tpdProcess.kill('SIGTERM');
  }
  xl2tpdProcess = null;
  runSafe('ipsec', ['stop']);
  ipsecRuntime = null;
}

function handleOpenvpnOutput(chunk) {
  const text = String(chunk).trim();
  if (!text) {
    return;
  }

  log(`openvpn stdout: ${text}`);
  pushOpenvpnRecentLog(text);

  if (/Initialization Sequence Completed/i.test(text)) {
    state.openvpn.initializedAt = new Date().toISOString();
    state.openvpn.lastWriteErrorAt = null;
    state.openvpn.writeErrorCount = 0;
    state.lastHandshakeAt = state.openvpn.initializedAt;
  }

  if (/write to TUN\/TAP\s*:\s*Invalid argument/i.test(text)) {
    state.openvpn.lastWriteErrorAt = new Date().toISOString();
    state.openvpn.writeErrorCount += 1;
    state.status = 'DEGRADED';
    state.lastMessage =
      'OpenVPN data channel is failing: invalid writes to TUN/TAP. This usually means a dev tun/tap mismatch or incompatible pushed routes.';
  }
}

function waitForInterface(interfaceName, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const timer = setInterval(() => {
      if (openvpnProcess && openvpnProcess.exitCode !== null) {
        clearInterval(timer);
        const diagnostics = buildOpenvpnStartupDiagnostics();
        reject(
          new Error(
            `OpenVPN exited before interface ${interfaceName} appeared (exit code ${openvpnProcess.exitCode}). ${
              diagnostics || 'No diagnostic logs captured before exit.'
            }`
          )
        );
        return;
      }

      try {
        run('ip', ['link', 'show', interfaceName]);
        clearInterval(timer);
        resolve();
      } catch (error) {
        if (Date.now() - start > timeoutMs) {
          clearInterval(timer);
          const diagnostics = buildOpenvpnStartupDiagnostics();
          reject(
            new Error(
              `VPN interface ${interfaceName} did not appear within ${timeoutMs}ms: ${error.message}. ${
                diagnostics || 'OpenVPN did not emit a recognizable failure message.'
              }`
            )
          );
        }
      }
    }, 1000);
  });
}

async function configureOpenvpn() {
  state.status = 'STARTING';
  state.lastMessage = 'Bootstrapping OpenVPN tunnel';

  const files = buildOpenvpnConfigFiles();
  openvpnRuntime = files;
  const args = ['--config', files.configPath];

  openvpnProcess = spawn('openvpn', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  openvpnProcess.stdout.on('data', handleOpenvpnOutput);
  openvpnProcess.stderr.on('data', (chunk) => {
    const text = String(chunk).trim();
    if (!text) {
      return;
    }
    pushOpenvpnRecentLog(text);
    log(`openvpn stderr: ${text}`);
  });
  openvpnProcess.on('exit', (code, signal) => {
    log(`openvpn exited with code=${code} signal=${signal}`);
    if (state.status !== 'STOPPED' && !recoverInProgress) {
      state.status = 'ERROR';
      state.lastMessage = `OpenVPN process exited unexpectedly (${code ?? signal})`;
    }
  });

  await waitForInterface(files.expectedInterface, OPENVPN_INTERFACE_TIMEOUT_MS);
  applyBuiltInIptablesForOpenvpn(files.expectedInterface);
  applyCustomFirewall();
  applyPortForwarding(files.expectedInterface);

  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastHandshakeAt = new Date().toISOString();
  state.lastMessage = `OpenVPN tunnel is active on ${files.expectedInterface} to ${PROFILE_HOST}:${PROFILE_PORT}`;
}

function waitForPath(targetPath, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const timer = setInterval(() => {
      if (fs.existsSync(targetPath)) {
        clearInterval(timer);
        resolve();
        return;
      }

      if (Date.now() - startedAt > timeoutMs) {
        clearInterval(timer);
        reject(new Error(`Path did not appear in time: ${targetPath}`));
      }
    }, 500);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ensurePppDevice() {
  if (fs.existsSync('/dev/ppp')) {
    return;
  }

  try {
    run('mkdir', ['-p', '/dev']);
  } catch {}

  try {
    run('mknod', ['/dev/ppp', 'c', '108', '0']);
    run('chmod', ['600', '/dev/ppp']);
    return;
  } catch (error) {
    throw new Error(`Failed to prepare /dev/ppp inside runtime container: ${error.message}`);
  }
}

function loadIpsecKernelModules() {
  const modules = ['af_pppox', 'ppp_generic', 'ppp_async', 'pppol2tp', 'l2tp_netlink', 'l2tp_ppp', 'l2tp_core'];

  for (const moduleName of modules) {
    try {
      run('modprobe', [moduleName]);
    } catch (error) {
      log(`modprobe ${moduleName} warning: ${error.message}`);
    }
  }
}

async function waitForIpsecStarter(timeoutMs = 15000) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    try {
      run('ipsec', ['statusall']);
      return;
    } catch (error) {
      await sleep(1000);
    }
  }

  throw new Error('strongSwan did not become ready in time');
}

async function waitForPppInterface(timeoutMs = 30000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const iface = detectIpsecPppInterface();
    if (iface && isInterfaceUp(iface)) {
      return iface;
    }
    await sleep(1000);
  }
  throw new Error(`PPP interface did not become UP within ${timeoutMs}ms`);
}

async function configureIpsec() {
  state.status = 'STARTING';
  state.lastMessage = 'Bootstrapping IPsec/L2TP tunnel';

  const files = buildIpsecRuntimeFiles();
  ipsecRuntime = files;
  ensurePppDevice();
  loadIpsecKernelModules();

  run('ipsec', ['restart']);
  await waitForIpsecStarter(15000);
  await sleep(2000);
  runSafe('ipsec', ['rereadall']);

  try {
    run('ipsec', ['up', files.connectionName]);
  } catch (error) {
    try {
      run('ipsec', ['statusall']);
    } catch (statusError) {
      log(`ipsec statusall after failure: ${statusError.message}`);
    }
    throw new Error(`Failed to bring up IPsec connection ${files.connectionName}: ${error.message}`);
  }

  xl2tpdProcess = spawn('xl2tpd', ['-D'], { stdio: ['ignore', 'pipe', 'pipe'] });
  xl2tpdProcess.stdout.on('data', (chunk) => log(`xl2tpd stdout: ${String(chunk).trim()}`));
  xl2tpdProcess.stderr.on('data', (chunk) => {
    const text = String(chunk).trim();
    if (!text) return;
    log(`xl2tpd stderr: ${text}`);

    if (/Maximum retries exceeded for tunnel/i.test(text)) {
      state.status = 'DEGRADED';
      state.lastMessage = 'L2TP control tunnel timed out, triggering recovery';
      forceResetPortForwardTcpSessions();
      recoverTunnel('xl2tpd tunnel timeout').catch((error) => log(`recovery after xl2tpd timeout failed: ${error.message}`));
    }
  });
  xl2tpdProcess.on('exit', (code, signal) => {
    log(`xl2tpd exited with code=${code} signal=${signal}`);
    if (state.status !== 'STOPPED' && !recoverInProgress) {
      state.status = 'ERROR';
      state.lastMessage = `xl2tpd exited unexpectedly (${code ?? signal})`;
    }
  });

  await waitForPath(files.controlPath, 15000);
  run('sh', ['-lc', `printf 'c ${files.lacName}\n' > ${files.controlPath}`]);
  const pppInterface = await waitForPppInterface(30000);
  state.ipsec.activeInterface = pppInterface;

  reconcileIpsecNetworking(pppInterface);
  applyCustomFirewall();
  startIpsecKeepalive();
  setIpsecClientResetGate(false);

  if (files.dnsServers.length > 0) {
    log(`DNS servers requested but not applied automatically inside the container: ${files.dnsServers.join(', ')}`);
  }

  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastHandshakeAt = new Date().toISOString();
  state.lastMessage = `IPsec/L2TP tunnel is active on ${pppInterface} to ${PROFILE_HOST}`;
}

async function recoverTunnel(reason) {
  if (recoverInProgress) return;
  recoverInProgress = true;
  state.reconnectAttempts += 1;
  log(`Starting ${VPN_TYPE} recovery attempt ${state.reconnectAttempts}: ${reason}`);

  try {
    cleanupNetworking();
    if (VPN_TYPE === 'OPENVPN') stopOpenvpnProcess();
    if (IS_IPSEC_TYPE) stopIpsecProcesses();
    if (VPN_TYPE === 'WIREGUARD') await configureWireguard();
    if (VPN_TYPE === 'OPENVPN') await configureOpenvpn();
    if (IS_IPSEC_TYPE) await configureIpsec();
  } catch (error) {
    state.status = 'ERROR';
    state.startupError = error.message;
    state.lastMessage = `Recovery failed: ${error.message}`;
    log(state.lastMessage);
    cleanupNetworking();
  } finally {
    recoverInProgress = false;
  }
}

async function monitorWireguard() {
  const handshakeInfo = collectWireguardHandshakeInfo();
  if (!handshakeInfo.hasInterface) {
    state.status = 'ERROR';
    state.lastHandshakeAt = null;
    state.lastMessage = 'WireGuard interface is missing';
    await recoverTunnel('interface is missing');
    return;
  }

  state.lastHandshakeAt = handshakeInfo.handshakeAt;
  if (!handshakeInfo.handshakeAt) {
    state.status = 'CONNECTING';
    state.lastMessage = 'WireGuard interface is up, waiting for handshake';
    return;
  }

  const ageSeconds = Math.floor((Date.now() - new Date(handshakeInfo.handshakeAt).getTime()) / 1000);
  if (ageSeconds > STALE_HANDSHAKE_SECONDS) {
    state.status = 'DEGRADED';
    state.lastMessage = `WireGuard handshake is stale (${ageSeconds}s), attempting recovery`;
    await recoverTunnel(`stale handshake (${ageSeconds}s)`);
    return;
  }

  state.status = 'CONNECTED';
  state.lastMessage = `WireGuard tunnel is active, latest handshake ${ageSeconds}s ago`;
}

async function monitorOpenvpn() {
  const iface = detectVpnInterface();
  if (!iface) {
    state.status = 'ERROR';
    state.lastMessage = 'OpenVPN tunnel interface is missing';
    await recoverTunnel('openvpn interface is missing');
    return;
  }

  if (!openvpnProcess || openvpnProcess.exitCode !== null) {
    state.status = 'ERROR';
    state.lastMessage = 'OpenVPN process is not running';
    await recoverTunnel('openvpn process is not running');
    return;
  }

  if (state.openvpn.lastWriteErrorAt) {
    const ageMs = Date.now() - new Date(state.openvpn.lastWriteErrorAt).getTime();
    if (ageMs < 30000) {
      state.status = 'DEGRADED';
      state.lastMessage =
        'OpenVPN control channel is up, but the data channel is failing with TUN/TAP write errors. Check whether the server requires dev tap instead of tun.';
      return;
    }
  }

  state.status = 'CONNECTED';
  state.lastHandshakeAt = new Date().toISOString();
  state.lastMessage = `OpenVPN tunnel is active on ${iface}`;
}

async function monitorIpsec() {
  const iface = detectIpsecPppInterface();
  if (!iface || !isInterfaceUp(iface)) {
    const now = Date.now();
    if (!state.ipsec.interfaceMissingSince) {
      state.ipsec.interfaceMissingSince = new Date(now).toISOString();
    }

    const missingForMs = now - new Date(state.ipsec.interfaceMissingSince).getTime();
    if (missingForMs < IPSEC_INTERFACE_MISSING_GRACE_MS) {
      state.status = 'DEGRADED';
      state.lastMessage = `IPsec/L2TP PPP interface is missing, waiting ${Math.ceil((IPSEC_INTERFACE_MISSING_GRACE_MS - missingForMs) / 1000)}s before recovery`;
      return;
    }

    state.status = 'ERROR';
    state.lastMessage = `IPsec/L2TP PPP interface is missing for ${Math.floor(missingForMs / 1000)}s`;
    state.ipsec.interfaceMissingSince = null;
    await recoverTunnel('ipsec ppp interface is missing');
    return;
  }

  state.ipsec.interfaceMissingSince = null;
  state.ipsec.activeInterface = iface;

  try {
    run('ipsec', ['status', 'l2tp-psk']);
  } catch (error) {
    state.status = 'ERROR';
    state.lastMessage = `IPsec status check failed: ${error.message}`;
    await recoverTunnel('ipsec status check failed');
    return;
  }

  state.status = 'CONNECTED';
  state.lastHandshakeAt = new Date().toISOString();
  try {
    reconcileIpsecNetworking(iface);
  } catch (error) {
    log(`IPsec network reconcile warning on ${iface}: ${error.message}`);
  }
  state.lastMessage = `IPsec/L2TP tunnel is active on ${iface}`;
}

function startWatchdog() {
  if (watchdogTimer) return;
  watchdogTimer = setInterval(() => {
    if (recoverInProgress) return;
    const task = VPN_TYPE === 'WIREGUARD'
      ? monitorWireguard
      : VPN_TYPE === 'OPENVPN'
        ? monitorOpenvpn
        : IS_IPSEC_TYPE
          ? monitorIpsec
          : null;
    if (!task) return;
    task().catch((error) => log(`watchdog error: ${error.message}`));
  }, WATCHDOG_INTERVAL_MS);
}

async function bootstrap() {
  if (VPN_TYPE === 'WIREGUARD') {
    await configureWireguard();
    startWatchdog();
    return;
  }

  if (VPN_TYPE === 'OPENVPN') {
    await configureOpenvpn();
    startWatchdog();
    return;
  }

  if (IS_IPSEC_TYPE) {
    await configureIpsec();
    startWatchdog();
    return;
  }

  state.status = 'CONNECTED';
  state.connectedAt = new Date().toISOString();
  state.lastMessage = `${VPN_TYPE} runtime container started in mock mode`;
  state.firewallStatus = 'NOT_CONFIGURED';
  state.firewallMessage = 'Custom firewall rules are disabled';
  state.portForwardingStatus = 'NOT_CONFIGURED';
  state.portForwardingMessage = 'Port forwarding is disabled';
}

app.get('/health', (req, res) => {
  const payload = {
    status: state.status === 'ERROR' ? 'error' : state.status === 'STARTING' ? 'starting' : 'ok',
    service: 'worker-runtime',
    vpnType: VPN_TYPE,
    profileId: PROFILE_ID,
    message: state.lastMessage
  };

  if (state.status === 'ERROR') return res.status(500).json(payload);
  if (state.status === 'STARTING') return res.status(503).json(payload);
  res.json(payload);
});

app.get('/status', (req, res) => {
  res.json({ vpnType: VPN_TYPE, ...state });
});

app.post('/disconnect', (req, res) => {
  if (watchdogTimer) {
    clearInterval(watchdogTimer);
    watchdogTimer = null;
  }
  if (VPN_TYPE === 'OPENVPN') stopOpenvpnProcess();
  if (IS_IPSEC_TYPE) stopIpsecProcesses();
  stopIpsecKeepalive();
  cleanupNetworking();

  state.status = 'STOPPED';
  state.connectedAt = null;
  state.lastHandshakeAt = null;
  state.lastMessage = `${VPN_TYPE} runtime stopped`;
  res.json({ ok: true, vpnType: VPN_TYPE, state });
});

app.get('/logs', (req, res) => {
  res.json({ logs: state.logs });
});

app.listen(PORT, () => {
  log(`worker-runtime listening on port ${PORT} for ${VPN_TYPE}`);
  bootstrap().catch((error) => {
    state.status = 'ERROR';
    state.startupError = error.message;
    state.lastMessage = error.message;
    log(`${VPN_TYPE} bootstrap failed: ${error.message}`);
  });
});

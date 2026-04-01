'use client';

import { useEffect, useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const REFRESH_INTERVAL_MS = 5000;
const DEFAULT_PORTS = {
  OPENVPN: '1194',
  IPSEC: '500',
  'IPSEC.B': '500',
  WIREGUARD: '51820'
};
const DEFAULT_OPENVPN_KEY_DIRECTION = '1';
const DEFAULT_WIREGUARD_ALLOWED_IPS = '0.0.0.0/0';
const DEFAULT_WIREGUARD_KEEPALIVE = '25';
const DEFAULT_IPSEC_MTU = '1410';
const DEFAULT_IPSEC_MRU = '1410';
const IPSEC_TYPES = ['IPSEC', 'IPSEC.B'];

function parseOpenvpnEndpoint(configText) {
  const lines = String(configText || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#') && !line.startsWith(';'));

  let remoteHost = '';
  let remotePort = '';
  let fallbackPort = '';

  for (const line of lines) {
    const portMatch = line.match(/^port\s+(\d+)$/i);
    if (portMatch) {
      fallbackPort = portMatch[1];
      continue;
    }

    const remoteMatch = line.match(/^remote\s+(\S+)(?:\s+(\d+))?/i);
    if (remoteMatch) {
      remoteHost = remoteMatch[1] || '';
      remotePort = remoteMatch[2] || '';
      break;
    }
  }

  return {
    host: remoteHost,
    port: remotePort || fallbackPort
  };
}

function buildFirewallRule() {
  return {
    id: crypto.randomUUID(),
    table: 'filter',
    chain: 'OUTPUT',
    action: 'ACCEPT',
    protocol: 'all',
    source: '',
    destination: '',
    destinationPort: '',
    comment: ''
  };
}

function buildPortForwardRule() {
  return {
    id: crypto.randomUUID(),
    enabled: true,
    protocol: 'tcp',
    hostPort: '',
    targetAddress: '',
    targetPort: '',
    description: ''
  };
}

function buildInitialForm() {
  return {
    name: '',
    type: 'OPENVPN',
    host: '',
    port: '',
    username: '',
    openvpn: {
      configText: '',
      username: '',
      password: '',
      caText: '',
      certText: '',
      keyText: '',
      tlsAuthText: '',
      keyDirection: ''
    },
    ipsec: {
      preSharedKey: '',
      password: '',
      userId: '',
      localIdentifier: '',
      remoteIdentifier: '',
      dnsServers: '',
      mtu: '',
      mru: ''
    },
    wireguard: {
      tunnelAddress: '',
      privateKey: '',
      peerPublicKey: '',
      presharedKey: '',
      allowedIps: '',
      dnsServers: '',
      persistentKeepalive: ''
    },
    firewall: {
      enabled: false,
      mode: 'BASIC',
      basicRules: [],
      advancedRules: ''
    },
    portForwarding: {
      enabled: false,
      rules: []
    }
  };
}

function buildCreateTypeForm(type) {
  const next = buildInitialForm();
  next.type = type;
  return next;
}

function normalizeFormFromProfile(profile) {
  return {
    name: profile.name || '',
    type: profile.type || 'OPENVPN',
    host: profile.host || '',
    port: String(profile.port || ''),
    username: profile.username || '',
    openvpn: {
      configText: '',
      username: profile.openvpn?.username || '',
      password: '',
      caText: '',
      certText: '',
      keyText: '',
      tlsAuthText: '',
      keyDirection: profile.openvpn?.keyDirection || ''
    },
    ipsec: {
      preSharedKey: '',
      password: '',
      userId: profile.ipsec?.userId || profile.username || '',
      localIdentifier: profile.ipsec?.localIdentifier || '',
      remoteIdentifier: profile.ipsec?.remoteIdentifier || '',
      dnsServers: profile.ipsec?.dnsServers || '',
      mtu: profile.ipsec?.mtu || '',
      mru: profile.ipsec?.mru || ''
    },
    wireguard: {
      tunnelAddress: profile.wireguard?.tunnelAddress || '',
      privateKey: '',
      peerPublicKey: '',
      presharedKey: '',
      allowedIps: profile.wireguard?.allowedIps || '',
      dnsServers: profile.wireguard?.dnsServers || '',
      persistentKeepalive: profile.wireguard?.persistentKeepalive || ''
    },
    firewall: {
      enabled: Boolean(profile.firewall?.enabled),
      mode: profile.firewall?.mode || 'BASIC',
      basicRules: Array.isArray(profile.firewall?.basicRules) ? profile.firewall.basicRules : [],
      advancedRules: profile.firewall?.advancedRules || ''
    },
    portForwarding: {
      enabled: Boolean(profile.portForwarding?.enabled),
      rules: Array.isArray(profile.portForwarding?.rules) ? profile.portForwarding.rules : []
    }
  };
}

const cardStyle = {
  background: '#fff',
  padding: 16,
  borderRadius: 8,
  marginBottom: 24
};

const tableStyle = {
  width: '100%',
  borderCollapse: 'collapse',
  background: '#fff'
};

const thtd = {
  border: '1px solid #ddd',
  padding: '8px',
  textAlign: 'left',
  verticalAlign: 'middle'
};

const fieldStyle = {
  width: '100%',
  minWidth: 0,
  boxSizing: 'border-box',
  padding: '8px 10px'
};

const compactTextareaStyle = {
  ...fieldStyle,
  minHeight: 68,
  resize: 'vertical'
};

const formGridStyle = {
  display: 'grid',
  gridTemplateColumns: 'repeat(12, minmax(0, 1fr))',
  gap: 10,
  alignItems: 'start'
};

const modalOverlayStyle = {
  position: 'fixed',
  inset: 0,
  background: 'rgba(15, 23, 42, 0.45)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 24,
  zIndex: 1000
};

const modalCardStyle = {
  width: 'min(1180px, 100%)',
  maxHeight: 'calc(100vh - 48px)',
  overflow: 'auto',
  background: '#fff',
  borderRadius: 14,
  boxShadow: '0 24px 70px rgba(15, 23, 42, 0.22)',
  padding: 20
};

const iconButtonStyle = {
  width: 34,
  height: 34,
  borderRadius: 8,
  border: '1px solid #d7dce3',
  background: '#fff',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  cursor: 'pointer',
  padding: 0
};

const createRowButtonStyle = {
  width: 34,
  height: 34,
  borderRadius: 8,
  border: '1px dashed #98d7af',
  background: '#f4fcf7',
  color: '#156c2f',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 0,
  cursor: 'pointer',
  boxSizing: 'border-box'
};

const createMenuStyle = {
  position: 'absolute',
  top: 'calc(100% + 6px)',
  left: 0,
  minWidth: 160,
  background: '#fff',
  border: '1px solid #d7dce3',
  borderRadius: 10,
  boxShadow: '0 12px 28px rgba(15, 23, 42, 0.16)',
  padding: 6,
  zIndex: 20
};

const createMenuItemStyle = {
  width: '100%',
  border: 'none',
  background: 'transparent',
  textAlign: 'left',
  padding: '8px 10px',
  borderRadius: 8,
  cursor: 'pointer'
};

const iconStyle = {
  width: 18,
  height: 18,
  display: 'block'
};

function getStatusColors(status) {
  switch (status) {
    case 'CONNECTED':
    case 'APPLIED':
    case 'running':
    case 'RUNNING':
      return { background: '#e9f9ee', color: '#156c2f', border: '#9fd8ad' };
    case 'STARTING':
    case 'CONNECTING':
    case 'DEGRADED':
    case 'starting':
      return { background: '#fff7df', color: '#8a6400', border: '#e7cb74' };
    case 'STOPPED':
    case 'stopped':
    case 'MISSING':
    case 'NOT_CONFIGURED':
      return { background: '#f2f4f7', color: '#455468', border: '#cbd2da' };
    case 'ERROR':
    case 'UNREACHABLE':
    case 'dead':
    case 'exited':
      return { background: '#fff0f0', color: '#a33030', border: '#e7aaaa' };
    default:
      return { background: '#eef4ff', color: '#274c8e', border: '#bfd0f2' };
  }
}

function StatusBadge({ value }) {
  const colors = getStatusColors(value);
  const descriptions = {
    CONNECTED: 'Соединение активно и работает штатно.',
    STARTING: 'Инстанс запускается и поднимает VPN.',
    CONNECTING: 'Интерфейс уже есть, но соединение ещё не полностью установлено.',
    DEGRADED: 'Соединение частично работает или требует восстановления.',
    STOPPED: 'Профиль выключен вручную.',
    ERROR: 'Произошла ошибка запуска или работы.',
    running: 'Контейнер запущен на уровне Docker.',
    RUNNING: 'Контейнер запущен на уровне Docker.',
    MISSING: 'Контейнер отсутствует и сейчас не найден.',
    UNREACHABLE: 'Контейнер существует, но runtime внутри не отвечает.',
    APPLIED: 'Правила успешно применены.',
    NOT_CONFIGURED: 'Дополнительные правила не настроены.'
  };
  return (
    <span
      title={descriptions[value] || String(value || '')}
      style={{
        display: 'inline-block',
        padding: '3px 8px',
        borderRadius: 999,
        border: `1px solid ${colors.border}`,
        background: colors.background,
        color: colors.color,
        fontSize: 12,
        fontWeight: 600
      }}
    >
      {value || '-'}
    </span>
  );
}

function formatRelativeDuration(value) {
  if (!value) {
    return '-';
  }

  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) {
    return '-';
  }

  const diffMs = Math.max(0, Date.now() - timestamp);
  const totalSeconds = Math.floor(diffMs / 1000);

  if (totalSeconds < 5) return 'только что';
  if (totalSeconds < 60) return `${totalSeconds} сек назад`;

  const totalMinutes = Math.floor(totalSeconds / 60);
  if (totalMinutes < 60) return `${totalMinutes} мин назад`;

  const totalHours = Math.floor(totalMinutes / 60);
  if (totalHours < 24) return `${totalHours} ч назад`;

  const totalDays = Math.floor(totalHours / 24);
  return `${totalDays} дн назад`;
}

function MaterialIcon({ path, title }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" style={iconStyle}>
      {title ? <title>{title}</title> : null}
      <path d={path} fill="currentColor" />
    </svg>
  );
}

export default function Dashboard() {
  const [profiles, setProfiles] = useState([]);
  const [instances, setInstances] = useState([]);
  const [form, setForm] = useState(buildInitialForm);
  const [editingId, setEditingId] = useState(null);
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [isCreateMenuOpen, setIsCreateMenuOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [lastUpdatedAt, setLastUpdatedAt] = useState('');
  const profileRows = Array.isArray(profiles) ? profiles : [];
  const instanceRows = Array.isArray(instances) ? instances : [];

  async function fetchJsonWithTimeout(url, timeoutMs = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, { cache: 'no-store', signal: controller.signal });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(
          data && typeof data === 'object' ? data.message || JSON.stringify(data) : `Request failed for ${url}`
        );
      }
      return data;
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new Error('Не удалось обновить данные вовремя, показаны последние известные значения');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async function refresh() {
    const profilesData = await fetchJsonWithTimeout(`${API_URL}/vpn-profiles`, 5000);
    setProfiles(Array.isArray(profilesData) ? profilesData : []);
    setLastUpdatedAt(new Date().toLocaleTimeString());

    try {
      const instancesData = await fetchJsonWithTimeout(`${API_URL}/vpn-instances`, 5000);
      setInstances(Array.isArray(instancesData) ? instancesData : []);
    } catch (error) {
      throw new Error(error.message || 'Не удалось загрузить инстансы');
    }
  }

  useEffect(() => {
    let mounted = true;

    async function runRefresh() {
      try {
        await refresh();
        if (mounted) setMessage('');
      } catch (error) {
        if (mounted) setMessage(error.message);
      }
    }

    runRefresh();
    const intervalId = setInterval(runRefresh, REFRESH_INTERVAL_MS);
    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  function resetForm() {
    setEditingId(null);
    setForm(buildInitialForm());
    setIsFormOpen(false);
    setIsCreateMenuOpen(false);
  }

  function updateType(type) {
    setForm((current) => ({
      ...current,
      type
    }));
  }

  function updateWireguardField(key, value) {
    setForm((current) => ({
      ...current,
      wireguard: {
        ...current.wireguard,
        [key]: value
      }
    }));
  }

  function updateOpenvpnField(key, value) {
    setForm((current) => {
      const next = {
        ...current,
        openvpn: {
          ...current.openvpn,
          [key]: value
        }
      };

      if (key === 'configText') {
        const parsed = parseOpenvpnEndpoint(value);
        if (parsed.host) {
          next.host = parsed.host;
        }
        if (parsed.port) {
          next.port = parsed.port;
        }
      }

      return next;
    });
  }

  function updateFirewallField(key, value) {
    setForm((current) => ({
      ...current,
      firewall: {
        ...current.firewall,
        [key]: value
      }
    }));
  }

  function updateIpsecField(key, value) {
    setForm((current) => ({
      ...current,
      ipsec: {
        ...current.ipsec,
        [key]: value
      }
    }));
  }

  function updateFirewallRule(ruleId, key, value) {
    setForm((current) => ({
      ...current,
      firewall: {
        ...current.firewall,
        basicRules: current.firewall.basicRules.map((rule) =>
          rule.id === ruleId ? { ...rule, [key]: value } : rule
        )
      }
    }));
  }

  function addFirewallRule() {
    setForm((current) => ({
      ...current,
      firewall: {
        ...current.firewall,
        basicRules: [...current.firewall.basicRules, buildFirewallRule()]
      }
    }));
  }

  function removeFirewallRule(ruleId) {
    setForm((current) => ({
      ...current,
      firewall: {
        ...current.firewall,
        basicRules: current.firewall.basicRules.filter((rule) => rule.id !== ruleId)
      }
    }));
  }

  function updatePortForwardingField(key, value) {
    setForm((current) => ({
      ...current,
      portForwarding: {
        ...current.portForwarding,
        [key]: value
      }
    }));
  }

  function updatePortForwardRule(ruleId, key, value) {
    setForm((current) => ({
      ...current,
      portForwarding: {
        ...current.portForwarding,
        rules: current.portForwarding.rules.map((rule) =>
          rule.id === ruleId ? { ...rule, [key]: value } : rule
        )
      }
    }));
  }

  function addPortForwardRule() {
    setForm((current) => ({
      ...current,
      portForwarding: {
        ...current.portForwarding,
        rules: [...current.portForwarding.rules, buildPortForwardRule()]
      }
    }));
  }

  function removePortForwardRule(ruleId) {
    setForm((current) => ({
      ...current,
      portForwarding: {
        ...current.portForwarding,
        rules: current.portForwarding.rules.filter((rule) => rule.id !== ruleId)
      }
    }));
  }

  function startEdit(profile) {
    setEditingId(profile.id);
    setForm(normalizeFormFromProfile(profile));
    setIsFormOpen(true);
    setMessage('');
  }

  function startCreate(type) {
    setEditingId(null);
    setForm(buildCreateTypeForm(type));
    setIsFormOpen(true);
    setIsCreateMenuOpen(false);
    setMessage('');
  }

  function buildPayload() {
    const payload = {
      name: form.name,
      type: form.type,
      host: form.host,
      port: Number(form.port || DEFAULT_PORTS[form.type] || DEFAULT_PORTS.OPENVPN),
      username: form.username,
      firewall: { ...form.firewall },
      portForwarding: { ...form.portForwarding }
    };

    if (form.type === 'OPENVPN') {
      payload.openvpn = {
        ...form.openvpn,
        keyDirection: form.openvpn.keyDirection || DEFAULT_OPENVPN_KEY_DIRECTION
      };
    }

    if (IPSEC_TYPES.includes(form.type)) {
      payload.ipsec = {
        ...form.ipsec,
        mtu: form.ipsec.mtu || DEFAULT_IPSEC_MTU,
        mru: form.ipsec.mru || DEFAULT_IPSEC_MRU
      };
    }

    if (form.type === 'WIREGUARD') {
      payload.wireguard = {
        ...form.wireguard,
        allowedIps: form.wireguard.allowedIps || DEFAULT_WIREGUARD_ALLOWED_IPS,
        persistentKeepalive: form.wireguard.persistentKeepalive || DEFAULT_WIREGUARD_KEEPALIVE
      };
    }

    return payload;
  }

  async function submitProfile(e) {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    try {
      const payload = buildPayload();
      const isEdit = Boolean(editingId);
      const res = await fetch(isEdit ? `${API_URL}/vpn-profiles/${editingId}` : `${API_URL}/vpn-profiles`, {
        method: isEdit ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(await res.text());
      resetForm();
      await refresh();
      setMessage(isEdit ? 'Профиль обновлён' : 'Профиль создан');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function action(id, name) {
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch(`${API_URL}/vpn-profiles/${id}/${name}`, { method: 'POST' });
      if (!res.ok) throw new Error(await res.text());
      await refresh();
      setMessage(`Операция ${name} выполнена`);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function removeProfile(id) {
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch(`${API_URL}/vpn-profiles/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(await res.text());
      if (editingId === id) resetForm();
      await refresh();
      setMessage('Профиль удалён');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 1500, margin: '0 auto', padding: 24 }}>
      <h1 style={{ marginTop: 0 }}>VPN Control Panel</h1>
      <p style={{ color: '#5b6473', marginTop: -4, marginBottom: 28 }}>
        Последнее обновление: {lastUpdatedAt || '-'}
      </p>

      {isFormOpen && (
        <div style={modalOverlayStyle} onClick={loading ? undefined : resetForm}>
          <section style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', marginBottom: 12 }}>
              <h2 style={{ margin: 0 }}>{editingId ? 'Редактировать профиль' : 'Создать профиль'}</h2>
              <button type="button" onClick={resetForm} disabled={loading} style={{ padding: '8px 12px' }}>
                {editingId ? 'Отменить редактирование' : 'Закрыть форму'}
              </button>
            </div>

        <form onSubmit={submitProfile} style={{ ...formGridStyle, marginTop: 12 }}>
          <input style={{ ...fieldStyle, gridColumn: 'span 3' }} placeholder="Имя" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <input style={{ ...fieldStyle, gridColumn: 'span 6' }} placeholder="Endpoint host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} required />
          <input style={{ ...fieldStyle, gridColumn: 'span 1' }} placeholder={`Port (default ${DEFAULT_PORTS[form.type] || DEFAULT_PORTS.OPENVPN})`} value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} />
          <input style={{ ...fieldStyle, gridColumn: 'span 2' }} placeholder="Пользователь" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />

          {form.type === 'OPENVPN' && (
            <>
              <input
                style={{ ...fieldStyle, gridColumn: 'span 3' }}
                placeholder="OpenVPN username"
                value={form.openvpn.username}
                onChange={(e) => updateOpenvpnField('username', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 3' }}
                placeholder={editingId ? 'OpenVPN password (введите заново, если меняете)' : 'OpenVPN password'}
                type="password"
                value={form.openvpn.password}
                onChange={(e) => updateOpenvpnField('password', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 2' }}
                placeholder={`key-direction (default ${DEFAULT_OPENVPN_KEY_DIRECTION})`}
                value={form.openvpn.keyDirection}
                onChange={(e) => updateOpenvpnField('keyDirection', e.target.value)}
              />
              <textarea
                style={{ ...compactTextareaStyle, gridColumn: 'span 12', minHeight: 160 }}
                placeholder={editingId ? 'OpenVPN .ovpn config (введите заново, если меняете)' : 'OpenVPN .ovpn config'}
                value={form.openvpn.configText}
                onChange={(e) => updateOpenvpnField('configText', e.target.value)}
                required={!editingId}
              />
              <textarea
                style={{ ...compactTextareaStyle, gridColumn: 'span 3', minHeight: 120 }}
                placeholder={editingId ? 'ca.crt (введите заново, если меняете)' : 'ca.crt'}
                value={form.openvpn.caText}
                onChange={(e) => updateOpenvpnField('caText', e.target.value)}
                required={!editingId}
              />
              <textarea
                style={{ ...compactTextareaStyle, gridColumn: 'span 3', minHeight: 120 }}
                placeholder={editingId ? 'client.crt (введите заново, если меняете)' : 'client.crt'}
                value={form.openvpn.certText}
                onChange={(e) => updateOpenvpnField('certText', e.target.value)}
                required={!editingId}
              />
              <textarea
                style={{ ...compactTextareaStyle, gridColumn: 'span 3', minHeight: 120 }}
                placeholder={editingId ? 'client.key (введите заново, если меняете)' : 'client.key'}
                value={form.openvpn.keyText}
                onChange={(e) => updateOpenvpnField('keyText', e.target.value)}
                required={!editingId}
              />
              <textarea
                style={{ ...compactTextareaStyle, gridColumn: 'span 3', minHeight: 120 }}
                placeholder="tls-auth key (optional)"
                value={form.openvpn.tlsAuthText}
                onChange={(e) => updateOpenvpnField('tlsAuthText', e.target.value)}
              />
            </>
          )}

          {IPSEC_TYPES.includes(form.type) && (
            <>
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder="L2TP username"
                value={form.ipsec.userId}
                onChange={(e) => updateIpsecField('userId', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder={editingId ? 'L2TP password (введите заново, если меняете)' : 'L2TP password'}
                type="password"
                value={form.ipsec.password}
                onChange={(e) => updateIpsecField('password', e.target.value)}
                required={!editingId}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder={editingId ? 'IPsec PSK (введите заново, если меняете)' : 'IPsec PSK'}
                type="password"
                value={form.ipsec.preSharedKey}
                onChange={(e) => updateIpsecField('preSharedKey', e.target.value)}
                required={!editingId}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder="Remote identifier (optional)"
                value={form.ipsec.remoteIdentifier}
                onChange={(e) => updateIpsecField('remoteIdentifier', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder="Local identifier (optional)"
                value={form.ipsec.localIdentifier}
                onChange={(e) => updateIpsecField('localIdentifier', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 4' }}
                placeholder="DNS servers"
                value={form.ipsec.dnsServers}
                onChange={(e) => updateIpsecField('dnsServers', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 2' }}
                placeholder={`MTU (default ${DEFAULT_IPSEC_MTU})`}
                value={form.ipsec.mtu}
                onChange={(e) => updateIpsecField('mtu', e.target.value)}
              />
              <input
                style={{ ...fieldStyle, gridColumn: 'span 2' }}
                placeholder={`MRU (default ${DEFAULT_IPSEC_MRU})`}
                value={form.ipsec.mru}
                onChange={(e) => updateIpsecField('mru', e.target.value)}
              />
            </>
          )}

          {form.type === 'WIREGUARD' && (
            <>
              <input style={{ ...fieldStyle, gridColumn: 'span 3' }} placeholder="Tunnel address" value={form.wireguard.tunnelAddress} onChange={(e) => updateWireguardField('tunnelAddress', e.target.value)} required />
              <input style={{ ...fieldStyle, gridColumn: 'span 5' }} placeholder={`Allowed IPs (default ${DEFAULT_WIREGUARD_ALLOWED_IPS})`} value={form.wireguard.allowedIps} onChange={(e) => updateWireguardField('allowedIps', e.target.value)} />
              <input style={{ ...fieldStyle, gridColumn: 'span 2' }} placeholder={`Keepalive (default ${DEFAULT_WIREGUARD_KEEPALIVE})`} value={form.wireguard.persistentKeepalive} onChange={(e) => updateWireguardField('persistentKeepalive', e.target.value)} />
              <input style={{ ...fieldStyle, gridColumn: 'span 2' }} placeholder="DNS servers" value={form.wireguard.dnsServers} onChange={(e) => updateWireguardField('dnsServers', e.target.value)} />
              <textarea style={{ ...compactTextareaStyle, gridColumn: 'span 4' }} placeholder={editingId ? 'Private key (введите заново, если меняете)' : 'Private key'} value={form.wireguard.privateKey} onChange={(e) => updateWireguardField('privateKey', e.target.value)} required={!editingId} />
              <textarea style={{ ...compactTextareaStyle, gridColumn: 'span 4' }} placeholder={editingId ? 'Peer public key (введите заново, если меняете)' : 'Peer public key'} value={form.wireguard.peerPublicKey} onChange={(e) => updateWireguardField('peerPublicKey', e.target.value)} required={!editingId} />
              <textarea style={{ ...compactTextareaStyle, gridColumn: 'span 4' }} placeholder="Preshared key (optional)" value={form.wireguard.presharedKey} onChange={(e) => updateWireguardField('presharedKey', e.target.value)} />
            </>
          )}

          <div style={{ gridColumn: '1 / -1', marginTop: 6, paddingTop: 12, borderTop: '1px solid #e6e8ec' }}>
            <h3 style={{ margin: '0 0 10px 0' }}>Port Forwarding</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, minmax(0, 1fr))', gap: 10, alignItems: 'center' }}>
              <label style={{ gridColumn: 'span 4', display: 'flex', gap: 8, alignItems: 'center' }}>
                <input type="checkbox" checked={form.portForwarding.enabled} onChange={(e) => updatePortForwardingField('enabled', e.target.checked)} />
                Enable published ports and VPN forwards
              </label>
              <div style={{ gridColumn: 'span 8', color: '#5b6473' }}>
                Host port to VPN target IP:port through this instance
              </div>
            </div>

            {form.portForwarding.enabled && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <strong>Forward Rules</strong>
                  <button type="button" onClick={addPortForwardRule}>Add forward</button>
                </div>
                {form.portForwarding.rules.length === 0 ? (
                  <div style={{ color: '#5b6473' }}>Нет правил. Добавь правило hostPort to targetAddress:targetPort.</div>
                ) : (
                  <div style={{ display: 'grid', gap: 8 }}>
                    {form.portForwarding.rules.map((rule) => (
                      <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr 1.2fr 1.6fr auto', gap: 8, alignItems: 'center' }}>
                        <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <input type="checkbox" checked={rule.enabled !== false} onChange={(e) => updatePortForwardRule(rule.id, 'enabled', e.target.checked)} />
                          On
                        </label>
                        <select style={fieldStyle} value={rule.protocol} onChange={(e) => updatePortForwardRule(rule.id, 'protocol', e.target.value)}>
                          <option value="tcp">tcp</option>
                          <option value="udp">udp</option>
                        </select>
                        <input style={fieldStyle} placeholder="Host port" value={rule.hostPort} onChange={(e) => updatePortForwardRule(rule.id, 'hostPort', e.target.value)} />
                        <input style={fieldStyle} placeholder="Target IP" value={rule.targetAddress} onChange={(e) => updatePortForwardRule(rule.id, 'targetAddress', e.target.value)} />
                        <input style={fieldStyle} placeholder="Target port" value={rule.targetPort} onChange={(e) => updatePortForwardRule(rule.id, 'targetPort', e.target.value)} />
                        <input style={fieldStyle} placeholder="Description" value={rule.description} onChange={(e) => updatePortForwardRule(rule.id, 'description', e.target.value)} />
                        <button type="button" onClick={() => removePortForwardRule(rule.id)}>Delete</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          <div style={{ gridColumn: '1 / -1', marginTop: 6, paddingTop: 12, borderTop: '1px solid #e6e8ec' }}>
            <h3 style={{ margin: '0 0 10px 0' }}>Firewall / iptables</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, minmax(0, 1fr))', gap: 10, alignItems: 'center' }}>
              <label style={{ gridColumn: 'span 3', display: 'flex', gap: 8, alignItems: 'center' }}>
                <input type="checkbox" checked={form.firewall.enabled} onChange={(e) => updateFirewallField('enabled', e.target.checked)} />
                Enable custom firewall rules
              </label>
              <select style={{ ...fieldStyle, gridColumn: 'span 2' }} value={form.firewall.mode} onChange={(e) => updateFirewallField('mode', e.target.value)} disabled={!form.firewall.enabled}>
                <option value="BASIC">Basic</option>
                <option value="ADVANCED">Advanced</option>
              </select>
            </div>

            {form.firewall.enabled && form.firewall.mode === 'BASIC' && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <strong>Basic Rules</strong>
                  <button type="button" onClick={addFirewallRule}>Add rule</button>
                </div>
                {form.firewall.basicRules.length === 0 ? (
                  <div style={{ color: '#5b6473' }}>Нет правил. Можно добавить правило в `filter` table.</div>
                ) : (
                  <div style={{ display: 'grid', gap: 8 }}>
                    {form.firewall.basicRules.map((rule) => (
                      <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr 1fr 1fr 1fr 1fr 1fr 1.2fr auto', gap: 8, alignItems: 'center' }}>
                        <select style={fieldStyle} value={rule.table} onChange={(e) => updateFirewallRule(rule.id, 'table', e.target.value)}>
                          <option value="filter">filter</option>
                        </select>
                        <select style={fieldStyle} value={rule.chain} onChange={(e) => updateFirewallRule(rule.id, 'chain', e.target.value)}>
                          <option value="INPUT">INPUT</option>
                          <option value="OUTPUT">OUTPUT</option>
                          <option value="FORWARD">FORWARD</option>
                        </select>
                        <select style={fieldStyle} value={rule.action} onChange={(e) => updateFirewallRule(rule.id, 'action', e.target.value)}>
                          <option value="ACCEPT">ACCEPT</option>
                          <option value="DROP">DROP</option>
                          <option value="REJECT">REJECT</option>
                        </select>
                        <select style={fieldStyle} value={rule.protocol} onChange={(e) => updateFirewallRule(rule.id, 'protocol', e.target.value)}>
                          <option value="all">all</option>
                          <option value="tcp">tcp</option>
                          <option value="udp">udp</option>
                          <option value="icmp">icmp</option>
                        </select>
                        <input style={fieldStyle} placeholder="Source" value={rule.source} onChange={(e) => updateFirewallRule(rule.id, 'source', e.target.value)} />
                        <input style={fieldStyle} placeholder="Destination" value={rule.destination} onChange={(e) => updateFirewallRule(rule.id, 'destination', e.target.value)} />
                        <input style={fieldStyle} placeholder="Port" value={rule.destinationPort} onChange={(e) => updateFirewallRule(rule.id, 'destinationPort', e.target.value)} />
                        <input style={fieldStyle} placeholder="Comment" value={rule.comment} onChange={(e) => updateFirewallRule(rule.id, 'comment', e.target.value)} />
                        <button type="button" onClick={() => removeFirewallRule(rule.id)}>Delete</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {form.firewall.enabled && form.firewall.mode === 'ADVANCED' && (
              <div style={{ marginTop: 12 }}>
                <textarea
                  style={{ ...compactTextareaStyle, minHeight: 120 }}
                  placeholder={'iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT\niptables -A OUTPUT -d 10.0.0.0/8 -j DROP'}
                  value={form.firewall.advancedRules}
                  onChange={(e) => updateFirewallField('advancedRules', e.target.value)}
                />
              </div>
            )}
          </div>

          <button type="submit" disabled={loading} style={{ gridColumn: 'span 2', padding: 10 }}>{editingId ? 'Сохранить' : 'Создать'}</button>
        </form>
          </section>
        </div>
      )}

      {isFormOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 800
          }}
        />
      )}

      <section style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h2 style={{ margin: 0 }}>Профили</h2>
        </div>
      </section>

      {message && <div style={{ background: '#eef6ff', border: '1px solid #bcdcff', padding: 12, borderRadius: 8, marginBottom: 24, whiteSpace: 'pre-wrap' }}>{message}</div>}

      <section style={{ marginBottom: 24 }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thtd} title="Понятное имя профиля VPN-подключения.">Имя</th>
              <th style={thtd} title="Тип VPN и runtime-образ, который будет использоваться.">Тип</th>
              <th style={thtd} title="Адрес VPN-сервера или endpoint-а.">Host</th>
              <th style={thtd} title="Порт VPN-сервера или endpoint-а.">Port</th>
              <th style={thtd} title="Количество активных пробросов портов с хоста в VPN.">Port Forwards</th>
              <th style={thtd} title="Режим и наличие пользовательских правил iptables.">Firewall</th>
              <th style={thtd} title="Состояние, которого хочет manager-api для профиля.">Желаемое состояние</th>
              <th style={thtd} title="Действия для управления профилем.">Действия</th>
            </tr>
          </thead>
          <tbody>
            {profileRows.length === 0 ? (
              <tr><td style={thtd} colSpan={8}>Пока нет профилей</td></tr>
            ) : profileRows.map((item) => (
              <tr key={item.id}>
                <td style={thtd}>{item.name}</td>
                <td style={thtd}>{item.type}</td>
                <td style={thtd}>{item.host}</td>
                <td style={thtd}>{item.port}</td>
                <td style={thtd}>{item.portForwarding?.enabled ? item.portForwarding.rules.filter((rule) => rule.enabled !== false).length : '-'}</td>
                <td style={thtd}>{item.firewall?.enabled ? `${item.firewall.mode} (${item.firewall.mode === 'BASIC' ? item.firewall.basicRules.length : 'raw'})` : '-'}</td>
                <td style={thtd}><StatusBadge value={item.status} /></td>
                <td style={thtd}>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button
                      onClick={() => startEdit(item)}
                      disabled={loading || item.status === 'CONNECTED'}
                      style={iconButtonStyle}
                      title="Редактировать профиль"
                      aria-label="Редактировать профиль"
                    >
                      <MaterialIcon path="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zm2.92 2.33H5v-.92l9.06-9.06.92.92L5.92 19.58zM20.71 7.04a1.003 1.003 0 0 0 0-1.42L18.37 3.29a1.003 1.003 0 0 0-1.42 0l-1.83 1.83 3.75 3.75 1.84-1.83z" />
                    </button>
                    <button
                      onClick={() => action(item.id, 'connect')}
                      disabled={loading}
                      style={iconButtonStyle}
                      title="Подключить профиль"
                      aria-label="Подключить профиль"
                    >
                      <MaterialIcon path="M8 5v14l11-7z" />
                    </button>
                    <button
                      onClick={() => action(item.id, 'disconnect')}
                      disabled={loading}
                      style={iconButtonStyle}
                      title="Отключить профиль"
                      aria-label="Отключить профиль"
                    >
                      <MaterialIcon path="M6 6h12v12H6z" />
                    </button>
                    <button
                      onClick={() => removeProfile(item.id)}
                      disabled={loading}
                      style={iconButtonStyle}
                      title="Удалить профиль"
                      aria-label="Удалить профиль"
                    >
                      <MaterialIcon path="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zm3.46-7.12 1.41-1.41L12 11.59l1.12-1.12 1.41 1.41L13.41 13l1.12 1.12-1.41 1.41L12 14.41l-1.12 1.12-1.41-1.41L10.59 13l-1.13-1.12zM15.5 4l-1-1h-5l-1 1H5v2h14V4z" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!isFormOpen && (
              <tr>
                <td style={{ ...thtd, background: '#fbfcfd', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', borderRight: 'none' }} />
                <td style={{ ...thtd, background: '#fbfcfd', borderLeft: 'none', textAlign: 'left' }}>
                  <div style={{ position: 'relative', display: 'inline-flex' }}>
                    <button
                      type="button"
                      onClick={() => setIsCreateMenuOpen((current) => !current)}
                      disabled={loading}
                      style={createRowButtonStyle}
                      aria-label="Создать профиль"
                      title="Создать профиль"
                    >
                      <MaterialIcon path="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6z" />
                    </button>
                    {isCreateMenuOpen && (
                      <div style={createMenuStyle}>
                        {['OPENVPN', 'IPSEC', 'IPSEC.B', 'WIREGUARD'].map((type) => (
                          <button
                            key={type}
                            type="button"
                            onClick={() => startCreate(type)}
                            style={createMenuItemStyle}
                            title={`Создать профиль ${type}`}
                          >
                            {type}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Инстансы</h2>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thtd} title="Имя профиля, которому принадлежит инстанс.">Профиль</th>
              <th style={thtd} title="Тип VPN для этого runtime-контейнера.">Тип</th>
              <th style={thtd} title="Имя Docker-контейнера, который обслуживает подключение.">Runtime container</th>
              <th style={thtd} title="Состояние, которого хочет manager-api.">Желаемое состояние</th>
              <th style={thtd} title="Фактическое состояние контейнера на уровне Docker.">Состояние контейнера</th>
              <th style={thtd} title="Состояние VPN внутри runtime-контейнера.">Реальный статус</th>
              <th style={thtd} title="Статус применения правил проброса портов.">Port Forwards</th>
              <th style={thtd} title="Статус применения пользовательских правил firewall.">Firewall</th>
              <th style={thtd} title="Последняя метка активности VPN, если она доступна.">Last Handshake</th>
              <th style={thtd} title="Последняя диагностическая информация от runtime.">Сообщение</th>
              <th style={thtd} title="Ошибка, сохранённая manager-api для профиля.">Ошибка</th>
            </tr>
          </thead>
          <tbody>
            {instanceRows.length === 0 ? (
              <tr><td style={thtd} colSpan={11}>Нет инстансов</td></tr>
            ) : instanceRows.map((item) => (
              <tr key={item.profileId}>
                <td style={thtd}>{item.name}</td>
                <td style={thtd}>{item.type}</td>
                <td style={thtd}>{item.runtimeContainerName || '-'}</td>
                <td style={thtd}><StatusBadge value={item.managerStatus} /></td>
                <td style={thtd}><StatusBadge value={item.runtimeContainerState || '-'} /></td>
                <td style={thtd}><StatusBadge value={item.workerStatus} /></td>
                <td style={thtd}>
                  <StatusBadge value={item.portForwardingStatus || 'NOT_CONFIGURED'} />
                  <div style={{ marginTop: 6 }}>{item.portForwardingMessage || '-'}</div>
                </td>
                <td style={thtd}>
                  <StatusBadge value={item.firewallStatus || 'NOT_CONFIGURED'} />
                  <div style={{ marginTop: 6 }}>{item.firewallMessage || '-'}</div>
                </td>
                <td style={thtd} title={item.lastHandshakeAt || ''}>{formatRelativeDuration(item.lastHandshakeAt)}</td>
                <td style={thtd}>{item.workerLastMessage || '-'}</td>
                <td style={thtd}>{item.lastError || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}

/**
 * Shared documentation-only typedefs for the MVP.
 */

/**
 * @typedef {Object} WireguardConfig
 * @property {string} tunnelAddress
 * @property {string} privateKey
 * @property {string} peerPublicKey
 * @property {string} presharedKey
 * @property {string} allowedIps
 * @property {string} dnsServers
 * @property {string} persistentKeepalive
 */

/**
 * @typedef {Object} OpenvpnConfig
 * @property {string} configText
 * @property {string} username
 * @property {string} password
 * @property {string} caText
 * @property {string} certText
 * @property {string} keyText
 * @property {string} tlsAuthText
 * @property {string} keyDirection
 */

/**
 * @typedef {Object} IpsecConfig
 * @property {string} preSharedKey
 * @property {string} password
 * @property {string} userId
 * @property {string} localIdentifier
 * @property {string} remoteIdentifier
 * @property {string} dnsServers
 * @property {string} mtu
 * @property {string} mru
 */

/**
 * @typedef {Object} FirewallBasicRule
 * @property {string} id
 * @property {string} table
 * @property {string} chain
 * @property {string} action
 * @property {string} protocol
 * @property {string} source
 * @property {string} destination
 * @property {string} destinationPort
 * @property {string} comment
 */

/**
 * @typedef {Object} FirewallConfig
 * @property {boolean} enabled
 * @property {'BASIC'|'ADVANCED'} mode
 * @property {FirewallBasicRule[]} basicRules
 * @property {string} advancedRules
 */

/**
 * @typedef {Object} PortForwardRule
 * @property {string} id
 * @property {boolean} enabled
 * @property {'tcp'|'udp'} protocol
 * @property {string} hostPort
 * @property {string} targetAddress
 * @property {string} targetPort
 * @property {string} description
 */

/**
 * @typedef {Object} PortForwardingConfig
 * @property {boolean} enabled
 * @property {PortForwardRule[]} rules
 */

/**
 * @typedef {Object} VpnProfile
 * @property {string} id
 * @property {string} name
 * @property {'OPENVPN'|'IPSEC'|'WIREGUARD'} type
 * @property {string} host
 * @property {number} port
 * @property {string} username
 * @property {'STOPPED'|'CONNECTED'|'ERROR'} status
 * @property {string|null} runtimeContainerName
 * @property {string|null} runtimeImage
 * @property {OpenvpnConfig|null} openvpn
 * @property {IpsecConfig|null} ipsec
 * @property {WireguardConfig|null} wireguard
 * @property {FirewallConfig} firewall
 * @property {PortForwardingConfig} portForwarding
 */

/**
 * @typedef {Object} VpnInstance
 * @property {string} profileId
 * @property {string} name
 * @property {'OPENVPN'|'IPSEC'|'WIREGUARD'} type
 * @property {'STOPPED'|'CONNECTED'|'ERROR'} managerStatus
 * @property {string|null} runtimeContainerName
 * @property {string|null} runtimeImage
 * @property {string} runtimeContainerState
 * @property {string} workerStatus
 * @property {string} firewallStatus
 * @property {string|null} firewallMessage
 * @property {string} portForwardingStatus
 * @property {string|null} portForwardingMessage
 * @property {string|null} lastHandshakeAt
 * @property {string|null} workerConnectedAt
 * @property {string|null} workerLastMessage
 * @property {string|null} lastError
 */

module.exports = {};

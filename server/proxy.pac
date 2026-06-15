// SecEoKnight Proxy Auto-Config (PAC) file
// Served by nginx at http://192.168.1.189/proxy.pac
//
// Key safety feature: "PROXY 127.0.0.1:8082; DIRECT"
// means: try the proxy first — if it is unreachable, go DIRECT.
// Internet can never be broken by the proxy being down.

function FindProxyForURL(url, host) {
    // Always bypass plain hostnames (internal servers)
    if (isPlainHostName(host)) return "DIRECT";

    // Always bypass loopback
    if (host === "localhost" || host === "127.0.0.1" || host === "::1")
        return "DIRECT";

    // Always bypass LAN ranges — never proxy local traffic
    if (shExpMatch(host, "192.168.*")) return "DIRECT";
    if (shExpMatch(host, "10.*"))      return "DIRECT";
    if (shExpMatch(host, "172.16.*"))  return "DIRECT";
    if (shExpMatch(host, "172.17.*"))  return "DIRECT";
    if (shExpMatch(host, "172.18.*"))  return "DIRECT";
    if (shExpMatch(host, "172.19.*"))  return "DIRECT";
    if (shExpMatch(host, "172.2*"))    return "DIRECT";
    if (shExpMatch(host, "172.30.*"))  return "DIRECT";
    if (shExpMatch(host, "172.31.*"))  return "DIRECT";

    // All other traffic: try proxy, fall back to DIRECT if proxy is down
    // This line is what prevents internet loss if mitmproxy stops running
    return "PROXY 127.0.0.1:8082; DIRECT";
}

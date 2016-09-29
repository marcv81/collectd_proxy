# collectd_proxy

collectd_proxy is a proxy for the collectd network protocol. It accepts
encrypted or signed packets, and forwards them as plain packets.

Some third-party applications support the collectd protocol, but only the
plain packets. collectd_proxy allows to build a secure interface.

## Example

InfluxDB and collectd_proxy are installed on the same server. A collectd
client publishes statistics over an untrusted network.

### InfluxDB

Listen to the plain collectd protocol on the loopback interface only.

    [[collectd]]
      enabled = true
      bind-address = "127.0.0.1:25826"

### collectd_proxy

Forward the encrypted or signed packets received on port 25827 as plain
packets on port 25826.

    [proxy]
    listen_host = 0.0.0.0
    listen_port = 25827
    send_host = localhost
    send_port = 25826

    [users]
    user = secret

### collectd

Encrypt the statistics.

    <Plugin network>
        <Server "server" "25827">
            SecurityLevel Encrypt
            Username "user"
            Password "secret"
        </Server>
    </Plugin>

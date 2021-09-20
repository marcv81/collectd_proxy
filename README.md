# collectd_proxy

collectd_proxy is a proxy for the collectd network protocol. It accepts
encrypted or signed packets, and forwards them as plain packets.

Some third-party applications support the collectd protocol, but only the
plain packets. collectd_proxy allows to use such applications over an
untrusted network.

## Setup

Setup a virtualenv.

    virtualenv -p python3 venv
    source venv/bin/activate
    pip3 install -r requirements.txt

Run the unit tests.

    python3 -m unittest discover .

Run the program. An optional argument specifies the location of the config
file. `collectd_proxy.ini` is used by default.

    python3 server.py

## Example

InfluxDB and collectd_proxy are installed on the same server. A collectd
client publishes statistics over an untrusted network.

### InfluxDB

In `influxdb.conf`, listen to the plain collectd protocol on the loopback
interface only.

    [[collectd]]
      enabled = true
      bind-address = "127.0.0.1:25826"

### collectd_proxy

In `collectd_proxy.ini`, forward the encrypted or signed packets received
on port 25827 as plain packets on port 25826.

    [proxy]
    listen_host = 0.0.0.0
    listen_port = 25827
    send_host = localhost
    send_port = 25826

    [users]
    user = secret

### collectd

In `collectd.conf`, encrypt the statistics and send them to collectd_proxy.

    <Plugin network>
        <Server "server" "25827">
            SecurityLevel Encrypt
            Username "user"
            Password "secret"
        </Server>
    </Plugin>

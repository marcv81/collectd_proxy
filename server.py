import configparser
import socket
import traceback
import sys

import packet

RECEIVE_BUFFER_SIZE = 4096

# Read config location
config_filename = "/etc/collectd_proxy/collectd_proxy.ini"
if len(sys.argv) > 1:
    config_filename = sys.argv[1]

# Read config
config = configparser.ConfigParser()
config.read_file(open(config_filename))
listen_host = config.get("proxy", "listen_host", fallback="0.0.0.0")
listen_port = int(config.get("proxy", "listen_port", fallback=25827))
send_host = config.get("proxy", "send_host", fallback="localhost")
send_port = int(config.get("proxy", "send_port", fallback=25826))

# Initialize sockets
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receive_socket.bind((listen_host, listen_port))
send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:

    data, address = receive_socket.recvfrom(RECEIVE_BUFFER_SIZE)

    # Try to decrypt/verify the payload
    try:
        encrypted = packet.read_encrypted(data)
        user = packet.read_user(data, encrypted)
        user_str = user.decode()
        assert config.has_option("users", user_str)
        key = config.get("users", user_str).encode()
        payload = packet.read_payload(data, encrypted, user, key)

    # Print a stack trace in case of error
    except AssertionError:
        print("Invalid packet from " + str(address[0]))
        traceback.print_exc()

    # Forward the payload otherwise
    else:
        send_socket.sendto(payload, (send_host, send_port))

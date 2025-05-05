# RDP_Client.py
#!/usr/bin/env python3
import socket
import sys
import time

HEADER_DELIM = b' '
TIMEOUT = 1.0
MAX_PACKET = 2048


def make_packet(flag, seq, ack, payload=b""):
    length = len(payload)
    header = f"{flag} {seq} {ack} {length}".encode('ascii')
    if length:
        return header + b' ' + payload
    return header


def parse_packet(data):
    parts = data.split(HEADER_DELIM, 4)
    flag = parts[0].decode('ascii')
    seq = int(parts[1])
    ack = int(parts[2])
    length = int(parts[3])
    payload = b''
    if length and len(parts) >= 5:
        payload = parts[4]
    return flag, seq, ack, length, payload


def main():
    if len(sys.argv) < 4:
        print(f"Usage: python3 {sys.argv[0]} <Server IP> <port> <Req file> [<Out file>] ")
        sys.exit(1)
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    req_file = sys.argv[3]
    out_file = sys.argv[4] if len(sys.argv) > 4 else 'received_' + req_file

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # --- Handshake ---
    sock.sendto(make_packet('SYN', 0, 0), (server_ip, server_port))
    while True:
        try:
            data, _ = sock.recvfrom(MAX_PACKET)
        except socket.timeout:
            sock.sendto(make_packet('SYN', 0, 0), (server_ip, server_port))
            continue
        flag, _, _, _, _ = parse_packet(data)
        if flag == 'SYN-ACK':
            break
    sock.sendto(make_packet('ACK', 0, 0), (server_ip, server_port))

    # --- GET ---
    sock.sendto(make_packet('GET', 0, 0, req_file.encode('ascii')), (server_ip, server_port))

    # --- Receive DATA ---
    expected = 1
    with open(out_file, 'wb') as f:
        while True:
            try:
                data, _ = sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                # ask for retransmit of last packet
                sock.sendto(make_packet('ACK', 0, expected-1), (server_ip, server_port))
                continue
            flag, seq, _, length, payload = parse_packet(data)
            if flag == 'DATA' and seq == expected:
                if length == 0:
                    # empty => file not found or end-of-file marker
                    break
                f.write(payload)
                # ACK this packet
                sock.sendto(make_packet('ACK', 0, seq), (server_ip, server_port))
                expected += 1
            elif flag == 'DATA':
                # duplicate or out-of-order: ACK last seen
                sock.sendto(make_packet('ACK', 0, expected-1), (server_ip, server_port))
            elif flag == 'FIN':
                # send final ACK and break
                sock.sendto(make_packet('ACK', 0, 0), (server_ip, server_port))
                break
    print(f"File received and stored as: {out_file}")
    sock.close()

if __name__ == '__main__':
    main()
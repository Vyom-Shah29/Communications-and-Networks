# RDP_Server.py
#!/usr/bin/env python3
import socket
import sys
import os
import threading
import time

# Packet formats (text-based header):
# FLAG SEQ ACK LENGTH [payload]
# FLAG: SYN, SYN-ACK, ACK, GET, DATA, FIN
# SEQ/ACK/ LENGTH: integers
# LIGHTWEIGHT stop-and-wait reliable protocol over UDP

HEADER_DELIM = b' '
TIMEOUT = 1.0  # seconds for socket timeout
MAX_PACKET = 1024
# Reserve space for header
MAX_PAYLOAD = 900


def make_packet(flag, seq, ack, payload=b""):
    length = len(payload)
    header = f"{flag} {seq} {ack} {length}".encode('ascii')
    if length:
        return header + b' ' + payload
    return header


def parse_packet(data):
    # split into header fields and payload
    parts = data.split(HEADER_DELIM, 4)
    flag = parts[0].decode('ascii')
    seq = int(parts[1])
    ack = int(parts[2])
    length = int(parts[3])
    payload = b''
    if length and len(parts) >= 5:
        payload = parts[4]
    return flag, seq, ack, length, payload


def handle_client(server_sock, addr):
    server_sock.settimeout(None)
    # --- Handshake ---
    # 1) Receive SYN
    data, _ = server_sock.recvfrom(MAX_PACKET)
    flag, seq, _, _, _ = parse_packet(data)
    if flag != 'SYN':
        return
    # 2) Send SYN-ACK
    server_sock.sendto(make_packet('SYN-ACK', 0, 0), addr)
    # 3) Receive ACK
    server_sock.settimeout(TIMEOUT)
    try:
        data, _ = server_sock.recvfrom(MAX_PACKET)
    except socket.timeout:
        return
    flag, _, _, _, _ = parse_packet(data)
    if flag != 'ACK':
        return

    # --- GET Request ---
    server_sock.settimeout(None)
    data, _ = server_sock.recvfrom(MAX_PACKET)
    flag, _, _, length, payload = parse_packet(data)
    if flag != 'GET':
        return
    filename = payload.decode('ascii')
    # Prepare file chunks
    if not os.path.isfile(filename):
        # send single DATA with empty payload to signal missing file
        server_sock.sendto(make_packet('DATA', 1, 0, b''), addr)
        # finish
        server_sock.sendto(make_packet('FIN', 0, 0), addr)
        return
    with open(filename, 'rb') as f:
        data_bytes = f.read()
    chunks = [data_bytes[i:i+MAX_PAYLOAD] for i in range(0, len(data_bytes), MAX_PAYLOAD)]

    # --- Send DATA with stop-and-wait ---
    seq_num = 1
    for chunk in chunks:
        while True:
            packet = make_packet('DATA', seq_num, 0, chunk)
            server_sock.sendto(packet, addr)
            # wait for ACK
            server_sock.settimeout(TIMEOUT)
            try:
                resp, _ = server_sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            flag_r, _, ack_r, _, _ = parse_packet(resp)
            if flag_r == 'ACK' and ack_r == seq_num:
                break
        seq_num += 1
    # --- Finish ---
    # Send FIN until ACK
    while True:
        server_sock.sendto(make_packet('FIN', 0, 0), addr)
        server_sock.settimeout(TIMEOUT)
        try:
            resp, _ = server_sock.recvfrom(MAX_PACKET)
        except socket.timeout:
            continue
        flag_r, _, _, _, _ = parse_packet(resp)
        if flag_r == 'ACK':
            break


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))
    print(f"RDP Server listening on {host}:{port}")
    while True:
        data, addr = server_sock.recvfrom(MAX_PACKET)
        # spawn a thread per client to handle separately
        threading.Thread(target=lambda: handle_client(server_sock, addr), daemon=True).start()

if __name__ == '__main__':
    main()
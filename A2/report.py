from collections import defaultdict, deque

DECIMALS = 6
    
def collect_connections_info(packets):
    if not packets: return {}

    offset = packets[0].timestamp
    connections = {}
    for p in packets:
        forward = (p.IP_header.src_ip, p.TCP_header.src_port, p.IP_header.dst_ip, p.TCP_header.dst_port)
        backward = (p.IP_header.dst_ip, p.TCP_header.dst_port, p.IP_header.src_ip, p.TCP_header.src_port)

        if forward not in connections:
            if backward not in connections:
                connections[forward] = {
                    "pkt_src_dest_count": 1,
                    "pkt_dest_src_count": 0,
                    "start_time": p.timestamp - offset,
                    "end_time": p.timestamp - offset,
                    "bytes_src_dest_count": p.get_data_bytes(),
                    "bytes_dest_src_count": 0,
                    "syn": p.get_flags()["SYN"],
                    "fin": p.get_flags()["FIN"],
                    "rst": p.get_flags()["RST"],
                    "win_size": [p.get_window_size()],
                    "packets": [
                        {
                            "seq_num": p.get_seq_number(),
                            "ack_num": p.get_ack_number(),
                            "data_bytes": p.get_data_bytes(),
                            "timestamp": p.timestamp - offset,
                            "is_client": True,
                            "fin": p.get_flags()["FIN"],
                            "syn": p.get_flags()["SYN"],
                            "packet_no": p.packet_No
                        }
                    ]
                }
            else:
                updated_info = {
                    "pkt_src_dest_count": connections[backward]["pkt_src_dest_count"],
                    "pkt_dest_src_count": connections[backward]["pkt_dest_src_count"] + 1,
                    "start_time": connections[backward]["start_time"],
                    "end_time": p.timestamp - offset if p.get_flags()["FIN"] == 1 else connections[backward]["end_time"],
                    "bytes_src_dest_count": connections[backward]["bytes_src_dest_count"],
                    "bytes_dest_src_count": connections[backward]["bytes_dest_src_count"] + p.get_data_bytes(),
                    "syn": connections[backward]["syn"] + p.get_flags()["SYN"],
                    "fin": connections[backward]["fin"] + p.get_flags()["FIN"],
                    "rst": connections[backward]["rst"] + p.get_flags()["RST"],
                    "win_size": connections[backward]["win_size"] + [p.get_window_size()],
                    "packets": connections[backward]["packets"] + [{
                            "seq_num": p.get_seq_number(),
                            "ack_num": p.get_ack_number(),
                            "data_bytes": p.get_data_bytes(),
                            "timestamp": p.timestamp - offset,
                            "is_client": False,
                            "fin": p.get_flags()["FIN"],
                            "syn": p.get_flags()["SYN"],
                            "packet_no": p.packet_No
                        }]
                }
                connections[backward] = updated_info
        else:
            updated_info = {
                "pkt_src_dest_count": connections[forward]["pkt_src_dest_count"] + 1,
                "pkt_dest_src_count": connections[forward]["pkt_dest_src_count"],
                "start_time": connections[forward]["start_time"],
                "end_time": p.timestamp - offset if p.get_flags()["FIN"] == 1 else connections[forward]["end_time"],
                "bytes_src_dest_count": connections[forward]["bytes_src_dest_count"] + p.get_data_bytes(),
                "bytes_dest_src_count": connections[forward]["bytes_dest_src_count"],
                "syn": connections[forward]["syn"] + p.get_flags()["SYN"],
                "fin": connections[forward]["fin"] + p.get_flags()["FIN"],
                "rst": connections[forward]["rst"] + p.get_flags()["RST"],
                "win_size": connections[forward]["win_size"] + [p.get_window_size()],
                "packets": connections[forward]["packets"] + [{
                        "seq_num": p.get_seq_number(),
                        "ack_num": p.get_ack_number(),
                        "data_bytes": p.get_data_bytes(),
                        "timestamp": p.timestamp - offset,
                        "is_client": True,
                        "fin": p.get_flags()["FIN"],
                        "syn": p.get_flags()["SYN"],
                        "packet_no": p.packet_No
                    }]
            }
            connections[forward] = updated_info

    return connections

def get_complete_connetions(connections):
    return list(filter(lambda conn: conn['syn'] > 0 and conn['fin'] > 0, connections))

def count_reset_connections(connections):
    return sum(map(lambda conn: min(1, conn['rst']), connections))

def count_not_ended_connections(connections):
    return sum(map(lambda conn: min(1, conn['syn']) - min(1, conn['fin']), connections))

def get_duration(connections, f):
    return round(f(map(lambda conn: conn["end_time"] - conn["start_time"], connections)), DECIMALS)

def get_mean_duration(connections):
    return round(sum(map(lambda conn: conn["end_time"] - conn["start_time"], connections))/len(connections), DECIMALS)

def get_packets(connections, f):
    return f(map(lambda conn: conn["pkt_src_dest_count"] + conn["pkt_dest_src_count"], connections))

def get_mean_packets(connections):
    return round(sum(map(lambda conn: conn["pkt_src_dest_count"] + conn["pkt_dest_src_count"], connections))/len(connections), DECIMALS)

def get_window_size(connections, f):
    return f(map(lambda conn: f(conn["win_size"]), connections))

def get_mean_window_size(connections):
    conns = map(lambda conn: (len(conn["win_size"]), sum(conn["win_size"])), connections)
    length, total = 0, 0
    for l, s in conns:
        length += l
        total += s
    return round(total/length, DECIMALS)

def get_list_RTT(connections):
    rtt = []
    for conn in connections:
        lookup = defaultdict(deque)
        rtt_tmp = []
        for p in conn["packets"]:
            if p["is_client"]:
                if p["data_bytes"] == 0 and (p["syn"] > 0 or p["fin"] > 0): lookup[p["seq_num"] + p["data_bytes"] + 1].append(p["timestamp"])
                else: lookup[p["seq_num"] + p["data_bytes"] + 1].append(p["timestamp"])
            else:
                if p["ack_num"] in lookup and len(lookup[p["ack_num"]]) > 0:
                    rtt_time = p["timestamp"] - lookup[p["ack_num"]].popleft()
                    rtt_tmp.append(rtt_time)

            if p["fin"] > 0:
                rtt += rtt_tmp
                rtt_tmp.clear()
    return rtt

def output_report(packets):
    connections = collect_connections_info(packets)
    print("A) Total number of connections:", len(connections))
    print()
    print("-----------------------------")

    print("B) Connection's details")
    for i, (k, v) in enumerate(sorted(connections.items(), key=lambda item: item[1]["start_time"])):
        print(f'Connection {i + 1}:')
        print(f'Source Address: {k[0]}')
        print(f'Destination Address: {k[2]}')
        print(f'Source Port: {k[1]}')
        print(f'Destination Port: {k[3]}')
        print(f'Status: S{v["syn"]}F{v["fin"]}{"/R" if v["rst"] > 0 else ""}')
        if v["fin"] > 0:
            print(f'Start time: {round(v["start_time"], DECIMALS)} seconds')
            print(f'End Time: {round(v["end_time"], DECIMALS)} seconds')
            print(f'Duration: {round(v["end_time"] - v["start_time"], DECIMALS)} seconds')
            print(f'Number of packets sent from Source to Destination: {v["pkt_src_dest_count"]}')
            print(f'Number of packets sent from Destination to Source: {v["pkt_dest_src_count"]}')
            print(f'Total number of packets: {v["pkt_src_dest_count"] + v["pkt_dest_src_count"]}')
            print(f'Number of data bytes sent from Source to Destination: {v["bytes_src_dest_count"]}')
            print(f'Number of data bytes sent from Destination to Source: {v["bytes_dest_src_count"]}')
            print(f'Total number of data bytes: {v["bytes_src_dest_count"] + v["bytes_dest_src_count"]}')
            print("END")
        print("++++++++++++++++++++++++++++++++")
    print()
    print("-----------------------------")

    complete_connections = get_complete_connetions(connections.values())
    print("C) General")
    print(f'Total number of complete TCP connections: {len(complete_connections)}')
    print(f'Number of reset TCP connections: {count_reset_connections(connections.values())}')
    print(f'Number of TCP connections that were still open when the trace capture ended: {count_not_ended_connections(connections.values())}')

    print()
    print("-----------------------------")
    print("D) Complete TCP connections")
    print(f'Minimum time duration: {get_duration(complete_connections, min)} seconds')
    print(f'Mean time duration: {get_mean_duration(complete_connections)} seconds')
    print(f'Maximum time duration: {get_duration(complete_connections, max)} seconds')
    print()

    rtt = get_list_RTT(complete_connections)
    print(f'Minimum RTT value: {round(min(rtt), DECIMALS)} seconds')
    print(f'Mean RTT value: {round(sum(rtt)/len(rtt), DECIMALS)} seconds')
    print(f'Maximum RTT value: {round(max(rtt), DECIMALS)} seconds')
    print()
    print(f'Minimum number of packets including both send/received: {get_packets(complete_connections, min)}')
    print(f'Mean number of packets including both send/received: {get_mean_packets(complete_connections)}')
    print(f'Maximum number of packets including both send/received: {get_packets(complete_connections, max)}')
    print()
    print(f'Minimum receive window size including both send/received: {get_window_size(complete_connections, min)} bytes')
    print(f'Mean receive window size including both send/received: {get_mean_window_size(complete_connections)} bytes')
    print(f'Maximum receive window size including both send/received: {get_window_size(complete_connections, max)} bytes')

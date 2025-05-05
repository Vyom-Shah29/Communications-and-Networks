import sys
from capfile_parser import Global_Header, Packet_Header, parse_pkt_data
from report import output_report

def main():
    packets = []
    with open(sys.argv[1], 'rb') as f:
        glob_header = Global_Header(f.read(24))

        while True:
            next_bytes = f.read(16)
            if not next_bytes: break
            p_header = Packet_Header(next_bytes, glob_header.byte_order)
            packet = parse_pkt_data(f.read(p_header.incl_len), len(packets) + 1, p_header)
            if packet: packets.append(packet)

    output_report(packets)

if __name__ == "__main__":
    main()

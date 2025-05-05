import struct
from packet_struct import *

MAGIC_NUMBER_SAME = b'\xa1\xb2\xc3\xd4' # big endian
MAGIC_NUMBER_SWAPPED = b'\xd4\xc3\xb2\xa1' # little endian

class Global_Header:
    def __init__(self, data):
        self.byte_order = self._get_magic_number_order(data[:4])
        self.thiszone = self._get_zone(data[9:13])

    def _get_magic_number_order(self, bytes):
        if bytes == MAGIC_NUMBER_SAME:
            return 'big'
        if bytes == MAGIC_NUMBER_SWAPPED:
            return 'little'
        raise ValueError("Invalid magic number")

    def _get_zone(self, bytes):
        return int.from_bytes(bytes, self.byte_order)


class Packet_Header:
    def __init__(self, data, byte_order='big'):
        fmt = '>' if byte_order == 'big' else '<'
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack_from(fmt + 'IIII', data)


def parse_pkt_data(data, number: int, p_header: Packet_Header) -> packet:
    protocol = data[14 + 9]
    if protocol != 6: return None

    ip_header = IP_Header()
    ip_header.set_header_len(data[14:15])
    ip_header_bytes = data[14:14 + ip_header.ip_header_len]
    ip_header.set_total_len(ip_header_bytes[2:4])
    ip_header.set_IP(ip_header_bytes[-8:-8+4], ip_header_bytes[-4:])
    
    tcp_header_bytes = data[14 + ip_header.ip_header_len:]
    tcp_header = TCP_Header()
    tcp_header.set_src_port(tcp_header_bytes[:2])
    tcp_header.set_dst_port(tcp_header_bytes[2:4])
    tcp_header.set_seq_num(tcp_header_bytes[4:8])
    tcp_header.set_ack_num(tcp_header_bytes[8:12])
    tcp_header.set_data_offset(tcp_header_bytes[12:13])
    tcp_header.set_flags(tcp_header_bytes[13:14])
    tcp_header.set_window_size(tcp_header_bytes[14:15], tcp_header_bytes[15:16])

    pkt = packet()
    pkt.set_ip_header(ip_header)
    pkt.set_tcp_header(tcp_header)
    pkt.set_packet_number(number)
    pkt.set_timestamp(p_header.ts_sec, p_header.ts_usec, 0)
    return pkt
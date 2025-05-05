import struct

class IP_Header:    
    def __init__(self):
        self.src_ip = None #<type 'str'>
        self.dst_ip = None #<type 'str'>
        self.ip_header_len = 0 #<type 'int'>
        self.total_len = 0 #<type 'int'>
        
    def set_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        self.src_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        self.dst_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        
    def set_header_len(self, value):
        result = struct.unpack('B', value)[0]
        self.ip_header_len = (result & 15)*4

    def get_header_len(self):
        return self.ip_header_len

    def set_total_len(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.total_len = num1+num2+num3+num4
 

class TCP_Header:    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        
    def set_src_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.src_port = num1+num2+num3+num4
    
    def set_dst_port(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.dst_port = num1+num2+num3+num4
    
    def set_seq_num(self, buffer):
        self.seq_num = struct.unpack(">I",buffer)[0]
    
    def set_ack_num(self, buffer):
        self.ack_num = struct.unpack('>I',buffer)[0]

    def set_flags(self, buffer):
        value = struct.unpack("B",buffer)[0]
        self.flags["ACK"] = (value & 16)>>4
        self.flags["RST"] = (value & 4)>>2
        self.flags["SYN"] = (value & 2)>>1
        self.flags["FIN"] = value & 1

    def set_window_size(self, buffer1, buffer2):
        buffer = buffer2+buffer1
        self.window_size = struct.unpack('H',buffer)[0]

    def set_data_offset(self, buffer):
        value = struct.unpack("B",buffer)[0]
        self.data_offset = ((value & 240)>>4)*4
   

class packet():
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_flag = False

    def set_timestamp(self, seconds, microseconds, orig_time):
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)

    def set_packet_number(self, number):
        self.packet_No = number

    def set_ip_header(self, ip_header):
        self.IP_header = ip_header

    def set_tcp_header(self, tcp_header):
        self.TCP_header = tcp_header

    def get_flags(self):
        return self.TCP_header.flags

    def get_data_bytes(self):
        return self.IP_header.total_len - self.IP_header.get_header_len() - self.TCP_header.data_offset

    def get_window_size(self):
        return self.TCP_header.window_size

    def get_seq_number(self):
        return self.TCP_header.seq_num

    def get_ack_number(self):
        return self.TCP_header.ack_num

    def __str__(self):
        return str(self.__class__) + ": <IP HEADER>" + str(self.IP_header.__dict__) + ": <TCP HEADER>" + str(self.TCP_header.__dict__)

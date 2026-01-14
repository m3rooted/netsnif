import socket
import struct


class IPv6:

    def __init__(self, raw_data: bytes):
        if len(raw_data) < 40:
            raise ValueError('IPv6 header requires at least 40 bytes')

        first_word = struct.unpack('! I', raw_data[:4])[0]
        self.version = (first_word >> 28) & 0xF
        self.traffic_class = (first_word >> 20) & 0xFF
        self.flow_label = first_word & 0xFFFFF

        self.payload_length, self.next_header, self.hop_limit = struct.unpack('! H B B', raw_data[4:8])

        src = raw_data[8:24]
        target = raw_data[24:40]
        self.src = self.ipv6(src)
        self.target = self.ipv6(target)

        self.data = raw_data[40:]

    def ipv6(self, addr: bytes) -> str:
        try:
            return socket.inet_ntop(socket.AF_INET6, addr)
        except (AttributeError, OSError):
            # Fallback: simple hextets formatting (no compression)
            hextets = [addr[i:i + 2] for i in range(0, 16, 2)]
            return ':'.join('{:02x}{:02x}'.format(h[0], h[1]) for h in hextets)

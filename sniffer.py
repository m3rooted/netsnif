import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.ipv6 import IPv6
from networking.ipv6_ext import walk_ipv6_headers
from networking.icmp import ICMP
from networking.icmpv6 import ICMPv6
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

__description__ = "netsnif — Minimal Python network sniffer that prints parsed packets and writes a PCAP file"
__author__ = "Nguyen Duong Quang"
__date__ = "2026-01-14"

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        # IPv6
        elif eth.proto in (34525, 56710):
            try:
                ipv6 = IPv6(eth.data)
            except ValueError:
                print(TAB_1 + 'Malformed IPv6 Packet')
                print(TAB_2 + 'IPv6 Data:')
                print(format_multi_line(DATA_TAB_3, eth.data))
                continue

            print(TAB_1 + 'IPv6 Packet:')
            print(TAB_2 + 'Version: {}, Traffic Class: {}, Flow Label: {}'.format(ipv6.version, ipv6.traffic_class, ipv6.flow_label))
            print(TAB_2 + 'Payload Length: {}, Next Header: {}, Hop Limit: {}'.format(ipv6.payload_length, ipv6.next_header, ipv6.hop_limit))
            print(TAB_2 + 'Source: {}, Target: {}'.format(ipv6.src, ipv6.target))

            walk = walk_ipv6_headers(ipv6.next_header, ipv6.data)

            if len(walk.ext_headers) > 0:
                chain = ' -> '.join(['{}({})'.format(h.name, h.next_header) for h in walk.ext_headers])
                print(TAB_2 + 'Extension Headers: {}'.format(chain))

            if walk.fragment is not None:
                print(TAB_2 + 'Fragment: offset={}, M={}, id={}, next={}'.format(
                    walk.fragment.fragment_offset,
                    walk.fragment.more_fragments,
                    walk.fragment.identification,
                    walk.fragment.next_header,
                ))

            if walk.stopped_on_esp:
                print(TAB_1 + 'IPv6 ESP Payload (encrypted):')
                print(format_multi_line(DATA_TAB_2, walk.l4_payload))
                continue

            if walk.no_next_header:
                print(TAB_1 + 'IPv6 No Next Header')
                continue

            if not walk.should_parse_l4:
                print(TAB_1 + 'IPv6 Fragment (non-first) - skipping L4 parsing')
                continue

            # ICMPv6
            if walk.final_next_header == 58 and len(walk.l4_payload) >= 4:
                icmpv6 = ICMPv6(walk.l4_payload)
                print(TAB_1 + 'ICMPv6 Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmpv6.type, icmpv6.code, icmpv6.checksum))
                print(TAB_2 + 'ICMPv6 Data:')
                print(format_multi_line(DATA_TAB_3, icmpv6.data))

            # TCP
            elif walk.final_next_header == 6 and len(walk.l4_payload) >= 14:
                tcp = TCP(walk.l4_payload)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif walk.final_next_header == 17 and len(walk.l4_payload) >= 8:
                udp = UDP(walk.l4_payload)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv6
            else:
                print(TAB_1 + 'Other IPv6 Data:')
                print(format_multi_line(DATA_TAB_2, walk.l4_payload))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()


main()

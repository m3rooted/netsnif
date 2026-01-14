import struct
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class IPv6ExtensionHeaderInfo:
    name: str
    next_header: int
    length: int


@dataclass
class IPv6FragmentInfo:
    fragment_offset: int
    more_fragments: int
    identification: int
    next_header: int


@dataclass
class IPv6HeaderWalkResult:
    final_next_header: int
    l4_payload: bytes
    ext_headers: List[IPv6ExtensionHeaderInfo]
    fragment: Optional[IPv6FragmentInfo]
    should_parse_l4: bool
    stopped_on_esp: bool
    no_next_header: bool


def _parse_len_8octets_excl_first8(payload: bytes, offset: int) -> int:
    # For HBH(0), Routing(43), Dest(60): 2nd byte is Hdr Ext Len in 8-octet units, excluding first 8 octets.
    if offset + 2 > len(payload):
        return 0
    hdr_ext_len = payload[offset + 1]
    return (hdr_ext_len + 1) * 8


def _parse_ah_len(payload: bytes, offset: int) -> int:
    # For AH(51): 2nd byte is Payload Len in 32-bit words, minus 2.
    if offset + 2 > len(payload):
        return 0
    payload_len = payload[offset + 1]
    return (payload_len + 2) * 4


def walk_ipv6_headers(next_header: int, payload: bytes, max_headers: int = 25) -> IPv6HeaderWalkResult:
    offset = 0
    ext_headers: List[IPv6ExtensionHeaderInfo] = []
    fragment: Optional[IPv6FragmentInfo] = None

    for _ in range(max_headers):
        # No Next Header
        if next_header == 59:
            return IPv6HeaderWalkResult(
                final_next_header=59,
                l4_payload=b'',
                ext_headers=ext_headers,
                fragment=fragment,
                should_parse_l4=False,
                stopped_on_esp=False,
                no_next_header=True,
            )

        # ESP: payload is encrypted; stop walking
        if next_header == 50:
            ext_headers.append(IPv6ExtensionHeaderInfo(name='ESP', next_header=50, length=len(payload) - offset))
            return IPv6HeaderWalkResult(
                final_next_header=50,
                l4_payload=payload[offset:],
                ext_headers=ext_headers,
                fragment=fragment,
                should_parse_l4=False,
                stopped_on_esp=True,
                no_next_header=False,
            )

        # Hop-by-Hop / Routing / Destination Options
        if next_header in (0, 43, 60):
            name = {0: 'Hop-by-Hop', 43: 'Routing', 60: 'Destination Options'}[next_header]
            hdr_len = _parse_len_8octets_excl_first8(payload, offset)
            if hdr_len <= 0 or offset + hdr_len > len(payload):
                # Malformed; treat remaining as payload and stop.
                return IPv6HeaderWalkResult(
                    final_next_header=next_header,
                    l4_payload=payload[offset:],
                    ext_headers=ext_headers,
                    fragment=fragment,
                    should_parse_l4=False,
                    stopped_on_esp=False,
                    no_next_header=False,
                )

            new_next = payload[offset]
            ext_headers.append(IPv6ExtensionHeaderInfo(name=name, next_header=new_next, length=hdr_len))
            offset += hdr_len
            next_header = new_next
            continue

        # Fragment
        if next_header == 44:
            if offset + 8 > len(payload):
                return IPv6HeaderWalkResult(
                    final_next_header=44,
                    l4_payload=payload[offset:],
                    ext_headers=ext_headers,
                    fragment=fragment,
                    should_parse_l4=False,
                    stopped_on_esp=False,
                    no_next_header=False,
                )

            new_next, _reserved, frag_off_res_m, identification = struct.unpack('! B B H I', payload[offset:offset + 8])
            fragment_offset = (frag_off_res_m >> 3) & 0x1FFF
            more_fragments = frag_off_res_m & 1

            fragment = IPv6FragmentInfo(
                fragment_offset=fragment_offset,
                more_fragments=more_fragments,
                identification=identification,
                next_header=new_next,
            )
            ext_headers.append(IPv6ExtensionHeaderInfo(name='Fragment', next_header=new_next, length=8))
            offset += 8
            next_header = new_next

            # If this is not the first fragment, the L4 header is typically absent.
            if fragment_offset != 0:
                return IPv6HeaderWalkResult(
                    final_next_header=next_header,
                    l4_payload=payload[offset:],
                    ext_headers=ext_headers,
                    fragment=fragment,
                    should_parse_l4=False,
                    stopped_on_esp=False,
                    no_next_header=False,
                )

            continue

        # AH
        if next_header == 51:
            hdr_len = _parse_ah_len(payload, offset)
            if hdr_len <= 0 or offset + hdr_len > len(payload):
                return IPv6HeaderWalkResult(
                    final_next_header=51,
                    l4_payload=payload[offset:],
                    ext_headers=ext_headers,
                    fragment=fragment,
                    should_parse_l4=False,
                    stopped_on_esp=False,
                    no_next_header=False,
                )

            new_next = payload[offset]
            ext_headers.append(IPv6ExtensionHeaderInfo(name='AH', next_header=new_next, length=hdr_len))
            offset += hdr_len
            next_header = new_next
            continue

        # Not an IPv6 extension header anymore -> L4
        return IPv6HeaderWalkResult(
            final_next_header=next_header,
            l4_payload=payload[offset:],
            ext_headers=ext_headers,
            fragment=fragment,
            should_parse_l4=True,
            stopped_on_esp=False,
            no_next_header=False,
        )

    # Safety: too many headers; stop
    return IPv6HeaderWalkResult(
        final_next_header=next_header,
        l4_payload=payload[offset:],
        ext_headers=ext_headers,
        fragment=fragment,
        should_parse_l4=False,
        stopped_on_esp=False,
        no_next_header=False,
    )

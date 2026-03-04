import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        # pass  # TODO
        self.version = buffer[0] >> 4
        self.header_len = (buffer[0] & 0xf) * 4
        self.tos = buffer[1]
        self.length = int.from_bytes(buffer[2:4], 'big')
        self.id = int.from_bytes(buffer[4:6], 'big')
        flags_and_offset = int.from_bytes(buffer[6:8], 'big')
        self.flags = flags_and_offset >> 13
        self.frag_offset = flags_and_offset & 0x1fff
        self.ttl = buffer[8]
        self.proto = buffer[9]
        self.cksum = int.from_bytes(buffer[10:12], 'big')
        self.src = util.inet_ntoa(buffer[12:16])
        self.dst = util.inet_ntoa(buffer[16:20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        # pass  # TODO
        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], 'big')

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        # pass  # TODO
        self.src_port = int.from_bytes(buffer[0:2], 'big')
        self.dst_port = int.from_bytes(buffer[2:4], 'big')
        self.len = int.from_bytes(buffer[4:6], 'big')
        self.cksum = int.from_bytes(buffer[6:8], 'big')

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like
"""
Use parser combinators to parse a packet recursively.
Each layer is IPv4 | ICMP | UDP | unknown ;  the last is only pretty printed as hexdump.
"""


def printrecvpacket(data: bytes, pretty: bool = True):
    print(f"Packet data: {data.hex()}")
    if pretty:
        def hexdump_section(title: str, start: int, end: int, indent: str = ""):
            section = data[start:end]
            print(f"{indent}{title} [{start}:{end}] ({len(section)} bytes)")
            for i in range(0, len(section), 16):
                chunk = section[i:i+16]
                hex_chunk = ' '.join(f"{b:02x}" for b in chunk)
                ascii_chunk = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
                print(f"{indent}  {start + i:04x}  {hex_chunk:<47}  {ascii_chunk}")

        if len(data) < 20:
            hexdump_section("Packet (too short for IPv4 header)", 0, len(data))
            return

        try:
            outer_ipv4 = IPv4(data)
        except Exception:
            hexdump_section("Packet (failed to parse IPv4 header)", 0, len(data))
            return

        outer_ip_end = min(outer_ipv4.header_len, len(data))
        print("┌─ IPv4 (outer) \t"
            f"src={outer_ipv4.src} dst={outer_ipv4.dst} "
            f"ttl={outer_ipv4.ttl} proto={outer_ipv4.proto}"
        )
        hexdump_section("│  Header", 0, outer_ip_end, indent="│")

        if outer_ipv4.proto != 1:
            print("└─ Not ICMP payload; raw packet follows")
            hexdump_section("Payload", outer_ip_end, len(data), indent="   ")
            return

        if len(data) < outer_ip_end + 8:
            print("└─ ICMP header truncated")
            hexdump_section("Remaining", outer_ip_end, len(data), indent="   ")
            return

        try:
            icmp = ICMP(data[outer_ip_end:outer_ip_end+8])
        except Exception:
            print("└─ Failed to parse ICMP header")
            hexdump_section("Remaining", outer_ip_end, len(data), indent="   ")
            return

        print("├─ ICMP")
        print(f"│  type={icmp.type} code={icmp.code} cksum=0x{icmp.cksum:x}")
        hexdump_section("│  Header", outer_ip_end, outer_ip_end + 8, indent="│")

        inner_ip_start = outer_ip_end + 8
        if len(data) < inner_ip_start + 20:
            print("└─ Embedded IPv4 header truncated")
            hexdump_section("Remaining", inner_ip_start, len(data), indent="   ")
            return

        try:
            inner_ipv4 = IPv4(data[inner_ip_start:])
        except Exception:
            print("└─ Failed to parse embedded IPv4 header")
            hexdump_section("Remaining", inner_ip_start, len(data), indent="   ")
            return

        inner_ip_end = min(inner_ip_start + inner_ipv4.header_len, len(data))
        print("├─ IPv4 (embedded/original probe)")
        print(
            f"│  src={inner_ipv4.src} dst={inner_ipv4.dst} "
            f"ttl={inner_ipv4.ttl} proto={inner_ipv4.proto}"
        )
        hexdump_section("│  Header", inner_ip_start, inner_ip_end, indent="│")

        inner_udp_start = inner_ip_end
        if inner_ipv4.proto == 17 and len(data) >= inner_udp_start + 8:
            try:
                udp = UDP(data[inner_udp_start:inner_udp_start + 8])
                print("└─ UDP (embedded/original probe)")
                print(
                    f"   src_port={udp.src_port} dst_port={udp.dst_port} "
                    f"len={udp.len} cksum=0x{udp.cksum:x}"
                )
                hexdump_section("   Header", inner_udp_start, inner_udp_start + 8, indent="   ")
            except Exception:
                print("└─ Failed to parse embedded UDP header")
                hexdump_section("Remaining", inner_udp_start, len(data), indent="   ")
        elif inner_ipv4.proto == 17:
            print("└─ Embedded UDP header truncated")
            hexdump_section("Remaining", inner_udp_start, len(data), indent="   ")
        else:
            print("└─ Embedded payload is not UDP")
            hexdump_section("Remaining", inner_udp_start, len(data), indent="   ")
    else:
        # print(f"Packet data: {data.hex()}")
        ipv4 = IPv4(data)
        print(ipv4)
        icmp = ICMP(data[ipv4.header_len:ipv4.header_len+8])
        print(icmp)
        udp = UDP(data[ipv4.header_len+8:ipv4.header_len+16])
        print(udp)

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    """
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        util.print_result([], ttl)
    return []
    """
    sendsock.set_ttl(1)
    sendsock.sendto(b'Hola', (ip, TRACEROUTE_PORT_NUMBER))
    recvsock.recv_select()
    data, (addr, port) = recvsock.recvfrom()
    print(f"Received packet from {addr}:{port}")
    printrecvpacket(data, pretty=False)
    util.print_result([addr], 1)
    return []


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

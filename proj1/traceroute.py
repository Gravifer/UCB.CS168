import util
from dataclasses import dataclass, field
from collections.abc import Callable

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

@dataclass
class ParsedLayer:
    kind: str
    start: int
    end: int
    value: object | None = None
    note: str = ""
    children: list["ParsedLayer"] = field(default_factory=list)


class _PacketView:
    """
    Use parser combinators to parse a packet recursively.
    Each layer is IPv4 | ICMP | UDP | unknown ;  the last is only pretty printed as hexdump.
    """

    Parser = Callable[[bytes, int], ParsedLayer | None]

    @staticmethod
    def _unknown_parser(note: str) -> Parser:
        def parse(data: bytes, start: int) -> ParsedLayer:
            bounded_start = min(max(0, start), len(data))
            return ParsedLayer("unknown", bounded_start, len(data), note=note)

        return parse

    @staticmethod
    def _choice(*parsers: Parser) -> Parser:
        def parse(data: bytes, start: int) -> ParsedLayer | None:
            for parser in parsers:
                parsed = parser(data, start)
                if parsed is not None:
                    return parsed
            return None

        return parse

    @staticmethod
    def _seq(first: Parser, next_for: Callable[[ParsedLayer], Parser | None]) -> Parser:
        def parse(data: bytes, start: int) -> ParsedLayer | None:
            node = first(data, start)
            if node is None:
                return None

            next_parser = next_for(node)
            if next_parser is None:
                return node

            child = next_parser(data, node.end)
            if child is not None:
                node.children.append(child)
            return node

        return parse

    @staticmethod
    def _parse_ipv4(data: bytes, start: int) -> ParsedLayer | None:
        if len(data) - start < 20:
            return None

        try:
            ipv4 = IPv4(data[start:])
        except Exception:
            return None

        if ipv4.header_len < 20:
            return None

        end = min(start + ipv4.header_len, len(data))
        return ParsedLayer("ipv4", start, end, value=ipv4)

    @staticmethod
    def _parse_icmp(data: bytes, start: int) -> ParsedLayer | None:
        if len(data) - start < 8:
            return None

        try:
            icmp = ICMP(data[start:start + 8])
        except Exception:
            return None

        return ParsedLayer("icmp", start, start + 8, value=icmp)

    @staticmethod
    def _parse_udp(data: bytes, start: int) -> ParsedLayer | None:
        if len(data) - start < 8:
            return None

        try:
            udp = UDP(data[start:start + 8])
        except Exception:
            return None

        return ParsedLayer("udp", start, start + 8, value=udp)

    @classmethod
    def _parse_embedded_packet(cls, data: bytes, start: int) -> ParsedLayer:
        parser = cls._choice(cls._chain_parser("ipv4"), cls._unknown_parser("failed to parse embedded packet"))
        parsed = parser(data, start)
        if parsed is None:
            return ParsedLayer("unknown", start, len(data), note="failed to parse embedded packet")
        return parsed

    @classmethod
    def _next_parser(cls, node: ParsedLayer) -> Parser | None:
        match node.kind:
            case "ipv4":
                ipv4 = node.value
                if not isinstance(ipv4, IPv4):
                    return None
                match ipv4.proto:
                    case 1:
                        return cls._chain_parser("icmp")
                    case 17:
                        return cls._choice(cls._parse_udp, cls._unknown_parser("truncated or invalid UDP payload"))
                    case _:
                        return cls._unknown_parser(f"unsupported IPv4 protocol {ipv4.proto}")
            case "icmp":
                return cls._parse_embedded_packet
            case _:
                return None

    @classmethod
    def _chain_parser(cls, kind: str) -> Parser:
        match kind:
            case "ipv4":
                return cls._seq(cls._parse_ipv4, cls._next_parser)
            case "icmp":
                return cls._seq(cls._parse_icmp, cls._next_parser)
            case _:
                raise ValueError(f"Unsupported chain kind: {kind}")

    @classmethod
    def _subtree_end(cls, node: ParsedLayer) -> int:
        end = node.end
        for child in node.children:
            end = max(end, cls._subtree_end(child))
        return end

    @classmethod
    def parse_packet(cls, data: bytes) -> ParsedLayer:
        # since it's traceroute, we expect the outmost to be IPv4
        root = cls._choice(cls._chain_parser("ipv4"), cls._unknown_parser("too short or invalid IPv4 packet"))(data, 0)
        if root is None:
            return ParsedLayer("unknown", 0, len(data), note="too short or invalid IPv4 packet")

        consumed_end = cls._subtree_end(root)
        if consumed_end < len(data):
            root.children.append(ParsedLayer("unknown", consumed_end, len(data), note="trailing bytes"))

        return root

    @staticmethod
    def _hexdump_section(data: bytes, start: int, end: int, indent: str) -> None:
        section = data[start:end]
        for i in range(0, len(section), 16):
            chunk = section[i:i + 16]
            hex_chunk = ' '.join(f"{b:02x}" for b in chunk)
            ascii_chunk = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
            print(f"{indent}{start + i:04x}  {hex_chunk:<47}  {ascii_chunk}")

    @staticmethod
    def _field_boundaries(node: ParsedLayer) -> list[int]:
        length = max(0, node.end - node.start)
        if node.kind == "icmp":
            return [b for b in [1, 2, 4, 8] if b < length]
        if node.kind == "udp":
            return [b for b in [2, 4, 6, 8] if b < length]
        if node.kind == "ipv4":
            base = [1, 2, 4, 6, 8, 9, 10, 12, 16, 20]
            if length > 20:
                base.append(length)
            return [b for b in base if b < length]
        return []

    @classmethod
    def _field_names(cls, node: ParsedLayer) -> list[str]:
        length = max(0, node.end - node.start)
        if node.kind == "icmp":
            names = ["type", "code", "cksum", "rest"]
        elif node.kind == "udp":
            names = ["src_port", "dst_port", "len", "cksum"]
        elif node.kind == "ipv4":
            names = [
                "ver+ihl", "tos", "len", "id", "flags+frag", "ttl",
                "proto", "cksum", "src", "dst"
            ]
            if length > 20:
                names.append("options")
        else:
            return []

        boundaries = cls._field_boundaries(node)
        return names[:len(boundaries) + 1]

    @classmethod
    def _print_known_header_with_separators(cls, data: bytes, node: ParsedLayer, indent: str) -> None:
        start = node.start
        end = node.end
        section = data[start:end]
        boundaries = set(cls._field_boundaries(node))
        parts: list[str] = []
        current: list[str] = []

        for idx, byte in enumerate(section):
            current.append(f"{byte:02x}")
            if (idx + 1) in boundaries:
                parts.append(' '.join(current))
                current = []

        if current:
            parts.append(' '.join(current))

        labels = cls._field_names(node)

        widths: list[int] = []
        for i, part in enumerate(parts):
            label = labels[i] if i < len(labels) else ""
            widths.append(max(len(label), len(part)))

        padded_parts = [part.ljust(widths[i]) for i, part in enumerate(parts)]
        if labels:
            padded_labels = []
            for i in range(len(parts)):
                label = labels[i] if i < len(labels) else ""
                padded_labels.append(label.ljust(widths[i]))
            print(f"{indent}{' ' * 6}{' | '.join(padded_labels)}")

        print(f"{indent}{start:04x}  {' | '.join(padded_parts)}")

    @staticmethod
    def _layer_label(node: ParsedLayer) -> str:
        match (node.kind, node.value):
            case ("ipv4", IPv4() as ipv4):
                return (
                    f"IPv4 src={ipv4.src} dst={ipv4.dst} "
                    f"ttl={ipv4.ttl} proto={ipv4.proto}"
                )
            case ("icmp", ICMP() as icmp):
                return f"ICMP type={icmp.type} code={icmp.code} cksum=0x{icmp.cksum:x}"
            case ("udp", UDP() as udp):
                return (
                    f"UDP src_port={udp.src_port} dst_port={udp.dst_port} "
                    f"len={udp.len} cksum=0x{udp.cksum:x}"
                )
            case _:
                return f"Unknown ({node.note})"

    @classmethod
    def print_layer_tree(cls, data: bytes, node: ParsedLayer, verbose: bool = True, prefix: str = "", is_last: bool = True) -> None:
        connector = "└─" if is_last else "├─"
        length = max(0, node.end - node.start)
        print(f"{prefix}{connector} {cls._layer_label(node)} [{node.start}:{node.end}] ({length} bytes)")

        child_prefix = prefix + ("   " if is_last else "│  ")
        if verbose:
            if node.kind in {"ipv4", "icmp", "udp"}:
                cls._print_known_header_with_separators(data, node, child_prefix)
            else:
                cls._hexdump_section(data, node.start, node.end, child_prefix)

        for i, child in enumerate(node.children):
            cls.print_layer_tree(data, child, verbose, child_prefix, i == len(node.children) - 1)


def parse_packet(data: bytes) -> ParsedLayer:
    return _PacketView.parse_packet(data)


def print_recv_packet(data: bytes, pretty: bool = True, verbose: bool = True) -> None:
    tree = parse_packet(data)
    if pretty:
        _PacketView.print_layer_tree(data, tree, verbose)
    else:
        def print_flat(node: ParsedLayer):
            print(_PacketView._layer_label(node))
            for child in node.children:
                print_flat(child)

        print(f"Packet data: {data.hex()}")
        print_flat(tree)

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

    def validate_probe_reply(data: bytes) -> tuple[int, int, str, int] | None:
        tree = parse_packet(data)

        if tree.kind != "ipv4" or not isinstance(tree.value, IPv4):
            return None
        if tree.value.proto != util.IPPROTO_ICMP:
            return None
        if len(tree.children) == 0:
            return None

        icmp_node = tree.children[0]
        if icmp_node.kind != "icmp" or not isinstance(icmp_node.value, ICMP):
            return None

        icmp = icmp_node.value
        if icmp.type not in (3, 11):
            return None
        if len(icmp_node.children) == 0:
            return None

        embedded_ip_node = icmp_node.children[0]
        if embedded_ip_node.kind != "ipv4" or not isinstance(embedded_ip_node.value, IPv4):
            return None
        if len(embedded_ip_node.children) == 0:
            return None

        embedded_udp_node = embedded_ip_node.children[0]
        if embedded_udp_node.kind != "udp" or not isinstance(embedded_udp_node.value, UDP):
            return None

        embedded_ipv4 = embedded_ip_node.value
        embedded_udp = embedded_udp_node.value
        return icmp.type, icmp.code, embedded_ipv4.dst, embedded_udp.dst_port

    results: list[list[str]] = []
    payload = b"'cs168 Traceroute'"

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        sendsock.set_ttl(ttl)

        ttl_routers: list[str] = []
        seen_routers: set[str] = set()

        for _ in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto(payload, (ip, TRACEROUTE_PORT_NUMBER))

            if not recvsock.recv_select():
                continue

            data, (addr, _) = recvsock.recvfrom()
            validated = validate_probe_reply(data)
            if validated is None:
                continue

            _, _, embedded_dst_ip, embedded_dst_port = validated
            if embedded_dst_ip != ip:
                continue
            if embedded_dst_port != TRACEROUTE_PORT_NUMBER:
                continue

            if addr not in seen_routers:
                seen_routers.add(addr)
                ttl_routers.append(addr)

        util.print_result(ttl_routers, ttl)
        results.append(ttl_routers)

        if ip in seen_routers:
            return results

    return results


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

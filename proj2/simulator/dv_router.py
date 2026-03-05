"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = True
    POISON_REVERSE = False
    # -----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = True

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####
        """cache for triggered adversizing
        record the most recent advertisement sent out of each port for each destination.
        maps dst to list of (time, latency) pairs
        """
        self.history = {}
        ##### End Stage 10A #####

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####
        self.table[host] = TableEntry(
            dst=host,
            latency=self.ports.get_latency(port),
            port=port,
            expire_time=FOREVER,
        )
        self.history[host] = [(api.current_time(), self.ports.get_latency(port))]
        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        
        ##### Begin Stage 2 #####
        # // if not isinstance(packet, api.Packet):
        # //     raise Exception(f"DVRouter should only receive RoutePackets, but got {type(packet)}")
        # drop if 1. no route 2. latency >= INFINITY 3. ttl exceeded 4. not data plane
        if (dst := packet.dst) not in self.table or\
          self.table[dst].latency >= INFINITY :
            return # ? Is entry dropping handled by _ValidatedDict ?
        out_port = self.table[dst].port
        if True:# out_port != in_port:
            # self.log("Forwarding packet %s to port %d" % (packet, out_port), level="debug")
            self.send(packet, port=out_port)
        ##### End Stage 2 #####

    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####
        if not hasattr(self, "history"):
            self.history = {}

        target_ports = (
            [single_port] if single_port is not None else list(self.ports.get_all_ports())
        )

        for port in target_ports:
            for dst, entry in self.table.items():
                is_source = entry.port == port
                if self.SPLIT_HORIZON and is_source:
                    continue

                latency = INFINITY if self.POISON_REVERSE and is_source else entry.latency
                if latency > INFINITY:
                    latency = INFINITY

                history_key = (port, dst)
                prev_latency = self.history.get(history_key)
                if force or prev_latency is None or prev_latency != latency:
                    self.send_route(port, dst, latency)
                    self.history[history_key] = latency
        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Clears out expired routes from table.
        accordingly.
        """
        
        ##### Begin Stages 5, 9 #####
        for dst, entry in list(self.table.items()):
            if entry.expire_time < api.current_time():
                if self.POISON_EXPIRED:
                    self.table[dst] = TableEntry(
                        dst=dst,
                        latency=INFINITY,
                        port=entry.port,
                        expire_time=api.current_time() + self.ROUTE_TTL,
                    )
                else:
                    self.table.pop(dst)
                self.s_log(f"Route to {dst} expired")
        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        assert port is not None, "Got route advertisement with no port specified"
        # - Advertisement from the current next-hop always accepted
        # - only accept strict improvements from other neighbors
        cur_entry = self.table[route_dst] if route_dst in self.table else None
        if cur_entry is not None and cur_entry.expire_time > api.current_time():
            cur_nexthop = cur_entry.port
            cur_latency = cur_entry.latency
        else: # * pylance struggles with ternaries with attribute access
            cur_nexthop = None
            cur_latency = INFINITY
        def saturated_add(a: int, b: int): # * don't rely on arithm with INFINITY
            if a >= INFINITY or b >= INFINITY:
                return INFINITY
            return a + b
        # ? Should we ignore advertisements from ports that are down ? (i.e. not in self.ports)
        if port not in self.ports.get_all_ports():
            raise Exception(f"Received route advertisement from port {port} which is not in self.ports")
        linkcost_to_neighbor = self.ports.get_latency(port)
        sum_latency = saturated_add(route_latency, linkcost_to_neighbor)
        if port == cur_nexthop or sum_latency < cur_latency:
            no_change = port == cur_nexthop and sum_latency == cur_latency
            self.table[route_dst] = TableEntry(
                dst=route_dst,
                latency=sum_latency,
                port=port,
                expire_time=api.current_time() + self.ROUTE_TTL,
            )
            if not no_change:
                self.send_routes()
        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####
        if self.SEND_ON_LINK_UP:
            self.send_routes(force=True, single_port=port)
        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####
        changed = False
        for dst, entry in list(self.table.items()):
            if entry.port != port:
                continue

            if self.POISON_ON_LINK_DOWN:
                self.table[dst] = TableEntry(
                    dst=dst,
                    port=port,
                    latency=INFINITY,
                    expire_time=api.current_time() + self.ROUTE_TTL,
                )
            else:
                self.table.pop(dst)
            changed = True

        if changed:
            self.send_routes(force=False)
        ##### End Stage 10B #####

    # Feel free to add any helper methods!

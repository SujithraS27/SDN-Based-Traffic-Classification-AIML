from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv
import os
import time

class FlowStatsCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        # CSV setup
        self.csv_file = "../datasets/traffic_flows.csv"
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "switch_id",
                    "src_ip", "dst_ip",
                    "src_port", "dst_port",
                    "protocol",
                    "packet_count", "byte_count",
                    "duration_sec", "duration_nsec",
                    "label"
                ])

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)

    def request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = time.time()
        dp_id = ev.msg.datapath.id

        for flow in ev.msg.body:
            if flow.priority == 0:
                continue

            match = flow.match

            src_ip = match.get('ipv4_src', '0.0.0.0')
            dst_ip = match.get('ipv4_dst', '0.0.0.0')
            protocol = match.get('ip_proto', 0)
            src_port = match.get('tcp_src', match.get('udp_src', 0))
            dst_port = match.get('tcp_dst', match.get('udp_dst', 0))

            # LABELING RULE (based on protocol)
            if protocol == 6:
                label = "embb"
            elif protocol == 17:
                label = "urllc"
            elif protocol == 1:
                label = "mmtc"
            else:
                label = "unknown"

            with open(self.csv_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp, dp_id,
                    src_ip, dst_ip,
                    src_port, dst_port,
                    protocol,
                    flow.packet_count,
                    flow.byte_count,
                    flow.duration_sec,
                    flow.duration_nsec,
                    label
                ])

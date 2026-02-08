from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
import csv
import time

class FlowStatsSwitch(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(FlowStatsSwitch, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        self.csv = open("flow_stats.csv", "w", newline="")
        self.writer = csv.writer(self.csv)
        self.writer.writerow([
            "time", "dpid", "src_ip", "dst_ip",
            "packet_count", "byte_count", "duration"
        ])

    # Track connected switches
    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def state_change_handler(self, ev):
        datapath = ev.datapath
        self.datapaths[datapath.id] = datapath

    # Periodically request flow stats
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

    # Receive flow stats
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        for flow in ev.msg.body:
            if flow.priority == 0:
                continue

            self.writer.writerow([
                now,
                ev.msg.datapath.id,
                flow.match.get('ipv4_src', 'NA'),
                flow.match.get('ipv4_dst', 'NA'),
                flow.packet_count,
                flow.byte_count,
                flow.duration_sec
            ])
            self.csv.flush()

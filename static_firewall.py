# Tên file: static_firewall.py
import json
import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

ARP_PRIORITY = 100
ACLRULE_PRIORITY = 11
DENY_PRIORITY = 10

class StaticFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticFirewall, self).__init__(*args, **kwargs)
        self.acl_rules = []
        try:
            with open('rules.json') as f:
                self.acl_rules = json.load(f)
        except: pass
        
        # Xóa log cũ
        if os.path.exists("monitor.dat"):
            os.remove("monitor.dat")
        # Chạy luồng ghi log
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info(">>> STATIC FIREWALL STARTED (LOGGING ENABLED) <<<")

    def _monitor(self):
        while True:
            # Logic hiển thị màu sắc trên Dashboard:
            # - Nếu số luật chặn < 5 (Ví dụ chỉ chặn 2 IP): Coi như vẫn NGUY HIỂM (Mode 1 - Đỏ)
            # - Nếu số luật chặn >= 5 (Chặn gần hết): Coi như AN TOÀN (Mode 2 - Xanh)
            
            num_blocked = 0
            for r in self.acl_rules:
                if r['action'] == 'DENY': num_blocked += 1
            
            mode = 1 if num_blocked < 5 else 2
            
            with open("monitor.dat", "a") as f:
                f.write(f"{time.time()},{mode},{num_blocked}\n")
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        self.add_flow(dp, ARP_PRIORITY, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), 
                      [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)])

        for r in self.acl_rules:
            if r['action'] == 'DENY':
                self.add_flow(dp, ACLRULE_PRIORITY, parser.OFPMatch(eth_type=0x0800, ipv4_src=r['src_ip']), [])
                self.logger.info(f" -> Rule: BLOCK {r['src_ip']}")

        self.add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)])

    def add_flow(self, dp, prio, match, actions):
        inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst))
# Tên file: static_firewall2.py
import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

# Mức ưu tiên
ARP_PRIORITY = 100      # Cho phép ARP
ACLRULE_PRIORITY = 11   # Luật chặn
DEFAULT_PRIORITY = 0    # Mặc định

class StaticFirewall2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticFirewall2, self).__init__(*args, **kwargs)
        self.acl_rules = []
        # ĐỌC FILE RULES2.JSON
        try:
            with open('rules2.json') as f:
                self.acl_rules = json.load(f)
                self.logger.info(f">>> Loaded {len(self.acl_rules)} rules from rules2.json <<<")
        except Exception as e:
            self.logger.info(f"Failed to load rules: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        
        # 1. Cho phép ARP
        self.add_flow(dp, ARP_PRIORITY, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), 
                      [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)])

        # 2. Nạp luật từ rules2.json
        count = 0
        for r in self.acl_rules:
            if r['action'] == 'DENY':
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=r['src_ip'])
                self.add_flow(dp, ACLRULE_PRIORITY, match, []) # Action rỗng = DROP
                self.logger.info(f" -> Installed Rule: BLOCK {r['src_ip']}")
                count += 1
        
        self.logger.info(f">>> Total rules installed: {count} <<<")

        # 3. Luật mặc định
        self.add_flow(dp, DEFAULT_PRIORITY, parser.OFPMatch(), [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)])

    def add_flow(self, dp, prio, match, actions):
        inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst)
        dp.send_msg(mod)
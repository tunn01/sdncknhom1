# ==============================================================================
# TÊN FILE: sdn_smart_firewall.py
# MÔ TẢ: Hệ thống tường lửa SDN thông minh phát hiện và ngăn chặn DDoS
# NỀN TẢNG: Ryu Controller (Python 3)
# TÀI LIỆU THAM KHẢO CHÍNH:
#   [1] Darekar et al. (2022): Cấu trúc Firewall, Priority Rules, OpenFlow.
#   [2] Sapkota et al. (2025): Cơ chế Monitoring định kỳ, Mitigation Timeout.
#   [3] Iqbal et al. (2023): Phân tích thông số mạng (Throughput/PPS) để phát hiện bất thường.
# ==============================================================================

import time
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
from ryu.lib import hub

# --- CẤU HÌNH NGƯỠNG (Dựa trên phân tích tham số mạng của Iqbal et al.) ---
THRESHOLD_PPS = 150    # Ngưỡng gói tin/giây (Sensitivity Analysis)
BLOCK_DURATION = 30    # Thời gian chặn (Giây) - Cơ chế "Reset Victim" của Sapkota
MONITOR_PERIOD = 2     # Chu kỳ lấy mẫu thống kê (Giây)

class SDNSmartFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNSmartFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Lưu trữ thống kê cũ để tính Delta (Tốc độ tức thời)
        self.prev_stats = {} 
        
        # Danh sách IP đang bị chặn
        self.blocked_ips = set()
        
        # Bảng MAC để chuyển mạch (Forwarding)
        self.mac_to_port = {}

        self.logger.info(">>> SDN SMART FIREWALL KHOI DONG <<<")
        self.logger.info(f"[CONFIG] PPS Limit: {THRESHOLD_PPS} | Block Time: {BLOCK_DURATION}s")

    # ==========================================================================
    # PHẦN 1: THIẾT LẬP LUẬT CƠ BẢN (Dựa trên Darekar et al.)
    # ==========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # Rule 0: Table-miss (Gói tin lạ gửi về Controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # [REF: Darekar et al.] ARP Priority
        # Ưu tiên ARP (100) để mạng LAN không bị mất kết nối
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match_arp, actions_arp)

        self.logger.info(f"-> Switch {datapath.id} connected. Default rules installed.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle, hard_timeout=hard)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)

    # ==========================================================================
    # PHẦN 2: GIÁM SÁT & PHÂN TÍCH (Dựa trên Sapkota & Iqbal)
    # ==========================================================================
    
    # [REF: Sapkota et al.] Vòng lặp Monitor (Polling) mỗi chu kỳ
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(MONITOR_PERIOD)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # [REF: Iqbal et al.] Tính Delta để phân tích hành vi (Behavioral Investigation)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.prev_stats.setdefault(dpid, {})
        
        # Gom nhóm packet theo IP nguồn (Source IP Aggregation)
        current_traffic = {} 

        for stat in body:
            # Chỉ xét IPv4, bỏ qua các giao thức quản trị khác
            if 'ipv4_src' in stat.match:
                ip_src = stat.match['ipv4_src']
                if ip_src not in current_traffic:
                    current_traffic[ip_src] = {'pkts': 0, 'bytes': 0}
                
                current_traffic[ip_src]['pkts'] += stat.packet_count
                current_traffic[ip_src]['bytes'] += stat.byte_count

        # Tính toán tốc độ (Rate)
        current_time = time.time()
        
        for ip, stats in current_traffic.items():
            prev = self.prev_stats[dpid].get(ip)
            
            if prev:
                prev_pkts, prev_bytes, prev_time = prev
                
                # [LOGIC] Tính Delta = Mới - Cũ
                delta_pkts = stats['pkts'] - prev_pkts
                time_diff = current_time - prev_time

                # [AN TOÀN] Tránh chia cho 0
                if time_diff > 0.1:
                    # Packet Per Second (PPS) - Chỉ số quan trọng nhất trong Iqbal et al.
                    pps = delta_pkts / time_diff 

                    # Log nếu tốc độ đáng chú ý (>10 pps)
                    if pps > 10: 
                        self.logger.info(f"Analysis [SW:{dpid}] IP:{ip} -> PPS:{pps:.2f}")

                    # Kiểm tra tấn công
                    if pps > THRESHOLD_PPS:
                        if ip not in self.blocked_ips:
                            self.logger.warning(f"\n[!!!] ALERT: DDoS Detected from {ip} (PPS: {pps:.2f})")
                            self._apply_mitigation(ev.msg.datapath, ip)

            # Cập nhật số liệu cũ
            self.prev_stats[dpid][ip] = (stats['pkts'], stats['bytes'], current_time)

    # ==========================================================================
    # PHẦN 3: GIẢM THIỂU TẤN CÔNG (Dựa trên Darekar & Sapkota)
    # ==========================================================================
    def _apply_mitigation(self, datapath, ip_src):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # [REF: Darekar et al.] Rule chặn dựa trên Source IP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        
        # [REF: Sapkota et al.] Sử dụng Hard Timeout để tự động gỡ bỏ sau thời gian chặn
        # Priority 200 > Priority 10 (Forwarding) -> Rule này sẽ được khớp trước
        instructions = [] # Rỗng = DROP
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=BLOCK_DURATION,
            priority=200, 
            instructions=instructions
        )
        datapath.send_msg(mod)
        
        self.logger.info(f"[>>>] BLOCKED {ip_src} for {BLOCK_DURATION}s (Auto-Removal Set).\n")
        self.blocked_ips.add(ip_src)

    # ==========================================================================
    # PHẦN 4: CHUYỂN MẠCH (L2 LEARNING)
    # ==========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Idle Timeout 10s: Giúp bảng Flow Table không bị đầy (Sapkota et al. khuyến nghị)
            self.add_flow(datapath, 10, match, actions, idle=10)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
# Tên file: legacy_switch.py
# Vai trò: Switch truyền thống (L2 Learning Switch) - Không có Firewall
# Mục đích: Dùng để chạy Kịch bản 1 (Chứng minh mạng sập khi bị tấn công)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class LegacySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LegacySwitch, self).__init__(*args, **kwargs)
        # Bảng lưu địa chỉ MAC: {dpid: {mac: port}}
        self.mac_to_port = {}
        self.logger.info(">>> LEGACY SWITCH ACTIVE (NO FIREWALL PROTECTION) <<<")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Xử lý khi Switch kết nối với Controller.
        Cài đặt luồng mặc định (Table-miss Flow Entry) với Priority = 0.
        """
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        # Match: Mọi gói tin (không khớp luồng nào khác)
        match = parser.OFPMatch()
        # Action: Gửi lên Controller (Packet-In)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, prio, match, actions):
        """Hàm hỗ trợ đẩy luồng (Flow) xuống Switch"""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Xử lý gói tin gửi lên Controller.
        Thực hiện chức năng học địa chỉ MAC (Mac Learning).
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        # Lấy thông tin cổng vào và gói tin
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        dst = eth.dst
        src = eth.src
        dpid = dp.id

        # Khởi tạo bảng MAC cho Switch nếu chưa có
        self.mac_to_port.setdefault(dpid, {})

        # Học địa chỉ MAC nguồn: Gói tin từ 'src' đến từ cổng 'in_port'
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        # Kiểm tra xem đã biết cổng của MAC đích chưa
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Nếu chưa biết -> Flooding (Gửi ra tất cả các cổng)
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Nếu không phải là Flooding, cài đặt luồng để lần sau Switch tự chuyển
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Priority 1: Cao hơn mức mặc định (0) nhưng thấp hơn Firewall
            self.add_flow(dp, 1, match, actions)

        # Gửi gói tin hiện tại đi (Packet-Out)
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)
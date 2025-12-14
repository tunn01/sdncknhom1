# # [Căn cứ: Iqbal et al. - Simulation Environment]
# # Import các thư viện cần thiết từ Mininet để tạo mạng ảo
# from mininet.topo import Topo
# from mininet.net import Mininet
# from mininet.node import RemoteController
# from mininet.link import TCLink  # Thư viện để chỉnh sửa thông số đường dây (băng thông, độ trễ)
# from mininet.cli import CLI
# from mininet.log import setLogLevel, info

# # Định nghĩa lớp Topology kế thừa từ lớp cha Topo của Mininet
# class FinalTopo(Topo):
#     def build(self):
#         # Tạo một Switch tên là 's1', sử dụng giao thức OpenFlow 1.3 (chuẩn hiện đại)
#         s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
#         # [QUAN TRỌNG - Iqbal et al.] Cấu hình đường dây mạng
#         # bw=10: Băng thông chỉ 10 Megabit/giây (Rất bé để dễ bị DDOS sập)
#         # delay='5ms': Độ trễ truyền dẫn 5 mili giây (Mô phỏng mạng thật)
#         # loss=0: Không tự làm mất gói tin (để xem DDOS làm mất gói thế nào)
#         # max_queue_size=1000: Hàng đợi tối đa 1000 gói. Quá 1000 sẽ bị tràn (Buffer Overflow)
#         linkopts = dict(bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)

#         # Tạo Host h1 (User hợp lệ - Nạn nhân) với IP và MAC cố định
#         h1 = self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
#         # Nối h1 vào Switch s1 với cấu hình đường dây đã định nghĩa ở trên
#         self.addLink(h1, s1, **linkopts)

#         # Vòng lặp tạo 9 máy tấn công (Botnet) từ h2 đến h10
#         for i in range(2, 11):
#             # Tạo tên host h2, h3... h10
#             h = self.addHost(f'h{i}', ip=f'10.0.0.{i}', mac=f'00:00:00:00:00:{i:02x}')
#             # Nối dây vào switch s1
#             self.addLink(h, s1, **linkopts)

#         # Tạo Server đích h64 (Máy chủ Web bị tấn công)
#         h64 = self.addHost('h64', ip='10.0.0.64', mac='00:00:00:00:00:40')
#         self.addLink(h64, s1, **linkopts)

# # Hàm chính chạy chương trình
# if __name__ == '__main__':
#     # Thiết lập mức log để in thông tin ra màn hình
#     setLogLevel('info')
    
#     # Khởi tạo mạng Mininet với topology đã định nghĩa
#     # link=TCLink: Bắt buộc để tham số bw=10 có tác dụng
#     net = Mininet(topo=FinalTopo(), controller=None, link=TCLink)
    
#     # Thêm Controller từ xa (Ryu) chạy ở cổng 6633
#     net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    
#     # Bắt đầu chạy mạng
#     net.start()
    
#     # In thông báo xác nhận
#     info("*** TOPOLOGY READY: 1 User, 9 Attackers, 1 Server (10Mbps Limit) ***\n")
    
#     # Mở giao diện dòng lệnh (CLI) để người dùng gõ lệnh (như h1 ping h2)
#     CLI(net)
    
#     # Dọn dẹp khi thoát
#     net.stop()

# [Căn cứ: Iqbal et al. - Simulation Environment]
# Import các thư viện cần thiết từ Mininet để tạo mạng ảo

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Định nghĩa lớp Topology kế thừa từ lớp cha Topo của Mininet
class FinalTopo(Topo):
    def build(self):
        # Switch s1 chạy OpenFlow13
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        # Đường truyền mô phỏng theo Iqbal et al.
        linkopts = dict(
            bw=10,                 # 10Mbps (để DDoS dễ làm nghẽn)
            delay='5ms',
            loss=0,
            max_queue_size=1000,
            use_htb=True
        )

        # Host hợp lệ h1 (nạn nhân)
        h1 = self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
        self.addLink(h1, s1, **linkopts)

        # 9 máy tấn công: h2 → h10
        for i in range(2, 11):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}', mac=f'00:00:00:00:00:{i:02x}')
            self.addLink(h, s1, **linkopts)

        # Server bị tấn công
        h64 = self.addHost('h64', ip='10.0.0.64', mac='00:00:00:00:00:40')
        self.addLink(h64, s1, **linkopts)


if __name__ == '__main__':
    setLogLevel('info')

    # Đây là dòng BẮT BUỘC SỬA để dùng OpenFlow13 đúng chuẩn
    net = Mininet(
        topo=FinalTopo(),
        controller=None,
        link=TCLink,
        switch=OVSSwitch     # Sửa tại đây
    )

    # Add Remote Controller (Ryu)
    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # Start network
    net.start()
    info("*** TOPOLOGY READY: 1 User, 9 Attackers, 1 Server (10Mbps Bottleneck) ***\n")

    # EP SWITCH VỀ OpenFlow 1.3 (rất quan trọng)
    info("*** Setting OVS to OpenFlow13...\n")
    net.switches[0].cmd("ovs-vsctl set Bridge s1 protocols=OpenFlow13")

    # Test xem đã set đúng chưa (in ra để bạn chụp hình bỏ báo cáo)
    print(net.switches[0].cmd("ovs-vsctl get Bridge s1 protocols"))

    CLI(net)
    net.stop()

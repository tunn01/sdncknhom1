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

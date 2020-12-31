import threading
import scapy 
import socket
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.l2 import Ether
from scapy.all import sniff
import queue
import os
if os.name == 'nt':
    import pydivert
    

        
class ICMFTP_receiver(threading.Thread):
    def __init__(self,addr,queue):
        self.META_INFO_HEAD_MSG = 'ZZZZ'
        self.addr = addr
        self.queue = queue
        #파일데이터 
        self.meta_created = False
        self.trans_id = ''
        self.data_hash = ''
        self.data_len = 0
        self.filename = ''
        threading.Thread.__init__(self, name='ICMP_IN_'+addr)
        
        
    def listen(self,packet):
        if packet.haslayer(IP) and str(packet.getlayer(IP).src)== self.addr:
            data = packet.build()[42:]
            if self.meta_created:
                '''
                    byte    data
                    0~4     트랜잭션 아이디
                    4~8     인덱스(4uint little)
                    8~??    데이터
                '''
                t_id = data[:4].decode()
                data_idx = int.from_bytes(data[4:8], byteorder='little')
                if self.trans_id == t_id:
                    self.queue.put([data_idx,data[8:]])
            else:
                '''
                    byte    data
                    0~4     매직넘버(ZZZZ)
                    4~8     트랜잭션 아이디
                    8~16    파일검증해쉬(md5 앞 8비트)
                    16~24   파일크기(8uint little)
                    24~??   파일이름(utf-8)   
                '''
                try:
                    decoded_four = data[:4].decode()
                except:
                    pass
                else:
                    if data[:4].decode() == self.META_INFO_HEAD_MSG:
                        self.trans_id = data[4:8].decode()
                        self.data_hash = data[8:16]
                        self.data_len = int.from_bytes(data[16:24], byteorder='little')
                        self.filename = data[24:].decode()
                        self.meta_created = True
                        print(self.trans_id,self.data_hash,self.data_len,self.filename)
                        file_proc = DATA_PROCESS(self.filename,self.queue)
                        file_proc.start()
                    
                
    def run(self):
        print(self.name + " is running")
        pkts=sniff(filter="icmp", prn = self.listen)
           
                
class ICMFTP_sender(threading.Thread):
    def __init__(self,addr,filename,buffsize=1024):
        self.addr = addr
        self.filename = filename
        self.buffsize = buffsize
        self.magic_num = 'ZZZZ'.encode()
        self.trans_id = (123456).to_bytes(4,byteorder="little")
        threading.Thread.__init__(self, name='ICMFTP_sender_'+filename)
        
    def calculate_checksum(self,source_string):
        countTo = (int(len(source_string) / 2)) * 2
        sum = 0
        count = 0
        loByte = 0
        hiByte = 0
        while count < countTo:
            if (sys.byteorder == "little"):
                loByte = source_string[count]
                hiByte = source_string[count + 1]
            else:
                loByte = source_string[count + 1]
                hiByte = source_string[count]
            if not six.PY3:
                loByte = ord(loByte)
                hiByte = ord(hiByte)
            sum = sum + (hiByte * 256 + loByte)
            count += 2

        if countTo < len(source_string): 
            loByte = source_string[len(source_string) - 1]
            if not six.PY3:
                loByte = ord(loByte)
            sum += loByte

        sum &= 0xffffffff 

        sum = (sum >> 16) + (sum & 0xffff)  
        sum += (sum >> 16)               
        answer = ~sum & 0xffff            
        answer = socket.htons(answer)

        return answer
    def send_one_ping(self, data):
        socket_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        checksum = 0
        own_id = os.getpid() & 0xFFFF

        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id,0
        )

        checksum = self.calculate_checksum(header + data)

        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id, 0
        )

        packet = header + data

        try:
            socket_icmp.sendto(packet, (self.addr, 1)) 
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            socket_icmp.close()
            return False
        return True
        
    def run(self):
        print(self.name,"start file transmit")
        '''
        byte    data
        0~4     매직넘버(ZZZZ)
        4~8     트랜잭션 아이디
        8~16    파일검증해쉬(md5 앞 8비트)
        16~24   파일크기(8uint little)
        24~??   파일이름(utf-8)   
        '''
        meta_data = self.magic_num
        meta_data += self.trans_id 
        meta_data += (23456).to_bytes(8,byteorder="little")
        meta_data += (5432).to_bytes(8,byteorder="little")
        meta_data += self.filename.encode()
        with open(self.filename, "rb") as f:
            byte = f.read(self.buffsize)
            while byte:
                self.send_one_ping(byte)
                byte = f.read(self.buffsize)
        print(self.name,"finished file transmit")
                
class DATA_PROCESS(threading.Thread):
    def __init__(self,filename,queue):
        print(filename)
        self.filename = filename
        self.queue = queue
        self.idx = 0
        self.data_dict = {}
        self.filestream = open(filename,'wb')
        threading.Thread.__init__(self, name='DATA_PROCESS_'+filename)

    def run(self):
        print(self.name + " is running")
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                if len(data) == 5 and data.decode() == '_fin_':
                    break
                if data[0] == self.idx:
                    self.filestream.write(data[1])
                    self.idx += 1
                else:
                    self.data_dict[self.idx] = data[1]
                    while self.idx in self.data_dict:
                        self.filestream.write(self.data_dict[self.idx])
                        self.idx += 1
        if len(self.data_dict) > 0:
            print('err')
        else:
            print('fin')
        self.filestream.close()
if __name__ == '__main__':
    que = queue.Queue()
    a = ICMFTP_receiver("172.20.144.127",que)
    a.start()


import socket
from collections import deque
import time


#和sender里的一样

class STP_Segment():
    def __init__(self, ack_t, syn_t, fin_t, data_t,  seq=0, ack=0, wms=500, mss=50, data=None,leng=500):

        self.ACK = ack_t # is ACKnowledgement ?
        self.SYN = syn_t # is SYN ?
        self.FIN = fin_t # is FIN ?
        self.DATA = data_t # is DATA type ?

        self.data = data
        self.seq = seq
        self.ack = ack
        self.length = leng
        self.wms = wms
        self.mss = mss

    def setData(self,data):
        self.data = data
        pass

    def getHeader(self):

        type = (((((((self.ACK << 1) | self.SYN) << 1) | self.FIN )<< 1 )| self.DATA) << 3)
        seq = self.seq
        ack = self.ack
        wms = self.wms
        mss = self.mss
        leng = self.length
        type = type | 0b00000000

        header = (((((((type << 32) | seq) << 32) | ack) << 16 | wms ) << 16 | mss ) << 16 | leng)

        bytes_header = '' # chr((header >> 64))

        lenght = int(header.bit_length()/8) if header.bit_length()%8 == 0 else  int(header.bit_length()/8)+1

        for i in reversed(range(lenght)):
            bytes_header += chr( (header & (0b11111111 << (i*8))  )>> (i*8))

        return bytes_header


    def getPacket(self):

        header = self.getHeader()

        packet = header + self.data if self.data != None else header

        return bytes(packet,encoding='utf-8')

'''
STP 接受端

'''

class STP_Receiver():
    def __init__(self,ip,port,filepath):
        self.ip = ip
        self.port = port
        self.address = (ip,port)
        self.filepath = filepath

        self.cache = deque()
        self.acked_point = 0
        self.waitFor = 0

        self.CloseWait = False #等待关闭状态
        self.LASTACK = False  #第二次握手关闭
        self.Established = False #确认等待数据传输

        self.waiteCounter = 0 # 对重传计数

        self.log_file = open('Receiver_log.txt', 'w')
        self.get_file = open(self.filepath,'w')

        self.seq = 0



        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.address)

    #解析数据
    def parse(self,data):

        data = data.decode('utf-8')

        type_bit = ord(data[0])

        ack_t = int((type_bit & 0b1000000)>>6)
        syn_t = int((type_bit & 0b0100000)>>5)
        fin_t = int((type_bit & 0b0010000)>>4)
        data_t = int((type_bit & 0b0001000)>>3)

        seq = 0
        ack = 0
        wms = 0
        mss = 0
        leng = 0

        for i in range(4):
            seq = ((ord(data[i + 1])) | seq << 8)
            ack = ((ord(data[i + 5])) | ack << 8)

        for i in range(2):
            wms = ((ord(data[i + 9])) | wms << 8)
            mss = ((ord(data[i + 11])) | mss << 8)
            leng = ((ord(data[i + 13])) | leng << 8)

        v_data = data[15:]

        header = {'seq':seq,'ack':ack,'ACK':ack_t,'SYN':syn_t,'FIN':fin_t,'DATA':data_t,'data':v_data,'WMS':wms,'MSS':mss,'length':leng}

        self.WMS = wms
        self.MSS = mss

        return header

    #三次握手，连接
    def accept(self):

        self.Time = time.time()

        flag = 0
        while True:
            data,addr = self.sock.recvfrom(1024)
            header = self.parse(data)

            if header['SYN'] == 1 and header['ACK'] == 0:
                innerTime = (time.time() - self.Time) * (10 ** 5)
                #self.log_file.writelines('rcv    ' + str(innerTime) + '     SA    ' + str(header['seq']) + '     0     ' + str(header['ack']) + '\n')
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'SA', header['seq'], 0, header['ack']))
                segment = STP_Segment(1,1,0,0,self.seq,header['seq']+1,self.WMS,self.MSS)
                self.sock.sendto(segment.getPacket(),addr)
                self.seq += 1

                self.waitFor = header['seq'] + 1
                flag = 1

            elif header['ACK'] == 1 and header['SYN'] == 0 and flag == 1:
                innerTime = (time.time() - self.Time) * (10 **5)
                #self.log_file.writelines('rcv    ' + str(innerTime) + '     SA    ' + str(header['seq']) + '     0     ' + str(header['ack']) + '\n')
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'SA', header['seq'], 0,header['ack']))

                self.WMS = header['WMS']
                self.MSS = header['MSS']
                self.Established = True

                return 0
            else:
                continue
    #接收数据
    def recv(self):

        for i in range(self.WMS):
            self.cache.append(None)

        while True:
            try:
                data,addr = self.sock.recvfrom(1024)
            except:
                return 0

            args = self.parse(data)
            seq = args['seq']

            #self.cache.append((args['seq'],args['data']))


            if args['ACK'] == 1 and args['DATA'] == 1 and self.Established == True:
                innerTime = (time.time() - self.Time) * (10 **5)
                #self.log_file.writelines('rcv    ' + str(innerTime) + '     D    ' + str(args['seq']) + '     0     ' + str(args['ack']) + '\n')
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'D', args['seq'], self.MSS, args['ack']))
                '''
                如果小于waitfor，那么就说明，这个packet是已经被确认的，所以drop掉
                '''
                if seq < self.waitFor:
                    continue

                '''
                如果接收到的这个packet在cache里，但是不是等待的哪个（waitfor），那么continue，因为packet已经在cachele，如果继续将packetappend到cache，那么会产生重复
                '''
                if seq != self.waitFor:

                    flag = 0

                    for i in self.cache:
                        if i != None and i[0] == seq:
                            flag = 1
                            break
                    if flag == 1:
                        continue
                '''
                更新ack，请求下一个数据包
                '''

                if seq == self.waitFor :
                    index = (seq-self.waitFor)//self.MSS
                    self.cache[index] = (seq, args['data'])
                    print("-------------------",index)



                    num = 0
                    for j in self.cache:
                        if j == None:
                            break
                        else:
                            num += 1

                    ack_response = seq

                    #可以确认收到的有序packet列，并将它们存入文件

                    for i in range(num):
                        ack_data = self.cache.popleft()
                        self.cache.append(None)

                        #ack_data = self.cache.popleft()
                        print(ack_data)
                        self.get_file.write(ack_data[1])
                        self.waitFor += self.MSS
                        ack_response += self.MSS

                        seg = STP_Segment(1,0,0,0,self.seq,ack_response)
                        self.seq += 1

                        self.waiteCounter = 0
                        #发送确认收到packet

                        self.sock.sendto(seg.getPacket(),addr)

                        #计数器质零

                        self.waiteCounter = 0

                        innerTime = (time.time() - self.Time) * (10 ** 5)
                        #self.log_file.writelines('snd    ' + str(innerTime) + '     A    ' + str(args['seq']) + '     0     ' + str(args['ack']) + '\n')
                        self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'A', self.seq, 0, args['ack']))
                        self.seq += 1
                #如果接受到的数据包不是等待的哪个，那么发送对上一个已确认的packet的重复确认包
                else:

                    index = (seq-self.waitFor) // self.MSS

                    self.cache[index] = (seq,args['data'])

                    ack_response = self.waitFor

                    self.waiteCounter += 1

                    #如果小于三，那么继续重传确认包

                    if self.waiteCounter <= 3:
                        seg = STP_Segment(1,0,0,0,0,ack_response)

                        self.sock.sendto(seg.getPacket(),addr)
                        innerTime = (time.time() - self.Time) * (10 ** 5)

                        #self.log_file.writelines('snd    ' + str(innerTime) + '     A    ' + str(args['seq']) + '     0     ' + str( args['ack']) + '\n')
                        self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'A', self.seq, 0, args['ack']))
                        self.seq += 1
                    #大于三，那么不在重传，并将计数器质零
                    else:
                        #self.waiteCounter = 0
                        pass

            elif args['FIN'] == 1 :

                innerTime = (time.time() - self.Time) * (10 ** 5)
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'F', args['seq'], 0, args['ack']))

                seg = STP_Segment(1,0,0,0,self.seq,args['seq'])
                self.seq += 1
                self.sock.sendto(seg.getPacket(),addr)

                innerTime = (time.time() - self.Time) * (10 ** 5)
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'A', self.seq, 0, args['ack']))

                self.CloseWait = True
                self.Established = False
                self.seq += 1

                '''

                仍然可以从接受端向发送端发送数据，但此处单向简化

                '''

                seg = STP_Segment(1, 0, 1, 0, self.seq, args['seq'])
                self.sock.sendto(seg.getPacket(), addr)

                innerTime = (time.time() - self.Time) * (10 ** 5)
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'FA', self.seq, 0, args['ack']))

            elif args['ACK'] == 1 and args['DATA'] == 0 and self.CloseWait == True:
                    innerTime = (time.time() - self.Time) * (10 ** 5)
                    self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'A', self.seq, 0, args['ack']))

                    self.LASTACK = True
                    self.sock.close()
                    return 0


if __name__ == '__main__':
    '''
    如果命令行操作，把这块注释去掉

    '''
    '''
    import sys

    args = sys.argv

    ip = args[1]
    port = args[2]
    filePath = args[3]
    stp = STP_Receiver(ip,port,filePath)
    stp.accept()
    data = stp.recv()

    '''
    ''''
    如果命令行操作，把这块注释
    '''
    stp = STP_Receiver('127.0.0.1',8080,'file.txt')
    stp.accept()
    data = stp.recv()


#-*- coding=utf-8 -*-

import socket
from collections import deque

import os
import time
import random

import threading

'''
需要发送的数据的packet类，主要是方便把需要传输的数据进行压缩，返回一个bytes串，进行传输

'''
class STP_Segment():
    def __init__(self,ack_t,syn_t,fin_t,data_t,seq = 0,ack=0,wms = 500,mss=50,data=None,len=500):

        self.ACK = ack_t # is ACKnowledgement ?
        self.SYN = syn_t # is SYN ?
        self.FIN = fin_t # is FIN ?
        self.DATA = data_t # is DATA type ?

        self.data = data # 数据段
        self.seq = seq #seq号
        self.ack = ack # ack码
        self.length = len #数据长度



        self.wms = wms # 最大窗口size
        self.mss = mss #数据包size

    '''
    设置数据data
    '''
    def setData(self,data):
        self.data = data

    '''
    把当前header数据封装成bytes
    '''

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

    '''

    将当前packet内的所有数据进行封装，返回bytes串，直接返回
    '''
    def getPacket(self):

        header = self.getHeader()

        packet = header + self.data if self.data != None else header

        return bytes(packet,encoding='utf-8')


'''
PLD模块，模拟丢包

'''
class PLD():
    def __init__(self,seed,pdrop):
        self.seed = seed
        self.pdrop = pdrop


    def drop(self):
        random_num = random.random()

        if random_num > self.pdrop:
            return False
        else:
            return True

'''
计时器，进行计时操作
'''

class Timer():
    def __init__(self,timeout):
        self.timeout = timeout
        self.startTime = time.time()
        self.closed = False
        pass

    #计时开始
    def start(self):
        self.startTime = time.time()

    #关闭计时器，
    def close(self):
        self.closed = True
    #计时器暂停，并返回是否超时
    def stop(self):
        self.stopTime = time.time()

        if self.close == True:
            return False

        if self.timeout > (self.stopTime - self.startTime)*(10**6):
            return False
        else:
            return True
    #返回当前计时器已经过了多久
    def interval(self):
        return (time.time()-self.start())*(10**6)


'''

封装的STP

'''
class STP_Sender():
    def __init__(self,MWS,MSS,seed,pdrop,timeout=0.1):

        self.lock = threading.Lock()

        self.stateFin1 = False #开始关闭
        self.statFin2 = False # 已完成第二次关闭握手
        self.Established = False #是否是连接已建立状态

        self.retransmit = 0 # 最新的那个已发送并已确认的packet，的重复请求的次数，超过三，那么他的下一个packet就需要进行重传（快重传算法）

        self.Time = time.time() # 传输开始时时间
        self.MWS = MWS #最大窗口值
        self.MSS = MSS # 最大包size
        self.timeout = timeout #超时时间
        self.seed = seed # seed
        self.pdrop = pdrop #丢包可能性

        self.front = 0 # 指向缓冲区最右端的指针
        self.back = MWS #指向缓冲区最左端指针
        self.waitAck = self.front # 当前已发送未确认 和 可发送但未发送的分界指针
        self.sizeOf = self.front # 初始时，front指针和0的差值


        self.seq = 0
        self.ack = 0

        self.temp_cache = deque() # 缓存已发送但未确认的packet 的ack值
        self.temp_cache_entry = deque() # 缓存已发送但未确认的packet 的内容
        self.loss_list = deque() # 发生丢失的包放在这

        self.timer_list = deque() #每一个在缓冲区的packet都设置一个timer

        self.rand = PLD(self.seed,self.pdrop) # PLD模块
        self.log_file = open('Sender_log.txt','w') #log文件

        random.seed(self.seed) #初始化random

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    '''
    解析获取到的数据，并返回一个字典, 前四位是 四种类型packet的位置， 然后32位是seq号，其次是32位ack号，再次是 16位wms ，16位mss， 16位length，往后是数据段

    '''
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
            seq =( ( ord(data[i+1]) ) | seq << 8 )
            ack =( ( ord(data[i+5]) ) | ack << 8 )

        for i in range(2):
            wms = ((ord(data[i + 9])) | wms << 8)
            mss = ((ord(data[i + 11])) | mss << 8)
            leng = ((ord(data[i + 13])) | leng << 8)

        v_data = data[15:]

        header = {'type':None,'seq':seq,'ack':ack,'ACK':ack_t,'SYN':syn_t,'FIN':fin_t,'DATA':data_t,'data':v_data,'WMS':wms,'MSS':mss,'length':leng}

        if ack_t == 1:
            header['type'] = 'ACK'
        elif syn_t == 1:
            header['type'] = 'SYN'
        elif fin_t == 1:
            header['type'] = 'FIN'
        elif data_t == 1:
            header['type'] = 'DATA'

        return header

    '''
    三次握手链接
    '''

    def connect(self,ip,port):
        self.ip = ip
        self.port = port
        self.address = (ip,port)

        self.Time = time.time()  # 传输开始时时间

        '''
        第一次握手，
        '''
        segment = STP_Segment(0,1,0,0,0,0,self.MWS,self.MSS,None)
        self.sock.sendto(segment.getPacket(),self.address)

        innerTime = (time.time() - self.Time) * 10 ** 5
        #self.log_file.writelines('snd    '+str(round(innerTime,2))+'     S    0      0      0 '+ '----后面这块是为了帮助理解，可删掉----- 当前waitAck指针  '+ str(self.waitAck) + '   当前back指针  ' +str(self.back) +'\n')
        self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'S', 0, 0, 0))

        self.sock.settimeout(self.timeout)

        '''
        等待接受端返回数据并解析
        '''
        data, addr = self.sock.recvfrom(1024)
        header = self.parse(data)

        #
        innerTime = (time.time()-self.Time)*10**5
        #self.log_file.writelines('rcv    '+str(round(innerTime,2))+'     SA    '+ str(header['seq'])+ '     0     '+str(header['ack'])+'----后面这块是为了帮助理解，可删掉----- 当前waitAck指针  '+ str(self.waitAck) + '   当前back指针  ' +str(self.back) +'\n')
        self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' %('rcv' ,innerTime,'SA' ,header['seq'] ,0 ,header['ack']))
        seq = header['seq']
        ack = header['ack']
        ack_t = header['ACK']
        syn_t = header['SYN']
        fin_t = header['FIN']
        data_t = header['DATA']

        #如果ack type不是1,或者syn type不是1 ，那么握手不成功
        if ack_t != 1 or syn_t != 1:
            raise 'connect error'

        '''
        front指针初始化
        '''
        self.front = header['ack']
        self.waitAck = self.front
        self.back = self.front + self.MWS
        self.sizeOf = self.front

        '''
        第二次握手，
        '''
        segment = STP_Segment(1, 0, 0, 0,ack, seq+1,self.MWS,self.MSS, None)
        self.sock.sendto(segment.getPacket(),self.address)

        innerTime = (time.time() - self.Time) * 10 ** 5
        #self.log_file.writelines('snd    '+str(round(innerTime,2))+'     A    '+str(header['seq'])+'     0    ' +str(header['ack'])+ '----后面这块是为了帮助理解，可删掉----- 当前waitAck指针  '+ str(self.waitAck) + '   当前back指针  ' +str(self.back) +'\n')
        self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'S',header['seq'],0, header['ack']))
        self.seq = self.waitAck
        self.ack = header['seq'] + 1

        '''
        进入链接成功状态，等待数据传输
        '''
        self.Established = True
        return 1

    '''
    关闭链接
    '''
    def close(self):

        seg = STP_Segment(0,0,1,0,self.waitAck-self.MSS)

        self.sock.sendto(seg.getPacket(),self.address)

        self.stateFin1 = True
        self.Established = False

        pass

    '''
    检查是否有超时
    '''

    def checkTimout(self):

        timeout_index = -1

        for i, v in enumerate(self.timer_list):
            if v.stop() == True:
                timeout_index = i
                break

        if timeout_index == -1:
            return False

        #如果有超时，就返回True， 同时超时的packet 在 temp_cache之后的所有packet的timer关闭
        if timeout_index != -1:

            self.loss_list.append(self.temp_cache[timeout_index])

            for i in range(timeout_index+1,len(self.temp_cache)):
                self.timer_list[i].close()

            return True
    #如果发生超时，那么进行处理

    def handleTimeout(self):
        #self.lock.acquire()


        temp_ack = self.loss_list.popleft()

        #更新waitack，赋值为超时的ack号
        self.waitAck = temp_ack

        self.cleanUnAck(self.waitAck)

        #self.lock.release()

    #把unack后面的所有未确认的packet从temp cache中清除

    def cleanUnAck(self,unack):
        index = self.temp_cache.index(unack)
        for i in range(index,len(self.temp_cache)):
            self.temp_cache.pop()
            self.timer_list.pop()
            self.temp_cache_entry.pop()

    '''

    确认已收到的packet
    '''
    def verify(self,v_ack):

        index = self.temp_cache.index(v_ack)

        num_ack = index + 1

        #print(' 3  check num', num_ack)
        for i in range(num_ack):
            print('确定成功传输')
            self.temp_cache.popleft()
            self.temp_cache_entry.popleft()
            #self.Ack_list.popleft()
            self.timer_list.popleft()
            self.back += self.MSS
            self.front += self.MSS

        #print('移除后   temp cache',self.temp_cache)
    '''
    发送数据
    '''
    def send(self,filepath):
        self.filepath = filepath

        file = open(filepath)
        file.seek(0)
        s1 = file.tell()
        file.seek(0,os.SEEK_END)
        s2 = file.tell()

        file_size = s2-s1

        while True:

            '''
            如果窗口内还有可发送空间，那么继续发送数据
            '''
            if self.Established == True:

                '''
                如果还有可发送的数据，那么发送
                '''

                if self.back - self.waitAck > 0:

                    file.seek(self.waitAck-self.sizeOf)
                    file_data = file.read(self.MSS)

                    if file_data == '' :

                        if self.waitAck == self.front:
                            self.close()

                            print('即将garni')
                    else:
                        seg = STP_Segment(1,0,0,1,self.waitAck,ack=0,wms=self.MWS,mss=self.MSS)
                        seg.setData(file_data)

                        self.temp_cache.append(self.waitAck)
                        self.temp_cache_entry.append(self.parse(seg.getPacket()))
                        self.timer_list.append(Timer(self.timeout))

                        if self.rand.drop() == False:
                            self.sock.sendto(seg.getPacket(),self.address)

                            innerTime = (time.time() - self.Time) * 10 ** 5
                            #self.log_file.writelines('snd    '+str(round(innerTime,2))+'    D    '+str(self.waitAck) + '    '+str(self.MSS)+'    '+str(self.ack)+ '----后面这块是为了帮助理解，可删掉----- 当前waitAck指针  '+ str(self.waitAck) + '   当前back指针  ' +str(self.back)  +'  \n')
                            self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('snd', innerTime, 'D',self.waitAck, self.MSS, self.ack))
                        else:
                            innerTime = (time.time() - self.Time) * 10 ** 5
                            #self.log_file.writelines('drop   '+str(round(innerTime,2))+'    D    '+str(self.waitAck)+ '    '+str(self.MSS) + '   '+str(self.ack)+ '----后面这块是为了帮助理解，可删掉------ 当前waitAck指针  '+str(self.waitAck) + '   当前back指针  ' +str(self.back)+'\n')
                            self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('pdrop', innerTime, 'D', self.waitAck, self.MSS, self.ack))

                        self.waitAck += self.MSS
            '''
            设置非阻塞，接受数据，解析数据

            '''

            self.sock.setblocking(False)
            server_data = ''

            try:
                server_data,server_addr = self.sock.recvfrom(1024)
            except :
                #print('  无数据  ')
                pass

            parse_data = {}


            '''
            数据不为空，那么解析
            '''
            if server_data != '':
                parse_data = self.parse(server_data)

                self.seq = parse_data['seq']

                innerTime = (time.time() - self.Time) * 10 ** 5
                #self.log_file.writelines('rcv    ' + str(round(innerTime, 2)) + '    A    ' + str(parse_data['seq']) + '    ' + str(self.MSS) + '    ' + str(parse_data['ack']) + '----后面这块是为了帮助理解，可删掉----- 当前waitAck指针  '+ str(self.waitAck) + '   当前back指针  ' +str(self.back) + '\n')
                self.log_file.writelines('%-6s %-8.2f %-6s %-6d %-4d %-6d\n' % ('rcv', innerTime, 'A', parse_data['seq'], self.MSS, parse_data['ack']))
            else:

                '''
                数据为空那么检超时，处理
                '''

                if self.checkTimout() == True:
                    '''
                    这是版主理解的log输出，提交时可以注释掉
                    '''
                    self.log_file.writelines('----------超时-----------\n')

                    self.handleTimeout()

                if len(parse_data) == 0:
                    continue

            ''''
            如果是确认包，那么进行确认
            '''
            if parse_data['ACK'] == 1 and self.stateFin1 == False:

                ack_get = parse_data['ack'] - self.MSS

                #self.log_file.writelines('--------------1   ' + str(ack_get) + str(self.temp_cache) + '     +' + str(self.waitAck) + '+\n')

                if ack_get in self.temp_cache :
                    self.verify(ack_get)
                    #self.log_file.writelines('--------------2    '+str(ack_get)+str(self.temp_cache)+'     +' +str(self.waitAck) +'+\n')

                else:
                    if ack_get+self.MSS in self.temp_cache:
                        self.retransmit += 1
                #self.log_file.writelines('--------------3   ' + str(ack_get) + str(self.temp_cache) + '     +' + str(self.waitAck) + '+\n')

                #重确认超过三次，那么重传
                if self.retransmit >= 3:

                    self.retransmit = 0

                    self.waitAck = ack_get + self.MSS

                    #self.log_file.writelines('--------三次------' + str(ack_get) + str(self.temp_cache) + '     +' + str(self.waitAck) + '+\n')
                    '''


                    if len(self.temp_cache) == 0:

                        #结束传输，四次握手关闭链接

                        #self.close()
                        #continue
                        pass
                    '''
                    self.cleanUnAck(self.front)
                    continue

                #self.log_file.writelines('--------------4    ' + str(ack_get) + str(self.temp_cache) + '     +' + str(self.waitAck) + '+\n')

                if self.checkTimout() == True:
                    self.handleTimeout()

                    self.log_file.writelines('--------------超时-------此处是帮助lob可删去    当前超时packet的前一个已经确认的packet seq  ' + str(ack_get)  + '         当前waitack  ' + str(self.waitAck) + '\n')

            #链接关闭处理

            elif parse_data['ACK'] == 1 and parse_data['FIN'] == 0 and self.stateFin1 == True:
                '''
                继续接受来自接收方的data数据

                '''

                self.statFin2 = True

            #彻底关闭

            elif parse_data['ACK'] == 1 and parse_data['FIN'] == 1 and self.statFin2 == True:
                '''

                等待，发送最后一次确认，关闭

                '''

                seg = STP_Segment(1, 0, 0, 0, parse_data['ack'], parse_data['seq'] + 1)
                self.sock.sendto(seg.getPacket(), server_addr)


                time.sleep(2)

                self.sock.close()
                print('关闭soclet')
                return 0


if  __name__ == '__main__':

    import sys


    '''
    下面注释掉的这块是命令行输入的时候使用的

    '''
    '''
    args = sys.argv
    ip = args[1]
    port = int(args[2])
    filePath = args[3]
    mws = int(args[4])
    mss = int(args[5])
    timout = int(args[6])
    pdrop = float(args[7])
    seed = int(args[8])

    sender = STP_Sender(mws,mss,seed,pdrop,timout)
    sender.connect(ip,port)
    sender.send(filePath)

  '''
    '''
    这块可以直接测试，修改参数就行  ， 560 是MWS,  56是 MSS，  300 是Seed， 0.3是pdrop， 100是timeout（ms）

    '''

    sender = STP_Sender(560,56,300,0.3,100)
    sender.connect('127.0.0.1',8080)
    sender.send('./test1.txt')



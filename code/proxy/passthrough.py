import socket, threading, logging, argparse, time
import threading, random
from queue import Empty
from threading import Thread
from queue import Queue
import sys
from util import *
from TLSRecon import TLSType
from scapy.all import *




class Session(threading.Thread):
    def __init__(self,d_addr,d_sock,logger):
        threading.Thread.__init__(self)
        self.d_sock = d_sock
        self.d_addr = d_addr
        self.termination = Queue()
        self.server_q = Queue()
        self.device_q = Queue()
        self.s_addr = original_addr(d_sock)
        self.logger = logger
        self.checkSession = 0
        self.delay_status = 1
        self.pattern = []
        #self.lastPacketLength = 0
        self.lastPacketTime = 0
        self.lenQueue = Queue(7)
        #self.packetQueue = Queue()
        self.queryTime = 0



    def run(self):
        self.s_sock = self.connect_server(self.s_addr)
        t_dr = Thread(target=self.device_read, name='device read')
        t_dw = Thread(target=self.device_write, name='device write')
        t_sr = Thread(target=self.server_read, name='server read')
        t_sw = Thread(target=self.server_write, name='server write')
        t_dr.start()
        t_sr.start()
        t_dw.start()
        t_sw.start()
        self.logger.info('new session with %s is established'%(str(self.s_addr)))
        if self.termination.get():
            self.s_sock.close()
            self.d_sock.close()
            self.logger.info('session with %s is getting terminated'%(str(self.s_addr)))
        t_dr.join()
        t_sr.join()
        t_dw.join()
        t_sw.join()
        self.logger.info('session with %s has been terminated'%(str(self.s_addr)))

    def in_range(self,time_range,lengths):
        for length in lengths:
            if (length >= time_range[0]) and (length <= time_range[1]):
                return True
        return False

    def contin2discrete(self, value):
        if value == 75:
            return "a"
        elif value == 113:
            return "b"
        elif value == 131:
            return "c"
        elif value == 138:
            return "d"
        elif value > 250 and value < 650:
            return "e"
        elif value > 5000:
            return "f"
        elif value == 121:
            return "g"
        elif value == 77:
            return "q"
        elif value == 33:
            return "w"
        else:
            return "x"



    def patternMatch(self, q):
        t1 = time.time()
        p = ''

        pattern = ["ececb", "ecbbb", "ecgec"]
        while not q.empty():
            p = p + self.contin2discrete(q.get())


        res = [ele in p for ele in pattern]

        if "q" in p or "w" in p:
            r = False
        r = True in res
        if "a" in p or "d" in p:
            r = True
        

        t2 = time.time()

        
        if r:
            return True
        else:
            return False



    def sessionFilter(self, lengths):
        global avs_pattern
        global avs_ip
        if self.checkSession == 0:
            for i in range(len(lengths)):
                self.pattern.append(lengths[i])
                if self.pattern == avs_pattern:
                    logger.info("IP address of avs server has been changed from %s to %s." % (avs_ip, self.s_addr[0]))
                    avs_ip = self.s_addr[0]
                    self.checkSession = 1
                    break


    def voicePatternRecog(self, msg, lengths):
        global avs_ip
        global verify_status

        if avs_ip == self.s_addr[0] and self.checkSession == 1 and verify_status == 1 and lengths[0] != 41:

            if self.delay_status == 0 or ((time.time() - self.lastPacketTime > 1) and (lengths[0] > 250)):
                self.delay_status = 0
                #self.packetQueue.put(msg)

                # check continues packets as pattern
                if (time.time() - self.lastPacketTime > 1):
                    self.lenQueue.queue.clear()
                    #self.delay_status = 1
                for ele in lengths:
                    if not self.lenQueue.full():
                        self.lenQueue.put(ele)
                    else:
                        break

                self.device_q.put(msg)
                self.lastPacketTime = time.time()
                #self.lastPacketLength = lengths[-1]
                if self.lenQueue.full():
                    res = self.patternMatch(self.lenQueue)
                    self.logger.info("match result: %s" % str(res))
                    self.lenQueue.queue.clear()
                    if res:
                        self.queryTime = time.time()
                        
                        # delay for 5 seconds
                        self.device_q.put(5)

                    #while not self.packetQueue.empty():
                    #    self.device_q.put(self.packetQueue.get())
                    self.delay_status = 1

            else:
                self.device_q.put(msg)
                self.lastPacketTime = time.time()
                #self.lastPacketLength = lengths[-1]
        else:
            self.device_q.put(msg)





    def analyze(self,msg):
        # self.logger.debug("%d btyes of data received from the %s with server at %s" %(len(msg),socket_type,session['s_addr']))
        global avs_ip
        global verify_status
        global avs_pattern
        records_sig = TLSType(msg)
        type_list = [x[0] for x in records_sig]
        if ('application_data' in type_list):
            lengths = [x[1] for x in records_sig]
            
            self.sessionFilter(lengths)
                
            #if avs_ip == self.s_addr[0]:
            logger.info("application TLS record of %s bytes to server at %s"%(str(lengths),self.s_addr))
            #logger.info("delay status is %d, avs ip is %s." % (self.delay_status, avs_ip))

            self.voicePatternRecog(msg, lengths)

        else:
            self.device_q.put(msg)

        



    def device_read(self):
        while True:
            try:
                msg_f_d = self.d_sock.recv(8192)
            except:
                self.termination.put(True)
                self.device_q.put('')
                break
            if len(msg_f_d) > 0:
                self.analyze(msg_f_d)
                #self.device_q.put(msg_f_d)
            else:
                self.termination.put(True)
                self.device_q.put('')
                break

        
    def device_write(self):
        while True:
            msg_t_d = self.server_q.get()
            if len(msg_t_d) > 0:
                try:
                    self.d_sock.send(msg_t_d)
                except:
                    self.termination.put(True)
                    break
            else:
                break

    def server_read(self):
        while True:
            try:
                msg_f_s = self.s_sock.recv(8192)
            except:
                self.termination.put(True)
                self.server_q.put('')
                break
            if len(msg_f_s):
                #self.analyze(msg_f_s)
                self.server_q.put(msg_f_s)
            else:
                self.termination.put(True)
                self.server_q.put('')
                break
        
    def server_write(self):
        global delay_status
        while True:
            msg_t_s = self.device_q.get()
            if type(msg_t_s) == int:
                self.logger.info("---------------delay starts for %s seconds---------------"%(str(msg_t_s)))

                time.sleep(msg_t_s)
                dlt_time = time.time() - self.queryTime
                self.logger.info("Query takes %s seconds." % str(dlt_time))

                with open("./rssi.txt", "r") as f:
                    rssi = f.read()
 
                if int(rssi) >= -6:
                    self.logger.info("rssi verification succeed. Value is %s. Foward voice command packets to the AVS server." % str(rssi))
                else:
                    self.logger.info("rssi verification failed. Value is %s. Discard voice command packets." % str(rssi))
                    with self.device_q.mutex:
                        self.device_q.queue.clear()

 
                self.logger.info("---------------delay ends for %s seconds---------------"%(str(msg_t_s)))
                continue

            if len(msg_t_s) > 0:
                try:
                    self.s_sock.send(msg_t_s)
                except:
                    self.termination.put(True)
                    break
            else:
                break


    def connect_server(self,s_addr):
        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s_sock.connect(s_addr)
            return s_sock
        except Exception as e:
            self.logger.error(e)
            return False



class keyboard_input(object):
    def __init__(self):
        thread = Thread(target=self.run, args=(), name="keyboard input")
        thread.start()

    def run(self):
        global verify_status
        input("press any key at any time to start rssi verification...\n")
        verify_status = 1



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Transparent proxy for TLS sessions')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-p', '--port',type=int, default=10000, metavar='P',help= 'port to listen')
    args = parser.parse_args()

    logger = logging.getLogger('logger')
    sh = logging.StreamHandler(stream=None)
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d | %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    verify_status = 0
    #delay_status = 1
    avs_ip = 'UNKNOWN'
    avs_pattern = [63,33,653,131,73,131,188,73,131,73,131,73,131,77,33,33]


    keyboard_input()


    if args.verbose: 
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
        listen_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listen_sock.bind(('0.0.0.0',args.port))
        listen_sock.listen()

        logger.info("start listening at port %d"%(args.port))
        while True:
            try:
                d_sock, d_addr = listen_sock.accept()
                session_thread = Session(d_addr,d_sock,logger)
                session_thread.start()
            except KeyboardInterrupt:
                listen_sock.close()
                del listen_sock
                sys.exit()
                

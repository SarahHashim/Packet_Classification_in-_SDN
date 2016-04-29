"""
A skeleton POX component

You can customize this to do whatever you like.  Don't forget to
adjust the Copyright above, and to delete the Apache license if you
don't want to release under Apache (but consider doing so!).

Rename this file to whatever you like, .e.g., mycomponent.py.  You can
then invoke it with "./pox.py mycomponent" if you leave it in the
ext/ directory.

Implement a launch() function (as shown below) which accepts commandline
arguments and starts off your component (e.g., by listening to events).

Edit this docstring and your launch function's docstring.  These will
show up when used with the help component ("./pox.py help --mycomponent").
"""
import BaseHTTPServer
import json
import threading

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
log = core.getLogger()

reservation_matrix=[]
avail_matrix=[]
qbw = [1,1,5,10] #q0 is the default queue for any unreserved traffic
#     q0    q1   q2   q3
#s1 DEFAULT FREE FREE FREE
#s2 DEFAULT FREE FREE FREE
#.
#.
#s6 DEFAULT FREE FREE FREE

#Modes
DUMB = "DUMB"
SMART = "SMART"

MODE = SMART #"SMART"

fixed_iplen = 29
switch_count = 6 
queue_count = 3
MAX_BANDWIDTH = 10
FREE = "free"
TEST = 1
dest = None
src = None
src0 = None
src00 = None
src10 = None

authlist = []
authdict = {}

table = {}

inTable = {}
all_ports = of.OFPP_FLOOD
stdip = "00001010000000000000000000000"

class DestTrie:
    def __init__(self,prefix,parent,rule, srctrie):
        self.left = None
        self.right = None
        self.prefix = prefix
	self.parent = parent
	self.rule = rule
	self.srctrie = srctrie
	

class SrcTrie:
    def __init__(self,prefix,parent,rule,switchl,switchr):
        self.left = None
        self.right = None
        self.prefix = prefix
	self.parent = parent
	self.rule = rule
	self.switchl = switchl
	self.switchr = switchr

def _handle_ConnectionUp(event):
    pass

def getSrcIPandARP (packet):
    #Gets source IPv4 address for packets that have one (IPv4 and ARP)
    #Returns (ip_address, has_arp).  If no IP, returns (None, False).
    if isinstance(packet, ipv4):
        log.debug("IP %s => %s",str(packet.srcip),str(packet.dstip))
        print("IPv4:src"+str(packet.srcip)+",dstn:"+str(packet.dstip))
        return ( packet.srcip, packet.dstip, False )
    elif isinstance(packet, arp):
        log.debug("ARP %s %s => %s",
                {arp.REQUEST:"request",arp.REPLY:"reply"}.get(packet.opcode,
                    'op:%i' % (packet.opcode,)),
               str(packet.protosrc), str(packet.protodst))
        #print("ARP:src"+str(packet.protosrc)+",dstn:"+str(packet.protodst))
        if (packet.hwtype == arp.HW_TYPE_ETHERNET and
          packet.prototype == arp.PROTO_TYPE_IP and
          packet.protosrc != 0):
            return ( packet.protosrc, packet.protodst, True )
    return ( None, None, False )


def _handle_PacketIn (event):
    global s1_dpid, s2_dpid
    #print("payload:"+str(dir(event.parsed.payload)))
    #print("event.con:"+str(event.connection))
    #print("hwdst:"+str(event.parsed.payload.hwdst))
    switch_id = event.connection.dpid
    print "switch_id:"
    print switch_id
    packet = event.parsed
    (pckt_srcip, pckt_dstip, hasARP) = getSrcIPandARP(packet.next)
    print ("src ip") 
    #print int(pckt_srcip)
    print ("dst ip") 
    print pckt_dstip

    if pckt_srcip is None:
        pckt_srcip = "10.0.0.0"
        #print("Pckt_srcip:"+str(pckt_srcip))
        #self.updateIPInfo(pckt_srcip,macEntry,hasARP)
        print("pckt_srcip is NONE and is set to 10.0.0.0!")



    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        event.connection.send(msg)


    table[(event.connection,packet.src)] = event.port

    dst_port = table.get((event.connection,packet.dst))
    
    #print('came into handle_packetin')
    if dst_port is None:
        # We don't know where the destination is yet.  So, we'll just
        # send the packet out all ports (except the one it came in on!)
        # and hope the destination is out there somewhere. :)
        msg = of.ofp_packet_out(data = event.ofp)
        msg.actions.append(of.ofp_action_output(port = all_ports))
        event.connection.send(msg)
    else:
        # Since we know the switch ports for both the source and dest
        # MACs, we can install rules for both directions.
	count = 0
	for item in authlist:
		if item["src_ip"] == str(packet.src) and item["dest_ip"] == str(packet.dst):
			count = count + 1


	ipv4_packet = event.parsed.find("ipv4")
        if ipv4_packet is None:
            print("ipv4 none")
        

	find_rule(str(pckt_srcip),str(pckt_dstip))
	print "source ip"
	#print str(packet.src)
	print ip.toUnsignedN()	
	print "dest ip"
	print str(packet.dst)
	if count == 0:
		print "drop"
		drop()
	else:
		print "match"		
		msg = of.ofp_flow_mod()
		msg.match.dl_dst = packet.src
		msg.match.dl_src = packet.dst
		msg.actions.append(of.ofp_action_output(port = event.port))
		event.connection.send(msg)
		# This is the packet that just came in -- we want to
		# install the rule and also resend the packet.
		msg = of.ofp_flow_mod()
		msg.data = event.ofp # Forward the incoming packet
		msg.match.dl_src = packet.src
		msg.match.dl_dst = packet.dst
		#msg.actions.append(of.ofp_action_output(port = dst_port))
		#ipv4_packet = event.parsed.find("ipv4")
		#if ipv4_packet is None:
		#    print("ipv4 none")
		#ipv4_src_ip = ipv4_packet.srcip
		#print("ipv4 src ip :"+str(ipv4_src_ip))
		msg.actions.append(of.ofp_action_output(port = dst_port))

		#print("Msg sent to Switch "+str(event.connection.dpid)+": Port"+str(dst_port)+", Queue"+str(getQidFromMatrix(str(pckt_srcip),switch_id-1)))
		#print("srcip:"+str(packet.src))
		event.connection.send(msg)
		log.debug("Installing %s <-> %s" % (packet.src, packet.dst))
    pass

def add_Auth(src_ip,dst_ip,message):
    info = {
	"src_ip": src_ip,
	"dest_ip":dst_ip,
	"message":message
    }
    authlist.append(info)
    return True

def remove_Auth(src_ip,dst_ip,message):
    info = {
	"src_ip": src_ip,
	"dest_ip":dst_ip,
	"message":message
    }
    for item in authlist:
	if cmp(info,item) == 0:
		authlist.remove(info)
		return True
    return False


def find_rule(src_ip, dst_ip):
    dstformat = dst_ip
    desttrie = dest
    validdtrie = desttrie
    while(len(desttrie) < 32 && (desttrie.left != None || desttrie.right != None)):
	if (desttrie.left != None && dstformat[:len(desttrie.left.prefix)] == desttrie.left.prefix):
		desttrie = desttrie.left
	elif (desttrie.right!= None && dstformat[:len(desttrie.right.prefix)] == desttrie.right.prefix):
		desttrie = desttrie.right
	if(desttrie.rule != False):
		validtrie = desttrie
    find_srcmatch(validtrie.srctrie, src_ip)
    return

def find_srcmatch(srctrie, src_ip):
    


'''

def new_Connection(src_ip, dstn_ip, bandwidth):
    if MODE==DUMB:
        pathPresent = True
        print("in new connection")
        if bandwidth<=MAX_BANDWIDTH:
            minQIndex = getCorrectQueue(bandwidth) #gives queue number . index 0 - 1 mbps, 1 - 5mbps, 2 - 10mbps
            qIds = []
            if minQIndex == -1:
                pathPresent = False
            else:
                for i in range(0,switch_count):
                    if reservation_matrix[i][minQIndex] == FREE:
                        reservation_matrix[i][minQIndex] = src_ip
                    else:
                        reservation_matrix[i][minQIndex] = reservation_matrix[i][minQIndex] + "," + src_ip
                #should not assign to all switch queus. but rather only to the switches involved in the connection
                for i in range(0,switch_count):
                    avail_matrix[i][minQIndex] -= bandwidth
        else:
            pathPresent = False
        print("new conn:")
        printResMatrix()
        return pathPresent
    elif MODE==SMART:
        pathPresent = True
        print("in new connection, with src_ip: " + src_ip)
        if bandwidth<=MAX_BANDWIDTH:
            qIds = []
            questr = getCorrectQueue(bandwidth,src_ip)
            if questr == "FALSE" or questr == "":
                pathPresent = False
            else:
                questrlist = questr.split(",")
                qIndex = [0 for x in range(len(questrlist))]
                print questrlist
                i=0
                for q in questrlist:
                    qIndex[i] = int(q)
                    i +=1
                #check for starting and ending indices, assuming unidrectional
                for i in range(switch_count):
                    if src_ip == "10.0.0." + str(i+1):
                        source =i
                    if dstn_ip == "10.0.0." + str(i+1):
                        destination = i
                        break
                for i in range(source, destination+1):
                    if reservation_matrix[i][qIndex[i]]== FREE:
                        reservation_matrix[i][qIndex[i]] = src_ip
                    else:
                        reservation_matrix[i][qIndex[i]] = reservation_matrix[i][qIndex[i]] + "," + src_ip
                for i in range(source, destination+1):
                    avail_matrix[i][qIndex[i]] -= bandwidth
        else:
            pathPresent = False
        print("new conn:")
        printResMatrix()
        return pathPresent
    pass

def printResMatrix():
    print("reservation matrix is")
    for i in range(switch_count):
        print("s"+str(i)+": "+reservation_matrix[i][0]+";"+reservation_matrix[i][1]+";"+reservation_matrix[i][2]+";"+reservation_matrix[i][3])

def getCorrectQueue(bandwidth,src_ip=None):
    if MODE==DUMB:
        que = getMinQueue(bandwidth)
        val = 1
        for i in range(switch_count):
            if avail_matrix[i][que] < bandwidth:
                val = 0
                break
        if val == 1:
            return que
        else:
            return -1
    elif MODE == SMART:
        que = getMinQueue(bandwidth, src_ip)
        print "start with queue: " + str(que)
        if que == -1:
            return "FALSE"
        val = 1
        questr = ""
        for i in range(switch_count):
            if avail_matrix[i][que] >= bandwidth:
                if questr == "":
                    questr = str(que)
                else:
                    questr = questr + " , " + str(que)
            elif avail_matrix[i][nextQueueNumber(que,1)] >= bandwidth:
                if questr == "":
                    questr = str(nextQueueNumber(que,1))
                else:
                    questr = questr + " , " + str(nextQueueNumber(que,1))
                que = nextQueueNumber(que,1)
            elif avail_matrix[i][nextQueueNumber(que,2)] >= bandwidth:
                if questr == "":
                    questr = str(nextQueueNumber(que,2))
                else:
                    questr = questr + " , " + str(nextQueueNumber(que,2))
                que = nextQueueNumber(que,1)
            else:
                val = 0
                break
        if val == 1:
            return questr
        else:
            return "FALSE"
    pass

def nextQueueNumber(que,n):
    que = (que+n)%queue_count+1
    return que+1


def getMinQueue(bandwidth, src_ip=None):
    if MODE==DUMB:
        if bandwidth <=1:
            return 1
        elif bandwidth<=5:
            return 2
        elif bandwidth<=10:
            return 3
    elif MODE==SMART:
        for i in range(switch_count):
        #check which queue to start with for that particular switch
            if src_ip == ("10.0.0."+str(i+1)):
                for j in range(1,queue_count+1):
                    print avail_matrix[i][j]
                    if avail_matrix[i][j] >= bandwidth:
                        return j
        return -1
    pass

def getQidFromMatrix(srcip,switch_id):
    qid = 0
    #print("checking Qid for srcip :"+str(srcip))
    for i in range(1,queue_count+1):
        #print("Res matrix entry chekcing:"+str(reservation_matrix[0][i]))
        if srcip in reservation_matrix[switch_id][i]:
            qid = i
    #print("get qid from matrix returns "+str(qid)+" for "+srcip)
    return qid


'''
def launch ():

    print "starting the reservation http service inside launch method"
    reservationService = ReservationServiceThread()
    reservationService.setDaemon(True)
    reservationService.start()

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    #root = SrcTrie(prefix,parent,rule,switchl,switchr)
    '''
    src = SrcTrie("", None, None, None, None)
    src.left = SrcTrie("0", src, None, None, None)
    src.left.left = SrcTrie("00", src.left, "R7", None, None)

    src0 = SrcTrie("", None, None, None, None)
    src0.right = SrcTrie("1",src0, "R3", None, None)
    src0.left = SrcTrie("0", src0, None, src.left.left, None)
    src0.right.left = SrcTrie("10", src0.right, "R1", None, None)
    src0.left.right = SrcTrie("01", src0.left, "R2", None, None)

    src00 = SrcTrie("", None, None, src0.left, None)
    src00.right = SrcTrie("1", src00, "R4", src0.right.left, None)
    src00.right.right = SrcTrie("11", src00.right, "R5", None, None)

    src10 = SrcTrie("", None, None, src.left, None)
    src10.right = SrcTrie("1", src10, "R6", None, None)
    

    #root = DestTrie(prefix,parent,rule, srctrie)
    dest = DestTrie("", None, True, src)
    dest.left = DestTrie("0", dest, True, src0)
    dest.left.left = DestTrie("00", dest.left, True, src00)
    dest.right = DestTrie("1", dest, False, None)
    dest.right.left = DestTrie("10", dest.right, True, src10)'''

    
def construct_trie():
    global src, src0, src00, src10, dest
    src = SrcTrie("", None, None, None, None)
    src.left = SrcTrie("0", src, None, None, None)
    src.left.left = SrcTrie("00", src.left, "R7", None, None)

    src0 = SrcTrie("", None, None, None, None)
    src0.right = SrcTrie("1",src0, "R3", None, None)
    src0.left = SrcTrie("0", src0, None, src.left.left, None)
    src0.right.left = SrcTrie("10", src0.right, "R1", None, None)
    src0.left.right = SrcTrie("01", src0.left, "R2", None, None)

    src00 = SrcTrie("", None, None, src0.left, None)
    src00.right = SrcTrie("1", src00, "R4", src0.right.left, None)
    src00.right.right = SrcTrie("11", src00.right, "R5", None, None)

    src10 = SrcTrie("", None, None, src.left, None)
    src10.right = SrcTrie("1", src10, "R6", None, None)

    dest = DestTrie("", None, True, src)
    dest.left = DestTrie("0", dest, True, src0)
    dest.left.left = DestTrie("00", dest.left, True, src00)
    dest.right = DestTrie("1", dest, False, None)
    dest.right.left = DestTrie("10", dest.right, True, src10)
    print "trie built"
    print dest.left.srctrie.right.rule

#curl -H "Content-Type: application/json" -X POST -d '{"bandwidth":5}' http://localhost:6060
class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    # Handler for the GET request
    def do_POST(self):



        src_ip = None
        dst_ip = None
        message = None
	option = None
	
        response={}
        try:
            #get the body of POST request
            post_body = self.rfile.read(int(self.headers['Content-Length'])).decode("UTF-8")
            request = json.loads(post_body);
            src_ip = request.get('source_ip')
            dst_ip = request.get('dest_ip')
            message = request.get('message')
	    option = request.get('option')

	    
        except Exception:
            print "internal server error happened"
            return



        if (src_ip is None) | (dst_ip is None) | (message is None) | (option is None):
            #we give an eror response back
            print 'src_ip, dst_ip, message, option cannot be null'
            response['reservation'] = 'BAD_REQUEST'
            json_str = json.dumps(response)

            content = bytes(json_str)
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
            return
	construct_trie()
	if option == 'RESERVE':
		bool_value = add_Auth(src_ip,dst_ip,message)
	elif opt == 'REMOVE':
		bool_value = remove_Auth(src_ip,dst_ip,message)
	else:
		response['result'] = 'FAILED'
        if(bool_value):
             response['result'] = 'OK'

        else:
             response['result'] = 'FAILED'


        json_str = json.dumps(response)
        content = bytes(json_str)
        self.send_response(200)
        self.send_header("Content-type","application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)
	print dest.left.srctrie.right.rule
        return


"""
The class is responsible for hosting the reservation
service for clients.
"""


class ReservationServiceThread(threading.Thread):
    SERVER_PORT = 6060

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ReservationServiceThread, self).__init__(group, target, name, args, kwargs, verbose)

    def run(self):
        print "starting reservation service. Listening on port %s",self.SERVER_PORT
        httpd = BaseHTTPServer.HTTPServer(("", self.SERVER_PORT), MyHandler)
        httpd.serve_forever();

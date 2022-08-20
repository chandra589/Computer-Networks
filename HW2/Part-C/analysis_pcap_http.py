import dpkt
import math

class Packet:
    
    def __init__(self, packet):
        self.ts = packet[0]
        self.buff = packet[1]
    
    def parsebuffer(self):
        self.srcip = str(int.from_bytes(self.buff[26:27], 'big')) + "." +  str(int.from_bytes(self.buff[27:28], 'big')) + \
            "." + str(int.from_bytes(self.buff[28:29], 'big')) + "." + str(int.from_bytes(self.buff[29:30], 'big'))
        self.destip = str(int.from_bytes(self.buff[30:31], 'big')) + "." +  str(int.from_bytes(self.buff[31:32], 'big')) + \
            "." + str(int.from_bytes(self.buff[32:33], 'big')) + "." + str(int.from_bytes(self.buff[33:34], 'big'))
        self.sourceport = int.from_bytes(self.buff[34:36], 'big')
        self.destport = int.from_bytes(self.buff[36:38], 'big')
        self.sequencenum = int.from_bytes(self.buff[38:42], 'big')
        self.acknum = int.from_bytes(self.buff[42:46], 'big')
        self.hl = int((int.from_bytes(self.buff[46:47], 'big'))/4)
        flags = int.from_bytes(self.buff[47:48], 'big')
        self.fin = flags & 1
        self.syn = (flags & (1 << 1)) >> 1
        self.rst = (flags & (1 << 2)) >> 2
        self.push = (flags & (1 << 3)) >> 3
        self.ack = (flags & (1 << 4)) >> 4
        self.urg = (flags & (1 << 5)) >> 5
        self.receivewindow = int.from_bytes(self.buff[48:50], 'big')
        self.payload = self.buff[34+self.hl:]
        self.payloadsize = len(self.buff[34+self.hl:])

class TCP_Connection:

    def __init__(self):
        self.packets = []
        self.destport = -1
        self.sourceport = -1

    def ReassembleHTTP(self):
        #find get packets in flow, ideally there should be only one
        getpktinflow = ''
        for packet in self.packets:
            if (str(packet.payload).find('GET') != -1):
                getpktinflow = packet
        
        print("Request: " + str(getpktinflow.payload[0:70]))
        print("Request Tuple: " + str(getpktinflow.sourceport) + "," + str(getpktinflow.destport) + "," + str(getpktinflow.sequencenum) + "," +str(getpktinflow.acknum))

        sequencepktsmap = {}
        for packet in self.packets:
            sequencepktsmap[packet.sequencenum] = packet

        responsepkts = []
        pkttoadd = sequencepktsmap[getpktinflow.acknum]
        while pkttoadd:
            responsepkts.append(pkttoadd)
            nextseqval = pkttoadd.sequencenum + pkttoadd.payloadsize
            pkttoadd = sequencepktsmap.get(nextseqval)
            if (pkttoadd.fin == 1):
                break
        print("Response Tuples: ")
        for pkt in responsepkts:
            print(str(pkt.sourceport) + "," + str(pkt.destport) + "," + str(pkt.sequencenum) + "," +str(pkt.acknum))
       

def ComputeAllTCPConnections(packets):
    Flows = []
    for packet in parsed_packets:
        destport = packet.destport
        srcport = packet.sourceport
        PresentinFlows = False
        for flow in Flows:
            if (((flow.destport == destport) or (flow.destport == srcport))
             and ((flow.sourceport == srcport) or (flow.sourceport == destport))):
                flow.packets.append(packet)
                PresentinFlows = True
        if (not PresentinFlows):
            newflow = TCP_Connection()
            newflow.destport = destport
            newflow.sourceport = srcport
            newflow.packets.append(packet)
            Flows.append(newflow)
    return Flows

def ComputeProtocolParameters(Flows):
    total_size = 0
    total_pkts = 0
    start_timestamp = Flows[0].packets[0].ts
    end_timestamp = Flows[0].packets[0].ts
    for flow in Flows:
        for pkt in flow.packets:
            if (pkt.ts > end_timestamp):
                end_timestamp = pkt.ts
            if (pkt.ts < start_timestamp):
                start_timestamp = pkt.ts
            if (pkt.sourceport == flow.sourceport):
                continue
            total_pkts+=1
            total_size+=pkt.payloadsize
    
    print("load time: " + str(end_timestamp - start_timestamp))
    print("Total Packets: " + str(total_pkts))
    print("Total Bytes: " + str(total_size))


if __name__ == '__main__':

    fileone = open('http_1080.pcap', 'rb')
    pcap = dpkt.pcap.Reader(fileone)
    packets_binary = pcap.readpkts()
    parsed_packets = []
    for packet_b in packets_binary:
        packet = Packet(packet_b)
        packet.parsebuffer()
        parsed_packets.append(packet)

    #have to segregate packets for each flow
    Flows_1080 = ComputeAllTCPConnections(parsed_packets)

    for flow in Flows_1080:
        flow.ReassembleHTTP()

    filetwo = open('tcp_1081.pcap', 'rb')
    pcap = dpkt.pcap.Reader(filetwo)
    packets_binary_two = pcap.readpkts() 
    parsed_packets = []
    for packet_b in packets_binary_two:
        packet = Packet(packet_b)
        packet.parsebuffer()
        parsed_packets.append(packet)
    
    Flows_1081 = ComputeAllTCPConnections(parsed_packets)
    print ("Number of Flows: " + str(len(Flows_1081)))
    if (len(Flows_1081) > 1):
        print("tcp_1081.pcap" + "--This Connection is HTTP 1.1")

    filethree = open('tcp_1082.pcap', 'rb')
    pcap = dpkt.pcap.Reader(filethree)
    packets_binary_three = pcap.readpkts()
    parsed_packets = []
    for packet_b in packets_binary_three:
        packet = Packet(packet_b)
        packet.parsebuffer()
        parsed_packets.append(packet)
    
    Flows_1082 = ComputeAllTCPConnections(parsed_packets)
    print("Number of Flows: " + str(len(Flows_1082)))
    if (len(Flows_1082) == 1):
        print("tcp_1082.pacp" + "--This Connection is HTTP 2.0")

    print("Under HTTP 1.0")
    ComputeProtocolParameters(Flows_1080)
    print("Under HTTP 1.1")
    ComputeProtocolParameters(Flows_1081)
    print("Under HTTP 2.0")
    ComputeProtocolParameters(Flows_1082)



    
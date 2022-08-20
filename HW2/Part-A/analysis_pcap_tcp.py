from itertools import islice
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
        self.payload = len(self.buff[34+self.hl:])

class TCP_Connection:

    def __init__(self):
        self.packets = []
        self.destport = -1
        self.sourceport = -1
        self.throughput = -1
        self.lossrate = -1
        self.rttest = -1
        self.MSS = -1
        self.receivewindowscale = -1
    
    def Confirm3WHSandGetFirstTransactionIndex(self):
        FirstsynVerified = False
        SecondsynackVerified = False
        ThirdackVerified = False
        for packet in self.packets[:3]:
            if (packet.syn == 1 and packet.ack == 0):
                 FirstsynVerified = True
                 self.MSS = int.from_bytes(packet.buff[56:58], 'big')
                 #https://ccie11440.blogspot.com/2009/08/tcp-window-scale-option.html
                 scalefactor = int.from_bytes(packet.buff[73:74], 'big')
                 self.receivewindowscale = 1 << scalefactor
            elif (packet.syn == 1 and packet.ack == 1):
                SecondsynackVerified = True
            elif (packet.syn == 0 and packet.ack == 1):
                ThirdackVerified = True
        
        if (FirstsynVerified and SecondsynackVerified and ThirdackVerified):
            return True, 3
        else:
            return False, 0

    def printfirsttwotransactions(self, index):
        senderone = self.packets[index]
        sendertwo = self.packets[index+1]
        senderone_ack_expected = senderone.sequencenum + senderone.payload
        sendertwo_ack_expected = sendertwo.sequencenum + sendertwo.payload
        receiverone = ''
        receivertwo = ''
        for packet in self.packets:
            if (packet.acknum == senderone_ack_expected):
                receiverone = packet
                break
        for packet in self.packets:
            if (packet.acknum == sendertwo_ack_expected):
                receivertwo = packet
                break
        
        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("First Transaction after Handshake")
        print(" " + "Sender Sequence number: " + str(senderone.sequencenum))
        print(" " + "Sender Acknowledgment number: " + str(senderone.acknum))
        print(" " + "Sender Receive window size: " + str(senderone.receivewindow)+"*"+str(self.receivewindowscale))
        print(" " + "Receiver Sequence number: " + str(receiverone.sequencenum))
        print(" " + "Receiver Acknowledgment number: " + str(receiverone.acknum))
        print(" " + "Receiver Receive window size: " + str(receiverone.receivewindow)+"*"+str(self.receivewindowscale))

        print("Second Transaction after Handshake")
        print(" " + "Sender Sequence number: " + str(sendertwo.sequencenum))
        print(" " + "Sender Acknowledgment number: " + str(sendertwo.acknum))
        print(" " + "Sender Receive window size: " + str(sendertwo.receivewindow)+"*"+str(self.receivewindowscale))
        print(" " + "Receiver Sequence number: " + str(receivertwo.sequencenum))
        print(" " + "Receiver Acknowledgment number: " + str(receivertwo.acknum))
        print(" " + "Receiver Receive window size: " + str(receivertwo.receivewindow)+"*"+str(self.receivewindowscale))

    def ComputeThroughput(self):
        data_bytes = 0
        for packet in self.packets:
            if (packet.srcip == "130.245.145.12"):
                data_bytes = data_bytes + len(packet.buff)
        TimebtwLastandFirstpkt = self.packets[-1].ts - self.packets[0].ts
        self.throughput = (data_bytes*8)/(TimebtwLastandFirstpkt*pow(10,6))
        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("Throughput = " + str(self.throughput))

    def ComputeLossrate(self):
        sequenceDB = {}
        payload_zeropkts = 0
        for packet in self.packets:
            if (packet.srcip != "130.245.145.12"):
                continue
            if (packet.payload == 0):
                payload_zeropkts+=1
                continue
            sequenceDB[packet.sequencenum] = sequenceDB.get(packet.sequencenum, 0) + 1
        
        totalpkts_sent = 0
        for counter in sequenceDB.values():
            totalpkts_sent += counter
        
        retransmit_count = totalpkts_sent - len(sequenceDB)

        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("packets sent: " + str(totalpkts_sent + payload_zeropkts))
        print("packets lost: " + str(retransmit_count))
        self.lossrate = retransmit_count/(totalpkts_sent+payload_zeropkts)
        print("Loss Rate: " + str(self.lossrate))

    def compute_RTTestimate(self):
        #we have to remove retransmit pkts first
        #seq, pkt -> dict 
        sourcesent_pktsdic = {}
        source_retransmitpktsdic = {}
        receiversent_pktsdic = {}
        for packet in self.packets:
            if (packet.sourceport == self.sourceport):
                if (sourcesent_pktsdic.get(packet.sequencenum)):
                    source_retransmitpktsdic[packet.sequencenum] = packet
                else:
                    sourcesent_pktsdic[packet.sequencenum] = packet
            else:
                receiversent_pktsdic[packet.acknum] = packet
        
        #remove retransmit packets
        for key in source_retransmitpktsdic.keys():
            del sourcesent_pktsdic[key]

        total_transactions = 0
        total_time = 0
        for seqnum in sourcesent_pktsdic.keys():
            sentpkt = sourcesent_pktsdic[seqnum]
            nextseq_num = seqnum + sentpkt.payload
            if (nextseq_num) in receiversent_pktsdic:
                receivept = receiversent_pktsdic[nextseq_num]
                total_time += receivept.ts - sentpkt.ts
                total_transactions += 1
        

        RTT = total_time/total_transactions
        self.rttest = RTT

        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("Average RTT: " + str(RTT))
        try:
            Throughput_theoretical = (math.sqrt(3/2)*self.MSS*8)/(self.rttest*math.sqrt(self.lossrate)*pow(10, 6))
            print("Theoretical Throughput: " + str(Throughput_theoretical))
        except ZeroDivisionError as error:
            print("Theoretical Throughput is Infinite as loss rate is zero")

    def ComputeCongestionWindows(self):
        #count the number of packets sent from sender to receiver in each RTT
        start = self.packets[0].ts
        pktsineachRTT = {}
        for packet in self.packets:
            td = packet.ts - start
            index = (int)(td/self.rttest)
            numofpkts = pktsineachRTT.get(index, 0)
            pktsineachRTT[index] = numofpkts + 1

        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("First 10 Congestion window sizes of the flow")
        for key, count in islice(pktsineachRTT.items(), 10):
            print(str(key+1) + "  " + str(count*self.MSS))
    
    def computeRetrasmitduetoTDAs(self):
        sourcesent_pktsdic = {}
        source_retransmitpktsdic = {}
        receiversent_pktsdic = {}
        for packet in self.packets:
            if (self.sourceport == packet.sourceport):
                pktsforseq = sourcesent_pktsdic.get(packet.sequencenum)
                if pktsforseq:
                    pktsforseq.append(packet)
                else:
                    sourcesent_pktsdic[packet.sequencenum] = [packet]
            else:
                pkstforack = receiversent_pktsdic.get(packet.acknum)
                if pkstforack:
                    pkstforack.append(packet)
                else:
                    receiversent_pktsdic[packet.acknum] = [packet]
        
        for seq in sourcesent_pktsdic.keys():
            if (len(sourcesent_pktsdic[seq]) > 1):
                source_retransmitpktsdic[seq] = sourcesent_pktsdic[seq]

        TripleDuplicateAcksCounter = 0
        for seq, seqpkts in source_retransmitpktsdic.items():
            for index in range(len(seqpkts) - 1):
                pkt_beforets = seqpkts[index].ts
                pkt_afterts = seqpkts[index+1].ts
                acks_pktslist = receiversent_pktsdic[seq]
                counter = 0
                for packet in acks_pktslist:
                    if (pkt_afterts > packet.ts and packet.ts > pkt_beforets):
                        counter+=1
                        if (counter >= 3):
                            TripleDuplicateAcksCounter+=1
                            break
        
        RetransmitsduetoTimeout = len(source_retransmitpktsdic) - TripleDuplicateAcksCounter - 1  #Sequence num is same in the handshake, so have to del 1
        print("Flow btw ports " + str(self.sourceport) + " and " + str(self.destport))
        print("Retransmits due to Triple Duplicate ACKs: " + str(TripleDuplicateAcksCounter))
        print("Retransmits due to Timeouts: " + str(RetransmitsduetoTimeout))  

if __name__ == '__main__':
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    packets_binary = pcap.readpkts()
    parsed_packets = []
    for packet_b in packets_binary:
        packet = Packet(packet_b)
        packet.parsebuffer()
        parsed_packets.append(packet)

    #have to segregate packets for each flow
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

    #Number of TCP Connections
    print("The Number of TCP connections established: " + str(len(Flows)))

    #Part-A - a, In each flow get the first two transactions after handshake
    for flow in Flows:
        VerifyHandshake, index = flow.Confirm3WHSandGetFirstTransactionIndex()
        if (VerifyHandshake):
            flow.printfirsttwotransactions(index)

    #Part-A - b, Compute Throughtput for each flow
    for flow in Flows:
        flow.ComputeThroughput()

    #Part-A - c, Compute loss rate for each flow
    for flow in Flows:
        flow.ComputeLossrate()

    #Part-A - d, Compute average RTT
    for flow in Flows:
        flow.compute_RTTestimate()

    #part-B - a, Compute first 10 congestion windows
    for flow in Flows:
        flow.ComputeCongestionWindows()

    #Part-B - b, Compute retransmission due to triple duplicate ACKs
    for flow in Flows:
        flow.computeRetrasmitduetoTDAs()



    
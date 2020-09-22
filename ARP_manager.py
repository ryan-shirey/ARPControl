                                                                                                                                   


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from ryu.ofproto import inet
balanceNum=1
class my_app(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(my_app, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        #add_flow takes a match, and action then adds it to the OF table                                                                                                                             
        #this function is mainly sourced from the simple_switch_13.py                                                                                                                                
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


        #Packet in handler                                                                                                                                                                               
        #this function takes in packets, if it is an arp request for the virtual address of "10.0.0.10" it will pass to a seperate function below                                                    
        #the function it is passing to is receiveBadArp                                                                                                                                              
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        #disects the event and message into useable variables                                                                                                                                        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        #creates a mac to port table to avoid flooding                                                                                                                                               
        #used later on                                                                                                                                                                               
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        #This interprets a packet and if it is an Arp request it will check for the destination                                                                                                      
        if(eth.ethertype == ether_types.ETH_TYPE_ARP):
            arpPKT = pkt.get_protocol(arp)
            arpDstIp = arpPKT.dst_ip
            #if the destination is the virtual ip then the code diverts to special handling                                                                                                          
            if arpDstIp == "10.0.0.10":
                self.receiveBadArp(datapath, pkt, eth, in_port, msg)
                return

        #looks for the port number used for a specific mac address                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        #if it isn't there then a flood must happen                                                                                                                                                  
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time                                                                                                                                                
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        #builds the outgoing message                                                                                                                                                                 
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        #sends the outgoing message                                                                                                                                                                  
        datapath.send_msg(out)

    #ReceiveBadArp takes in packet info then builds an arp reply to send to the original client                                                                                                      
    def receiveBadArp(self, datapath, packet, etherFrame, inPort, msg):
        #get a packet with data on the type of arp packet                                                                                                                                            
        arpPacket = packet.get_protocol(arp)

        #if this is a request then opcode is 1 so we must do something                                                                                                                               
        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            #double checks the arp destination is '10.0.0.10'                                                                                                                                        
            if arp_dstIp == '10.0.0.10':
                #calls function to build and send message                                                                                                                                            
                self.replyArp(datapath, etherFrame, arpPacket, arp_dstIp, inPort, msg, packet)
        else:
            self.logger.info("2")
    def replyArp(self, datapath, etherFrame, arpPacket, arpdstIp, inPort, msg, OrigPacket):
        #this variable iterates so that the load is balanced                                                                                                                                         
        global balanceNum

        #destination and source ip of packet will be reversed of what was received                                                                                                                   
        destIp = arpPacket.src_ip
        sourcIp = arpPacket.dst_ip
        destMac = etherFrame.src

        #assigns port,mac, and Ip for sending out in an alternating fashion                                                                                                                          
        if(balanceNum%2==1):
            endPort = 5
            srcMac = "00:00:00:00:00:05"
            newIP = "10.0.0.5"
        else:
            endPort = 6
            srcMac = "00:00:00:00:00:06"
            newIP = "10.0.0.6"

        #iterate counter                                                                                                                                                                             
        balanceNum = balanceNum+1

        parser = datapath.ofproto_parser
#add flow tables                                                                                                                                                                             
        #client to server flow                                                                                                                                                                       
        actions = [parser.OFPActionSetField(ipv4_dst=newIP),parser.OFPActionOutput(endPort)]
        match = parser.OFPMatch(in_port=inPort,ipv4_dst="10.0.0.10")
        self.add_flow(datapath, 1, match, actions)
        #server to client flow                                                                                                                                                                       
        actions = [parser.OFPActionSetField(ipv4_src="10.0.0.10"),parser.OFPActionOutput(inPort)]
        match = parser.OFPMatch(in_port=endPort,ipv4_src=newIP,ipv4_dst=destIp)
        self.add_flow(datapath, 1, match, actions)
        #build arp request                                                                                                                                                                            
        #https://ryu.readthedocs.io/en/latest/library_packet.html                                                                                                                                    
        e = ethernet.ethernet(destMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1,0x0800,6,4, 2, srcMac, sourcIp, destMac, destIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [parser.OFPActionOutput(inPort)]
        #build message                                                                                                                                                                               
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=endPort,actions=actions,data=p)
        datapath.send_msg(out)

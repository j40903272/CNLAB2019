# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

import time
import numpy as np
from detect import basic_detector, connection_detector, dst_detector, entropy_detector, packetIn_detector
from mitigation import limit_connection



class MSG():
    def __init__(self, flowstats):
        #self.datapath = Datapath(dpid)
        self.body = []
        for cookie in flowstats:
            dst, src, in_port, dpid = cookie
            bcnt = flowstats[cookie]["byte_count"]
            pcnt = flowstats[cookie]["packet_count"]
            self.body.append(Stat(cookie, bcnt, pcnt, dst, in_port, dpid))

class Datapath():
    def __init__(self, id):
        self.id = id

class Stat():
    def __init__(self, cookie, byte_cnt, packet_cnt, eth_dst, in_port, dpid):
        self.priority = 1
        self.cookie = cookie
        self.byte_count = byte_cnt
        self.packet_count = packet_cnt
        self.match = {"eth_dst":eth_dst, "in_port":in_port, "dpid":dpid}

class DDosMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(DDosMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flowstats = {}
        self.packetIn = {}
        
        #### add detection ###
        self.detector = basic_detector()
        self.detector2 = dst_detector()
        self.detector3 = entropy_detector()
        self.detector4 = connection_detector()
        self.detector5 = packetIn_detector()
        ####


    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        cookie = (dst, src, in_port, dpid)
        if dst in self.packetIn:
            self.packetIn[dst] += 1
        else:
            self.packetIn[dst] = 1
        if src in self.packetIn:
            self.packetIn[src] += 1
        else:
            self.packetIn[src] = 1

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_port[dpid][dst] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    


    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        msg = ev.msg
        dpid = msg.datapath.id

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

            stat.cookie = (stat.match['eth_dst'], stat.match['eth_src'], stat.match['in_port'], dpid)
        
        

        sort_list = sorted([flow for flow in msg.body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst']))
        self.detector.detect(sort_list)
        self.detector2.detect(sort_list)
        self.detector3.detect(msg)
        self.detector4.detect(sort_list)
        self.detector5.detect(self.packetIn)



        f3 = self.detector3.detected_flags

        for stats in sort_list:
            in_port = stats.match['in_port']
            out_port = stats.instructions[0].actions[0].port
            dst = stats.match["eth_dst"]
            src = stats.match["eth_src"]

            f1 = self.detector.detected_flags[stats.cookie]
            f2 = self.detector2.detected_flags[dst]
            #f3 = self.detector3.detected_flags[stats.cookie]
            f4 = self.detector4.detected_flags[dst]
            f5 = self.detector5.detected_flags[dst] or self.detector5.detected_flags[src]

            #print(stats.cookie, f1, f2, f3, f4, f5)
            if f1 + f2 + f3 + f4 + f5 >= 2:

                ### logging ###
                self.logger.info("\n==========================================================")
                self.logger.info("DDos detected !!!!  Victim : [%17s]", stats.match["eth_dst"])
                if f1:
                    self.logger.info("abnormal burst in flow")
                if f2:
                    self.logger.info("Threshold triggered")
                if f3:
                    self.logger.info("Entropy change detected")
                if f5:
                    self.logger.info("abnormal number of fail connections")
                self.logger.info("\n==========================================================")
                # self.logger.info('datapath         '
                #          'in-port  eth-dst           '
                #          'out-port packets  bytes')
                # self.logger.info('%016x %8x %17s %8x %8d %8d',
                #              dpid,
                #              stats.match['in_port'], stats.match['eth_dst'],
                #              stats.instructions[0].actions[0].port,
                #              stats.packet_count, stats.byte_count)



    

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        return
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)




    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        ### add mitigation ###
        limit_connection(datapath, ofproto, parser)
        ###

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     if ev.msg.msg_len < ev.msg.total_len:
    #         self.logger.debug("packet truncated: only %s of %s bytes",
    #                           ev.msg.msg_len, ev.msg.total_len)

    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match['in_port']

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]

    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         print "ignore lldp packet"
    #         return

    #     dst = eth.dst
    #     src = eth.src

    #     dpid = datapath.id
        

    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

    #     byte_count = msg.total_len
    #     cookie = (dst, src, in_port, dpid)
    #     if cookie in self.flowstats:
    #         self.flowstats[cookie]["packet_count"] += 1
    #         self.flowstats[cookie]["byte_count"] += byte_count
    #     else:
    #         self.logger.info("ADD %s", cookie)
    #         self.flowstats[cookie] = {
    #             'packet_count': 1,
    #             'byte_count': byte_count
    #         }


    #     actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
    #                               in_port=in_port, actions=actions, data=None)
    #     datapath.send_msg(out)




    # def _monitor(self):
    #     while True:
    #         print "############# flow table #############  %d ", len(self.flowstats)
    #         # for cookie in self.flowstats:
    #         #     print cookie
    #         #     print "packet count", self.flowstats[cookie]["packet_count"]
    #         #     print "byte count", self.flowstats[cookie]["byte_count"]
    #         #     print ""

    #         self._flow_stats_reply_handler(MSG(self.flowstats))
    #         hub.sleep(5)

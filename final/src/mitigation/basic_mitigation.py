def block_out_sample_in(self, stats):
    ofproto = datapath.ofproto
    #SRC BLOCK FLOW
    src_mac = stats.match.dl_dst
    if not src_mac == self.gateway_mac:
        src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

        src_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=src_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(src_flow)

    eventlet.sleep(0.1)

    # DST BLOCK FLOW - We only sample this flow for 1 second,
    # Destination does not receive anything.
    dst_mac = stats.match.dl_dst
    if not dst_mac == self.gateway_mac:
        dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

        dst_actions = [datapath.ofproto_parser.OFPActionOutput(monitor_port)]

        dst_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=dst_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=1,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
        datapath.send_msg(dst_flow)

    #Notify parser of this source/destination being blocked from this point on.
    outgoing_block_mode_v1_dict[(haddr_to_str(src_mac))] = int(time.time() * 1000)



def sample_first_block_later(self, stats):
    # DST flow with slightly higher priority
    ofproto = datapath.ofproto
    dst_mac = stats.match.dl_dst
    if not dst_mac == self.gateway_mac:
        dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

        dst_actions = stats.actions
        dst_actions.append(datapath.ofproto_parser.OFPActionOutput(monitor_port))

        dst_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=dst_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
            priority=0x6001,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
        datapath.send_msg(dst_flow)

    outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))] = []
    # Time of installing first sample flow.
    outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))].append(int(time.time() * 1000))

    # Not sampling this flow for now. Could check relation between outgoing requests
    # and incoming responses if we sampled this.
    src_mac = stats.match.dl_dst
    if not src_mac == self.gateway_mac:
        src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

        src_actions = [datapath.ofproto_parser.OFPActionOutput(self.gateway_port)]

        src_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=src_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=2,
            priority=0x6001,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=src_actions)
        datapath.send_msg(src_flow)

    #SRC BLOCK FLOW
    src_mac = stats.match.dl_dst
    if not src_mac == self.gateway_mac:
        src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

        src_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=src_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=3,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(src_flow)

    # Time of installing DROP flow. We do not want to count packets after this flow expired
    # (3 seconds from this moment on)
    outgoing_block_mode_v2_dict[(haddr_to_str(dst_mac))].append(int(time.time() * 1000))

    # DST BLOCK FLOW - We only sample this flow for 1 second,
    # destination does not receive anything.
    dst_mac = stats.match.dl_dst
    if not dst_mac == self.gateway_mac:
        dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

        dst_actions = [datapath.ofproto_parser.OFPActionOutput(monitor_port)]

        dst_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=dst_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=3,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
        datapath.send_msg(dst_flow)



def sample_in_out(self, stats):
    print 'sample_in_out started'
    ofproto = datapath.ofproto
    # DST flow
    dst_mac = stats.match.dl_dst
    if not dst_mac == self.gateway_mac:
        dst_match = datapath.ofproto_parser.OFPMatch(dl_src=self.gateway_mac, dl_dst=dst_mac)

        dst_actions = stats.actions
        dst_actions.append(datapath.ofproto_parser.OFPActionOutput(monitor_port))

        dst_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=dst_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=10,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=dst_actions)
        datapath.send_msg(dst_flow)
        print 'Creating dst match sample flow'

    # SRC flow
    src_mac = stats.match.dl_dst
    if not src_mac == self.gateway_mac:
        src_match = datapath.ofproto_parser.OFPMatch(dl_src=src_mac, dl_dst=self.gateway_mac)

        src_actions = [datapath.ofproto_parser.OFPActionOutput(self.gateway_port),
                       datapath.ofproto_parser.OFPActionOutput(monitor_port)]

        src_flow = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=src_match, cookie=random_int(),
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=60,
            priority=0x6000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=src_actions)
        datapath.send_msg(src_flow)
        print 'Creating src match sample flow'
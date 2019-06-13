def limit_connection(datapath, ofproto, ofparser):
    """ Configure meter """
    b1 = ofparser.OFPMeterBandDscpRemark(rate=10, prec_level=1)
    req = ofparser.OFPMeterMod(datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_PKTPS, meter_id=1, bands=[b1])
    datapath.send_msg(req)
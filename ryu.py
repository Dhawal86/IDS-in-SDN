# ryu_app/simple_ids.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
from ryu.lib.packet import ether_types

import logging
import joblib
import numpy as np
from collections import defaultdict
import time

MODEL_PATH = "/home/dhawal/ryu_app/ids_model.pkl"
SCALER_PATH = "/home/dhawal/ryu_app/scaler.pkl"
LOG_FILE = "/home/dhawal/ryu_app/ids.log"

class SimpleIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def _init_(self, *args, **kwargs):
        super(SimpleIDS, self)._init_(*args, **kwargs)
        logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
        self.logger.info("Starting Ryu with Simple IDS...")

        # Load ML model and scaler
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)

        self.packet_count = defaultdict(int)
        self.attack_duration = defaultdict(list)
        self.blocked_ips = {}
        self.cooldown = 60  # seconds
        self.attack_threshold = 100
        self.time_window = 60

        self.monitor_thread = hub.spawn(self._unblock_ips)

    def _unblock_ips(self):
        while True:
            now = time.time()
            for ip in list(self.blocked_ips.keys()):
                if now - self.blocked_ips[ip]["time"] > self.cooldown:
                    self.logger.info(f"🟢 Unblocking IP: {ip}")
                    self.blocked_ips.pop(ip)
            hub.sleep(5)

    def _extract_features(self, pkt):
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            pkt_len = ip_pkt.total_length
            ether_type = eth.ethertype
            src_ip = int(ip_pkt.src.replace('.', ''))
            dst_ip = int(ip_pkt.dst.replace('.', ''))
            return np.array([pkt_len, ether_type, src_ip, dst_ip])
        return None

    def _predict(self, features):
        try:
            scaled = self.scaler.transform([features])
            return self.model.predict(scaled)[0]
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info(f"Switch connected: {ev.msg.datapath.id}")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_ip = ip_pkt.src
        if src_ip in self.blocked_ips:
            self.logger.warning(f"🔴 Dropped packet from blocked IP: {src_ip}")
            return

        features = self._extract_features(pkt)
        if features is None:
            return

        prediction = self._predict(features)
        if prediction == 1:
            self.logger.warning(f"🔴 Attack detected from {src_ip}")
            self._block_ip(datapath, src_ip)
            self.blocked_ips[src_ip] = {"time": time.time()}
        else:
            self._track(src_ip)

    def _track(self, src_ip):
        now = time.time()
        self.packet_count[src_ip] += 1
        self.attack_duration[src_ip].append(now)

        self.attack_duration[src_ip] = [t for t in self.attack_duration[src_ip] if now - t < self.time_window]

        if len(self.attack_duration[src_ip]) > self.attack_threshold:
            self.logger.warning(f"🟡 Repeated activity from {src_ip}. Blocking.")
            self.blocked_ips[src_ip] = {"time": now}

    def _block_ip(self, datapath, ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        instructions = []
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )
        datapath.send_msg(mod)
        self.logger.info(f"🚫 Blocked IP {ip} on switch {datapath.id}")
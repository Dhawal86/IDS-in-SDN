import logging
import joblib
from collections import defaultdict
import time
import numpy as np

from pox.core import core
from pox.lib.packet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.openflow import libopenflow_01 as of

log = logging.getLogger("pox.customids.simpleids")

# Model and scaler paths
MODEL_PATH = "/home/dhawal/pox/pox/customids/ids_model.pkl"
SCALER_PATH = "/home/dhawal/pox/pox/customids/scaler.pkl"

class IDSComponent:
    def _init_(self):
        log.info("Initializing IDS Component")

        # Load model and scaler
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            log.info("Model and scaler loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load model/scaler: {e}")
            raise

        # For activity tracking
        self.packet_count = defaultdict(int)
        self.attack_duration = defaultdict(list)
        self.time_window = 60  # seconds
        self.attack_threshold = 100  # packets

        core.openflow.addListeners(self)

    def _extract_features(self, packet):
        pkt_len = len(packet)
        ether_type = packet.type
        src_ip, dst_ip = 0, 0

        if packet.find('ipv4'):
            ip_pkt = packet.find('ipv4')
            src_ip = int(ip_pkt.srcip.toUnsigned())
            dst_ip = int(ip_pkt.dstip.toUnsigned())

        return np.array([pkt_len, ether_type, src_ip, dst_ip])

    def _predict(self, features):
        try:
            scaled = self.scaler.transform([features])
            return self.model.predict(scaled)[0]
        except Exception as e:
            log.error(f"Prediction error: {e}")
            return 0

    def _handle_packet_in(self, event):
        packet = event.parsed
        if not packet:
            return

        features = self._extract_features(packet)
        prediction = self._predict(features)

        if prediction == 1:  # Attack
            if packet.find('ipv4'):
                attacker_ip = packet.find('ipv4').srcip
                log.warning(f"🔴 Attack detected from IP: {attacker_ip}")
                self._block_ip(attacker_ip, event.dpid)
        else:
            self._track(packet)

    def _track(self, packet):
        now = time.time()
        if packet.find('ipv4'):
            src_ip = packet.find('ipv4').srcip
            self.packet_count[src_ip] += 1
            self.attack_duration[src_ip].append(now)

            # Remove timestamps outside the time window
            self.attack_duration[src_ip] = [t for t in self.attack_duration[src_ip] if now - t < self.time_window]

            if len(self.attack_duration[src_ip]) > self.attack_threshold:
                log.warning(f"🟡 Repeated suspicious activity from {src_ip}, blocking.")
                self._block_ip(src_ip)

    def _block_ip(self, ip, dpid=None):
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800  # IP
        msg.match.nw_src = IPAddr(str(ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

        if dpid:
            core.openflow.sendToDPID(dpid, msg)
            log.info(f"🚫 Sent block rule to switch {dpid} for IP {ip}")
        else:
            for conn in core.openflow.connections:
                conn.send(msg)
            log.info(f"🚫 Broadcasted block rule for IP {ip}")

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch connected: {event.dpid}")

def launch():
    log.info("Starting POX with Simple IDS...")
    IDSComponent()
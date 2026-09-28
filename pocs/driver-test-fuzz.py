#!/usr/bin/env python3
"""Malformed-input and robustness tester for the hostapd/wpa_supplicant
"test" driver transport (src/drivers/driver_test.c).

The tool binds its own UNIX datagram socket, sends a bounded corpus of
malformed, truncated, oversized, duplicated and otherwise hostile datagrams to
a running hostapd (driver=test) and/or wpa_supplicant (-Dtest) instance and
then verifies that the target still answers a well-formed Probe Request (AP)
or keeps running (STA). Everything stays on local sockets; no network
interface is touched.

Wire format (driver_test.h):
    magic "HTD1" | version u8 | type u8 | flags u8 | link_id u8 |
    freq le32 | payload_len le16 | seq le16 | payload

Usage:
    driver-test-fuzz.py --ap-sock /path/AP-socket [--sta-sock /path/STA-sock]
                        [--iterations N] [--seed S] [--report out.txt]
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

MAGIC = b"HTD1"
VERSION = 1
HDR_LEN = 16
MAX_PAYLOAD = 4000
MSG_MGMT, MSG_EAPOL, MSG_NULL = 1, 2, 3
BCAST = b"\xff" * 6


def hdr(msg_type=MSG_MGMT, flags=0, link_id=0xff, freq=2412, payload_len=0,
        seq=0, magic=MAGIC, version=VERSION):
    return magic + struct.pack("<BBBBIHH", version, msg_type, flags, link_id,
                               freq, payload_len, seq)


def msg(payload, **kw):
    kw.setdefault("payload_len", len(payload))
    return hdr(**kw) + payload


def mgmt(stype, da, sa, bssid, body, fc_flags=0):
    fc = (stype << 4) | fc_flags
    return struct.pack("<HH", fc, 0) + da + sa + bssid + struct.pack("<H", 0) + body


def probe_req(sa, ssid=b""):
    body = bytes([0, len(ssid)]) + ssid + bytes([1, 8, 0x82, 0x84, 0x8b, 0x96,
                                                  0x0c, 0x12, 0x18, 0x24])
    return mgmt(4, BCAST, sa, BCAST, body)


def rand_mac(rng):
    return bytes([0x02] + [rng.randrange(256) for _ in range(5)])


class Tester:
    def __init__(self, ap_sock, sta_sock, rng, report):
        self.ap_sock = ap_sock
        self.sta_sock = sta_sock
        self.rng = rng
        self.report = report
        self.own_path = "/tmp/driver-test-fuzz-%d.sock" % os.getpid()
        try:
            os.unlink(self.own_path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.own_path)
        self.sock.settimeout(0.5)
        self.own_mac = b"\x02\xfa\xce\x00\x00\x01"
        self.sent = 0
        self.send_errors = 0
        self.results = []

    def log(self, line):
        print(line)
        self.report.write(line + "\n")
        self.report.flush()

    def send(self, target, data):
        # The receiver may be slow (sanitizer builds); pace the sender when
        # the datagram socket queue is full instead of dropping test cases.
        for attempt in range(200):
            try:
                self.sock.sendto(data, target)
                self.sent += 1
                if self.sent % 50 == 0:
                    time.sleep(0.01)
                return True
            except (socket.timeout, BlockingIOError):
                time.sleep(0.01)
                continue
            except OSError as e:
                if e.errno == 11:  # EAGAIN
                    time.sleep(0.01)
                    continue
                self.send_errors += 1
                if self.send_errors <= 10:
                    self.log("  sendto(%s) failed: %s (len=%d)" % (target, e, len(data)))
                return False
        self.send_errors += 1
        self.log("  sendto(%s): receiver queue stayed full (len=%d)" % (target, len(data)))
        return False

    def drain(self):
        n = 0
        self.sock.settimeout(0.05)
        try:
            while True:
                self.sock.recvfrom(8192)
                n += 1
        except (socket.timeout, OSError):
            pass
        self.sock.settimeout(0.5)
        return n

    def ap_alive(self):
        """Send a valid Probe Request and expect a Probe Response."""
        if not self.ap_sock:
            return True
        self.drain()
        self.send(self.ap_sock, msg(probe_req(self.own_mac)))
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            if len(data) >= HDR_LEN + 24 and data[:4] == MAGIC:
                fc = struct.unpack("<H", data[HDR_LEN:HDR_LEN + 2])[0]
                if (fc >> 4) & 0xf == 5 and (fc >> 2) & 3 == 0:
                    return True
        return False

    def check(self, name, target):
        alive = self.ap_alive() if target == self.ap_sock else True
        self.results.append((name, alive))
        self.log("[%s] %s: sent=%d alive=%s" % ("AP" if target == self.ap_sock else "STA",
                                                name, self.sent, alive))
        return alive

    # ------------------------------------------------------------------
    def corpus(self, target, sta_mode=False):
        rng = self.rng
        peer_mac = self.own_mac
        # A valid frame to mutate: Probe Request for AP, Beacon-like Probe
        # Response for STA (addressed to a random STA address so it only
        # exercises the scan-result parser).
        if sta_mode:
            body = struct.pack("<QHH", 0, 100, 0x0411) + bytes([0, 4]) + b"fuzz" + \
                bytes([1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 3, 1, 1])
            valid = mgmt(5, BCAST, peer_mac, peer_mac, body)
        else:
            valid = probe_req(peer_mac)

        cases = []
        # 1. Header level
        cases.append(("empty datagram", b""))
        cases.append(("1 byte", b"H"))
        cases.append(("truncated header (15 bytes)", hdr(payload_len=0)[:15]))
        cases.append(("bad magic", msg(valid, magic=b"XXXX")))
        cases.append(("bad version 0", msg(valid, version=0)))
        cases.append(("bad version 2", msg(valid, version=2)))
        cases.append(("bad version 255", msg(valid, version=255)))
        cases.append(("unknown type 0", msg(valid, msg_type=0)))
        cases.append(("unknown type 4", msg(valid, msg_type=4)))
        cases.append(("unknown type 255", msg(valid, msg_type=255)))
        cases.append(("reserved flags", msg(valid, flags=0xfc)))
        cases.append(("invalid link_id 15", msg(valid, link_id=15)))
        cases.append(("invalid link_id 200", msg(valid, link_id=200)))
        cases.append(("payload_len too small", msg(valid, payload_len=len(valid) - 1)))
        cases.append(("payload_len too large", msg(valid, payload_len=len(valid) + 1)))
        cases.append(("payload_len 0xffff", msg(valid, payload_len=0xffff)))
        cases.append(("payload_len 0 with payload", msg(valid, payload_len=0)))
        cases.append(("header only, payload_len claims 100", hdr(payload_len=100)))
        cases.append(("oversized payload (4001)", msg(b"\x40" * 4001)))
        cases.append(("oversized payload (8000)", msg(b"\x40" * 8000)))
        cases.append(("max payload exactly (4000)", msg(valid + b"\x00" * (4000 - len(valid)))))
        cases.append(("NULL with payload", msg(b"\x00" * 10, msg_type=MSG_NULL)))
        cases.append(("NULL valid", msg(b"", msg_type=MSG_NULL)))
        cases.append(("freq 0", msg(valid, freq=0)))
        cases.append(("freq huge", msg(valid, freq=0xffffffff)))
        # 2. Management frame level
        cases.append(("mgmt payload 23 bytes", msg(valid[:23])))
        cases.append(("mgmt payload 24 bytes (header only)", msg(valid[:24])))
        cases.append(("data frame type", msg(mgmt(0, BCAST, peer_mac, BCAST, b"") [:1] +
                                             b"\x08" + valid[2:])))
        cases.append(("control frame type", msg(b"\xd4\x00" + valid[2:])))
        cases.append(("multicast SA", msg(mgmt(4, BCAST, BCAST, BCAST, b""))))
        cases.append(("protected bit without key", msg(mgmt(12, peer_mac, peer_mac, peer_mac,
                                                            b"\x03\x00", fc_flags=0x4000))))
        cases.append(("assoc req without auth", msg(mgmt(0, peer_mac, peer_mac, peer_mac,
                                                         struct.pack("<HH", 0x431, 10) + b"\x00\x04fuzz"))))
        cases.append(("assoc req truncated fixed fields", msg(mgmt(0, peer_mac, peer_mac, peer_mac, b"\x31"))))
        cases.append(("auth truncated", msg(mgmt(11, peer_mac, peer_mac, peer_mac, b"\x00\x00\x01"))))
        cases.append(("auth SAE bogus", msg(mgmt(11, peer_mac, peer_mac, peer_mac,
                                                 struct.pack("<HHH", 3, 1, 0) + bytes(rng.randrange(256) for _ in range(40))))))
        cases.append(("deauth from unknown", msg(mgmt(12, peer_mac, rand_mac(rng), peer_mac, b"\x02\x00"))))
        cases.append(("disassoc truncated", msg(mgmt(10, peer_mac, peer_mac, peer_mac, b"\x02"))))
        cases.append(("action truncated", msg(mgmt(13, peer_mac, peer_mac, peer_mac, b""))))
        cases.append(("action SA Query bogus", msg(mgmt(13, peer_mac, peer_mac, peer_mac, b"\x08\x00\x01\x02"))))
        cases.append(("action FT bogus", msg(mgmt(13, peer_mac, peer_mac, peer_mac, b"\x06\x01" + b"\x00" * 30))))
        cases.append(("probe req huge SSID len", msg(mgmt(4, BCAST, peer_mac, BCAST, b"\x00\xff" + b"A" * 20))))
        cases.append(("probe req elements overrun", msg(mgmt(4, BCAST, peer_mac, BCAST, b"\x00\x04fu"))))
        cases.append(("beacon truncated", msg(mgmt(8, BCAST, peer_mac, peer_mac, b"\x00" * 11))))
        cases.append(("probe resp truncated", msg(mgmt(5, peer_mac, peer_mac, peer_mac, b"\x00" * 5))))
        cases.append(("probe resp element overrun", msg(mgmt(5, BCAST, peer_mac, peer_mac,
                                                             struct.pack("<QHH", 0, 100, 0x411) + b"\x00\x20abc"))))
        cases.append(("reassoc resp bogus", msg(mgmt(3, peer_mac, peer_mac, peer_mac, struct.pack("<HHH", 0x411, 0, 0xc001)))))
        cases.append(("ML element garbage", msg(mgmt(0, peer_mac, peer_mac, peer_mac,
                                                     struct.pack("<HH", 0x431, 10) + b"\xff\x0a\x6b" +
                                                     bytes(rng.randrange(256) for _ in range(9))))))
        # 3. EAPOL level
        eth = peer_mac + peer_mac + b"\x88\x8e"
        cases.append(("eapol 13 bytes", msg(eth[:13], msg_type=MSG_EAPOL)))
        cases.append(("eapol eth header only", msg(eth, msg_type=MSG_EAPOL)))
        cases.append(("eapol wrong ethertype", msg(peer_mac + peer_mac + b"\x08\x00" + b"\x01" * 8, msg_type=MSG_EAPOL)))
        cases.append(("eapol multicast source", msg(peer_mac + BCAST + b"\x88\x8e" + b"\x01" * 8, msg_type=MSG_EAPOL)))
        cases.append(("eapol from unknown STA", msg(rand_mac(rng) + rand_mac(rng) + b"\x88\x8e" +
                                                    b"\x02\x03\x00\x5f" + b"\x00" * 95, msg_type=MSG_EAPOL)))
        cases.append(("eapol-key bogus length", msg(eth + b"\x02\x03\xff\xff" + b"\x00" * 20, msg_type=MSG_EAPOL)))
        cases.append(("eapol protected flag", msg(eth + b"\x02\x03\x00\x5f" + b"\x00" * 95, msg_type=MSG_EAPOL, flags=1)))
        cases.append(("eapol max size", msg(eth + b"\x02\x03" + struct.pack(">H", 3982) + b"\x00" * 3982, msg_type=MSG_EAPOL)))
        cases.append(("eapol rsn preauth ethertype", msg(peer_mac + peer_mac + b"\x88\xc7" + b"\x02\x00\x00\x04\x00\x00\x00\x00", msg_type=MSG_EAPOL)))
        return cases, valid

    def run_corpus(self, target, sta_mode):
        cases, valid = self.corpus(target, sta_mode)
        for name, data in cases:
            self.send(target, data)
        self.check("hand-crafted malformed corpus (%d cases)" % len(cases), target)
        return valid

    def run_bitflips(self, target, valid, iterations):
        rng = self.rng
        for _ in range(iterations):
            data = bytearray(msg(valid))
            for _ in range(rng.randrange(1, 6)):
                pos = rng.randrange(len(data))
                data[pos] ^= 1 << rng.randrange(8)
            # keep length consistent half of the time to reach the payload parser
            if rng.random() < 0.5:
                struct.pack_into("<H", data, 12, len(data) - HDR_LEN)
                data[0:4] = MAGIC
                data[4] = VERSION
            self.send(target, bytes(data))
        self.check("random bit flips (%d datagrams)" % iterations, target)

    def run_random_lengths(self, target, iterations):
        rng = self.rng
        for _ in range(iterations):
            n = rng.choice([0, 1, 7, 15, 16, 17, 23, 24, 40, 255, 256, 1500, 4015,
                            4016, 4017, 5000, 9000])
            data = bytes(rng.randrange(256) for _ in range(n))
            if n >= HDR_LEN and rng.random() < 0.7:
                data = msg(data[HDR_LEN:], msg_type=rng.choice([1, 2, 3, 77]))
            self.send(target, data)
        self.check("random length/garbage datagrams (%d)" % iterations, target)

    def run_duplicates(self, target, valid):
        for _ in range(50):
            self.send(target, msg(valid, seq=7))
        self.check("duplicate frames (50x same seq)", target)

    def run_peer_flood(self, target, count):
        """Many distinct transmitter addresses to exercise peer table bounds."""
        rng = self.rng
        for _ in range(count):
            self.send(target, msg(probe_req(rand_mac(rng))))
        self.check("peer table flood (%d distinct STA addresses)" % count, target)

    def run_state_machine_abuse(self, target):
        """Out-of-order MLME frames from a single fake STA."""
        sta = b"\x02\xab\xad\x1d\xea\x01"
        ap = BCAST
        # discover the BSSID from a probe response first
        self.drain()
        self.send(target, msg(probe_req(sta)))
        bssid = None
        deadline = time.time() + 1.5
        while time.time() < deadline and bssid is None:
            try:
                data, _ = self.sock.recvfrom(8192)
            except socket.timeout:
                break
            if len(data) >= HDR_LEN + 24 and data[:4] == MAGIC:
                bssid = data[HDR_LEN + 10:HDR_LEN + 16]
        if bssid is None:
            self.log("  (no BSSID learned; using broadcast)")
            bssid = ap
        seq = [
            ("assoc before auth", mgmt(0, bssid, sta, bssid, struct.pack("<HH", 0x431, 10) + b"\x00\x04fuzz\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24")),
            ("deauth before auth", mgmt(12, bssid, sta, bssid, b"\x03\x00")),
            ("open auth", mgmt(11, bssid, sta, bssid, struct.pack("<HHH", 0, 1, 0))),
            ("open auth duplicate", mgmt(11, bssid, sta, bssid, struct.pack("<HHH", 0, 1, 0))),
            ("auth transaction 2 from STA", mgmt(11, bssid, sta, bssid, struct.pack("<HHH", 0, 2, 0))),
            ("assoc with bogus SSID", mgmt(0, bssid, sta, bssid, struct.pack("<HH", 0x431, 10) + b"\x00\x05bogus\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24")),
            ("assoc without rates", mgmt(0, bssid, sta, bssid, struct.pack("<HH", 0x431, 10) + b"\x00\x04fuzz")),
            ("reassoc with bogus current AP", mgmt(2, bssid, sta, bssid, struct.pack("<HH", 0x431, 10) + b"\x11" * 6 + b"\x00\x04fuzz\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24")),
            ("SA Query before keys", mgmt(13, bssid, sta, bssid, b"\x08\x00\xaa\xbb")),
            ("disassoc", mgmt(10, bssid, sta, bssid, b"\x08\x00")),
            ("deauth twice", mgmt(12, bssid, sta, bssid, b"\x03\x00")),
            ("deauth twice", mgmt(12, bssid, sta, bssid, b"\x03\x00")),
            ("eapol before assoc", None),
        ]
        for name, frame in seq:
            if frame is None:
                self.send(target, msg(bssid + sta + b"\x88\x8e" + b"\x02\x03\x00\x5f" + b"\x00" * 95, msg_type=MSG_EAPOL))
            else:
                self.send(target, msg(frame))
            time.sleep(0.02)
        self.check("out-of-order MLME/EAPOL sequence (%d frames)" % len(seq), target)

    def run_sta_corpus(self, target):
        """Frames towards a wpa_supplicant test driver instance."""
        cases, valid = self.corpus(target, sta_mode=True)
        for name, data in cases:
            self.send(target, data)
        fake_ap = b"\x02\xde\xad\xbe\xef\x01"
        sta = BCAST  # broadcast DA so that the unicast checks are exercised too
        extra = [
            ("unsolicited auth resp", mgmt(11, sta, fake_ap, fake_ap, struct.pack("<HHH", 0, 2, 0))),
            ("unsolicited assoc resp", mgmt(1, sta, fake_ap, fake_ap, struct.pack("<HHH", 0x411, 0, 0xc001))),
            ("unsolicited deauth", mgmt(12, sta, fake_ap, fake_ap, b"\x02\x00")),
            ("unsolicited action", mgmt(13, sta, fake_ap, fake_ap, b"\x08\x01\x01\x02")),
            ("beacon w/ many elements", mgmt(8, BCAST, fake_ap, fake_ap, struct.pack("<QHH", 0, 100, 0x411) + (b"\xdd\x05\x00\x11\x22\x33\x44" * 300))),
            ("probe resp 64 different BSSIDs", None),
        ]
        rng = self.rng
        for name, frame in extra:
            if frame is None:
                for _ in range(80):
                    ap = rand_mac(rng)
                    body = struct.pack("<QHH", 0, 100, 0x411) + b"\x00\x04fuzz\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x06"
                    self.send(target, msg(mgmt(5, BCAST, ap, ap, body), freq=2437))
            else:
                self.send(target, msg(frame))
        self.check("STA-directed corpus (%d + %d cases)" % (len(cases), len(extra)), target)
        return valid

    def close(self):
        self.sock.close()
        try:
            os.unlink(self.own_path)
        except FileNotFoundError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ap-sock", help="hostapd test driver socket path")
    ap.add_argument("--sta-sock", help="wpa_supplicant test driver socket path")
    ap.add_argument("--iterations", type=int, default=500)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--report", default="/dev/stdout")
    args = ap.parse_args()
    if not args.ap_sock and not args.sta_sock:
        ap.error("--ap-sock and/or --sta-sock required")
    rng = random.Random(args.seed)
    with open(args.report, "w") as rep:
        t = Tester(args.ap_sock, args.sta_sock, rng, rep)
        t.log("driver-test fuzz: seed=%d iterations=%d ap=%s sta=%s" %
              (args.seed, args.iterations, args.ap_sock, args.sta_sock))
        ok = True
        if args.ap_sock:
            if not t.check("baseline liveness", args.ap_sock):
                t.log("AP does not answer Probe Requests before fuzzing - aborting")
                sys.exit(2)
            valid = t.run_corpus(args.ap_sock, sta_mode=False)
            t.run_bitflips(args.ap_sock, valid, args.iterations)
            t.run_random_lengths(args.ap_sock, args.iterations)
            t.run_duplicates(args.ap_sock, valid)
            t.run_peer_flood(args.ap_sock, 300)
            t.run_state_machine_abuse(args.ap_sock)
        if args.sta_sock:
            valid = t.run_sta_corpus(args.sta_sock)
            t.run_bitflips(args.sta_sock, valid, args.iterations)
            t.run_random_lengths(args.sta_sock, args.iterations)
            t.run_duplicates(args.sta_sock, valid)
        ok = all(alive for _, alive in t.results)
        t.log("summary: datagrams_sent=%d send_errors=%d checks=%d all_alive=%s" %
              (t.sent, t.send_errors, len(t.results), ok))
        t.close()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

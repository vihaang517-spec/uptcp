#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Multi-IMEI TCP GPS Packet Sender (VTMS Style)
Compatible with Python 2.7 & Python 3.x across Linux, Termux, macOS, & Windows.
Uses standard Python library (no external packages required).
"""

import sys
import time
import socket
import zlib
import argparse
import json
import os
from datetime import datetime

try:
    import urllib2 as urllib_req
except ImportError:
    import urllib.request as urllib_req

# ───────── COLOR CODES FOR TERMINAL ─────────
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_GREEN   = "\033[92m"
CLR_CYAN    = "\033[96m"
CLR_YELLOW  = "\033[93m"
CLR_RED     = "\033[91m"
CLR_MAGENTA = "\033[95m"

TEMPLATE = "$DP,TNOWTN,2.0.4,NR,01,L,{IMEI},0000,1,{DATE},{TIME},{LAT},{NS},{LON},{EW},0.0,207.78,45,265.5,0.60,0.40,airtel,0,1,25.6,4.0,0,C,29,404,97,06BC,3014,31,06BC,8E3C,31,06BC,8E1E,31,06BC,6E01,31,06BC,585A,0000,00,0,85091.887,0,0,{SEQ},(),{CRC}*"

def crc32_hex(data_str):
    """Calculates IEEE 802.3 CRC32 hex string in uppercase."""
    data_bytes = data_str.encode('ascii') if hasattr(data_str, 'encode') else str(data_str)
    crc = zlib.crc32(data_bytes) & 0xFFFFFFFF
    return "%08X" % crc

def build_packet(imei, lat, lon, seq_num):
    """Builds TNOWTN protocol packet with 0000 Vehicle No and calculated CRC32."""
    now = datetime.utcnow()
    date_str = now.strftime("%d%m%Y")  # DDMMYYYY
    time_str = now.strftime("%H%M%S")  # HHMMSS

    ns = "S" if lat < 0 else "N"
    ew = "W" if lon < 0 else "E"
    lat_str = "%.8f" % abs(lat)
    lon_str = "%.8f" % abs(lon)
    seq_str = "%06d" % seq_num

    body = TEMPLATE.replace("{IMEI}", str(imei)) \
                   .replace("{DATE}", date_str) \
                   .replace("{TIME}", time_str) \
                   .replace("{LAT}", lat_str) \
                   .replace("{NS}", ns) \
                   .replace("{LON}", lon_str) \
                   .replace("{EW}", ew) \
                   .replace("{SEQ}", seq_str)

    crc_target = body[:body.find("{CRC}")]
    crc_val = crc32_hex(crc_target)
    final_packet = body.replace("{CRC}", crc_val)
    return final_packet

def send_tcp_packet(ip, port, packet, timeout=5):
    """Sends packet via TCP socket to target IP & Port and reads response."""
    start_time = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        data_bytes = packet.encode('ascii') if hasattr(packet, 'encode') else packet
        sock.sendall(data_bytes)
        sent_len = len(data_bytes)
        
        reply = ""
        try:
            recv_data = sock.recv(1024)
            if recv_data:
                reply = recv_data.decode('utf-8', 'replace').strip() if hasattr(recv_data, 'decode') else str(recv_data).strip()
        except Exception:
            reply = ""
        
        latency = int((time.time() - start_time) * 1000)
        sock.close()
        return True, sent_len, latency, reply, None
    except Exception as e:
        if sock:
            try: sock.close()
            except Exception: pass
        latency = int((time.time() - start_time) * 1000)
        return False, 0, latency, "", str(e)

def fetch_vehicles_from_server(server_url):
    """Fetches vehicles list from PHP web backend database."""
    try:
        base_url = server_url.split('?')[0]
        url = base_url + '?action=vehicles'
        req = urllib_req.Request(url, headers={'User-Agent': 'VTMS/1.0'})
        res = urllib_req.urlopen(req, timeout=5)
        raw = res.read()
        if hasattr(raw, 'decode'): raw = raw.decode('utf-8')
        res_data = json.loads(raw)
        if res_data.get('ok') and isinstance(res_data.get('vehicles'), list):
            return res_data['vehicles']
    except Exception as e:
        print("%sWarning: Could not fetch DB from web server (%s)%s" % (CLR_RED, str(e), CLR_RESET))
    return []

def report_packet_sent_to_server(server_url, ip, port, packet, imei, vehicle_id=0):
    """Syncs sent packet count back to send.php web backend."""
    try:
        base_url = server_url.split('?')[0]
        payload = json.dumps({
            "ip": ip,
            "port": port,
            "packet": packet,
            "imei": imei,
            "vehicle_id": vehicle_id
        })
        if hasattr(payload, 'encode'): payload = payload.encode('utf-8')
        req = urllib_req.Request(base_url, data=payload, headers={
            'Content-Type': 'application/json',
            'User-Agent': 'VTMS/1.0'
        })
        res = urllib_req.urlopen(req, timeout=4)
        res.close()
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Multi-IMEI TCP GPS Packet Sender (VTMS)")
    parser.add_argument("--ip", default="154.210.168.75", help="Target Server IP / Host")
    parser.add_argument("--port", type=int, default=4002, help="Target Port")
    parser.add_argument("--interval", type=float, default=10.0, help="Sending Interval (seconds)")
    parser.add_argument("--imeis", default="", help="Comma-separated IMEIs list (e.g. 869742088976045,866192078002423)")
    parser.add_argument("--file", default="", help="Path to text file with IMEIs list")
    parser.add_argument("--lat", type=float, default=30.00982350, help="Default Latitude")
    parser.add_argument("--lon", type=float, default=77.57197480, help="Default Longitude")
    parser.add_argument("--server", default="", help="Web backend URL to fetch DB (e.g. http://orbitgps.in/up/send.php)")
    args = parser.parse_args()

    print("\n%s%s===================================================%s" % (CLR_BOLD, CLR_CYAN, CLR_RESET))
    print("%s%s   MULTI-IMEI TCP PACKET SENDER (VTMS)            %s" % (CLR_BOLD, CLR_GREEN, CLR_RESET))
    print("%s%s===================================================%s" % (CLR_BOLD, CLR_CYAN, CLR_RESET))
    print("%sTarget Host:%s %s:%d" % (CLR_BOLD, CLR_RESET, args.ip, args.port))
    print("%sInterval:%s %.1f seconds" % (CLR_BOLD, CLR_RESET, args.interval))
    print("%sVehicle No:%s 0000 (Fixed)" % (CLR_BOLD, CLR_RESET))

    vehicles_list = []

    # 1. Parse IMEIs from command line
    if args.imeis:
        raw_imeis = [x.strip() for x in args.imeis.split(',') if x.strip()]
        for idx, imei_val in enumerate(raw_imeis, start=1):
            vehicles_list.append({
                'id': idx,
                'vehicle_no': '0000',
                'imei': imei_val,
                'lat': args.lat,
                'lon': args.lon
            })

    # 2. Parse IMEIs from text file
    if args.file and os.path.exists(args.file):
        with open(args.file, 'r') as f:
            for idx, line in enumerate(f, start=len(vehicles_list) + 1):
                imei_val = line.strip()
                if imei_val and imei_val.isdigit() and len(imei_val) == 15:
                    vehicles_list.append({
                        'id': idx,
                        'vehicle_no': '0000',
                        'imei': imei_val,
                        'lat': args.lat,
                        'lon': args.lon
                    })

    # Default fallback list if none provided
    if not vehicles_list and not args.server:
        vehicles_list = [
            {'id': 1, 'vehicle_no': '0000', 'imei': '869742088976045', 'lat': 30.00982350, 'lon': 77.57197480},
            {'id': 2, 'vehicle_no': '0000', 'imei': '866192078002423', 'lat': 24.09697030, 'lon': 72.74554590},
            {'id': 3, 'vehicle_no': '0000', 'imei': '864201048291034', 'lat': 28.61393910, 'lon': 77.20902120}
        ]

    print("%sInitial Loaded IMEIs:%s %d" % (CLR_BOLD, CLR_RESET, len(vehicles_list)))
    if args.server:
        print("%sWeb Server DB Sync:%s %s" % (CLR_BOLD, CLR_RESET, args.server))
    print("%s---------------------------------------------------%s\n" % (CLR_CYAN, CLR_RESET))

    loop_count = 0
    seq_counter = 0

    try:
        while True:
            loop_count += 1
            now_str = datetime.now().strftime("%H:%M:%S")

            # Fetch live list from server if configured
            active_vehicles = vehicles_list
            if args.server:
                remote_list = fetch_vehicles_from_server(args.server)
                if remote_list:
                    active_vehicles = remote_list

            print("%s%s=== Loop #%d at [%s] (Processing %d Vehicles) ===%s" % (CLR_BOLD, CLR_YELLOW, loop_count, now_str, len(active_vehicles), CLR_RESET))

            for v in active_vehicles:
                seq_counter += 1
                imei = v.get('imei', '')
                lat = float(v.get('lat', args.lat))
                lon = float(v.get('lon', args.lon))
                v_id = v.get('id', 0)

                packet = build_packet(imei, lat, lon, seq_counter)
                print("%s[IMEI %s]%s -> %s" % (CLR_CYAN, str(imei), CLR_RESET, packet))

                ok, sent_bytes, latency, reply, err = send_tcp_packet(args.ip, args.port, packet)

                if ok:
                    reply_str = (" | Reply: %s" % reply) if reply else ""
                    print("  %s[OK] Delivered %d bytes in %d ms to %s:%d%s%s" % (CLR_GREEN, sent_bytes, latency, args.ip, args.port, reply_str, CLR_RESET))
                    
                    if args.server:
                        report_packet_sent_to_server(args.server, args.ip, args.port, packet, imei, v_id)
                else:
                    print("  %s[FAIL] %s (%d ms)%s" % (CLR_RED, str(err), latency, CLR_RESET))

            print("%sWaiting %.1fs before next cycle...%s\n" % (CLR_MAGENTA, args.interval, CLR_RESET))
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n%s%sStopped by user. Completed %d loops.%s\n" % (CLR_BOLD, CLR_YELLOW, loop_count, CLR_RESET))

if __name__ == "__main__":
    main()

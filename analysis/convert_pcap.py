import socket
from scapy.all import *
import sys
import re
import os

def combine_payloads(packet, combined_payload):
    return combined_payload + bytes(packet[IP].payload.load)

def convert_pcap_into_single_seed_file(input_pcap, dst_ip, output_raw, region_delimiter):
    try:
        packets = rdpcap(input_pcap)
    except FileNotFoundError:
        print(f"Error: The file {input_pcap} was not found.")
        sys.exit(1)

    combined_payload = b""
    expected_content_length = 0
    os.makedirs(os.path.dirname(output_raw), exist_ok=True)

    hex_bytes = []

    with open(output_raw, "wb") as f:
        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt[IP].payload):
                continue

            network_pkt = pkt[IP]
            
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                transport_pkt = pkt[TCP]
            elif pkt.haslayer(UDP) and pkt[UDP].payload:
                transport_pkt = pkt[UDP]
            elif pkt.haslayer(SCTP) and pkt[SCTP].payload:
                transport_pkt = pkt[SCTP]
            else:
                continue

            if network_pkt.dst != dst_ip:
                continue

            if combined_payload:
                expected_content_length -= len(bytes(pkt[IP].payload.load))
                payload = combine_payloads(pkt, combined_payload)
                combined_payload = b""
            else:
                payload = bytes(transport_pkt.payload.load)

            try:
                payload_str = payload.decode('utf-8')
            except UnicodeDecodeError:
                continue

            content_length_match = re.search(r'Content-Length: (\d+)', payload_str)
            if content_length_match:
                content_length = int(content_length_match.group(1))
                end_of_headers = payload.find(b'\r\n\r\n')
                if end_of_headers == -1:
                    continue
                expected_content_length = content_length - (len(payload) - end_of_headers - 4)

            if expected_content_length > 0:
                combined_payload += payload
                continue

            payload += region_delimiter
            request_hex = [byte for byte in payload]
            hex_bytes.append(request_hex)

            f.write(payload)

    return hex_bytes

def convert_pcap_into_multiple_seed_files(input_pcap, dst_ip, output_dir, input_filename, region_delimiter):
    try:
        packets = rdpcap(input_pcap)
    except FileNotFoundError:
        print(f"Error: The file {input_pcap} was not found.")
        sys.exit(1)

    combined_payload = b""
    expected_content_length = 0
    request_counter = 0

    os.makedirs(output_dir, exist_ok=True)

    for _, pkt in enumerate(packets):
        if pkt.haslayer(IP) and pkt[IP].payload:
            network_pkt = pkt[IP]

            if pkt.haslayer(TCP) and pkt[TCP].payload:
                transport_pkt = pkt[TCP]
            elif pkt.haslayer(UDP) and pkt[UDP].payload:
                transport_pkt = pkt[UDP]
            elif pkt.haslayer(SCTP) and pkt[SCTP].payload:
                transport_pkt = pkt[SCTP]
            else:
                continue

            if network_pkt.dst == dst_ip:
                if combined_payload:
                    expected_content_length -= len(bytes(pkt[IP].payload.load))
                    payload = combine_payloads(pkt, combined_payload)
                    combined_payload = b""
                else:
                    payload = bytes(transport_pkt.payload.load)

                try:
                    payload_str = payload.decode('utf-8')
                except UnicodeDecodeError:
                    continue

                content_length_match = re.search(r'Content-Length: (\d+)', payload_str)
                if content_length_match:
                    content_length = int(content_length_match.group(1))
                    end_of_headers = payload.find(b'\r\n\r\n')
                    assert end_of_headers != -1
                    expected_content_length = content_length - (len(payload) - end_of_headers - 4)

                if expected_content_length > 0:
                    combined_payload += payload
                    continue

                payload += region_delimiter
                output_raw = os.path.join(output_dir, f"{input_filename}_{request_counter}.seed")
                os.makedirs(os.path.dirname(output_raw), exist_ok=True)
                with open(output_raw, "wb") as f:
                    f.write(payload)
                request_counter += 1

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python script.py <input_pcap> <output_path> <dst_ip> <mode>")
        print("Modes: 'single' for single output file, 'multiple' for multiple output files")
        sys.exit(1)

    input_pcap = sys.argv[1]
    output_path = sys.argv[2]
    dst_ip = sys.argv[3]
    mode = sys.argv[4]

    input_filename = os.path.splitext(os.path.basename(input_pcap))[0]

    if mode == 'single':
        output_raw = os.path.join(output_path, f"{input_filename}_output.bin")
        convert_pcap_into_single_seed_file(input_pcap, dst_ip, output_raw, b'\r\r\n\r\r\n')
    elif mode == 'multiple':
        convert_pcap_into_multiple_seed_files(input_pcap, dst_ip, output_path, input_filename, b'\r\r\n\r\r\n')
    else:
        print("Invalid mode specified. Use 'single' for single output file or 'multiple' for multiple output files.")
        sys.exit(1)

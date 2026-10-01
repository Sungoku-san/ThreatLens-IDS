"""
generate_test_dataset.py
Generates a realistic, highly diverse multi-parameter testing dataset with 1,500 records
conforming to the CICIDS2017 standard 79-column schema.
"""

import os
import csv
import random

def generate_test_dataset(num_records=1500):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(base_dir, 'dataset')
    root_dir = os.path.dirname(base_dir)
    os.makedirs(dataset_dir, exist_ok=True)
    
    filepath_backend = os.path.join(dataset_dir, 'test_network_flows_1500.csv')
    filepath_root = os.path.join(root_dir, 'test_dataset_1000.csv')
    
    # 79 standard columns of CIC-IDS2017 (including leading whitespace conventions)
    headers = [
        " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
        "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
        " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
        " Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
        " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
        " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean",
        " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
        " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags",
        " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length",
        "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
        " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count",
        " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count",
        " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio",
        " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size",
        " Fwd Header Length.1", "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk",
        " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk",
        " Bwd Avg Bulk Rate", "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets",
        " Subflow Bwd Bytes", "Init_Win_bytes_forward", " Init_Win_bytes_backward",
        " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean", " Active Std",
        " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min",
        " Label"
    ]
    
    # Traffic profile distribution
    # Profile types:
    # 1. BENIGN_WEB (HTTP/HTTPS) - ~35%
    # 2. BENIGN_DNS_NTP - ~15%
    # 3. BENIGN_SSH_ADMIN - ~10%
    # 4. BENIGN_DATABASE - ~10%
    # 5. DDOS_SYN_FLOOD - ~8%
    # 6. DDOS_HTTP_VOLUMETRIC - ~7%
    # 7. PORTSCAN_HORIZONTAL - ~6%
    # 8. PORTSCAN_SYN_STEALTH - ~4%
    # 9. SSH_PATATOR_BRUTEFORCE - ~3%
    # 10. ANOMALY_OUTLIER - ~2%
    
    profiles = [
        "BENIGN_WEB", "BENIGN_DNS_NTP", "BENIGN_SSH_ADMIN", "BENIGN_DATABASE",
        "DDOS_SYN_FLOOD", "DDOS_HTTP_VOLUMETRIC", "PORTSCAN_HORIZONTAL",
        "PORTSCAN_SYN_STEALTH", "SSH_PATATOR_BRUTEFORCE", "ANOMALY_OUTLIER"
    ]
    weights = [0.35, 0.15, 0.10, 0.10, 0.08, 0.07, 0.06, 0.04, 0.03, 0.02]
    
    rows = []
    
    for i in range(num_records):
        profile = random.choices(profiles, weights=weights)[0]
        
        # Default initialization
        fin_flag = 0
        syn_flag = 0
        rst_flag = 0
        psh_flag = 0
        ack_flag = 1
        urg_flag = 0
        cwe_flag = 0
        ece_flag = 0
        
        if profile == "BENIGN_WEB":
            port = random.choice([80, 443, 8080, 8443])
            duration = random.uniform(50, 15000)
            fwd_pkts = random.randint(3, 20)
            bwd_pkts = random.randint(3, 25)
            fwd_len = fwd_pkts * random.uniform(100, 1200)
            bwd_len = bwd_pkts * random.uniform(200, 1450)
            syn_flag = random.choice([0, 1])
            ack_flag = 1
            label = "BENIGN"
            
        elif profile == "BENIGN_DNS_NTP":
            port = random.choice([53, 123])
            duration = random.uniform(5, 500)
            fwd_pkts = random.randint(1, 2)
            bwd_pkts = random.randint(1, 2)
            fwd_len = fwd_pkts * random.uniform(32, 90)
            bwd_len = bwd_pkts * random.uniform(48, 180)
            syn_flag = 0
            ack_flag = random.choice([0, 1])
            label = "BENIGN"
            
        elif profile == "BENIGN_SSH_ADMIN":
            port = 22
            duration = random.uniform(1000, 80000)
            fwd_pkts = random.randint(10, 40)
            bwd_pkts = random.randint(10, 45)
            fwd_len = fwd_pkts * random.uniform(40, 150)
            bwd_len = bwd_pkts * random.uniform(60, 250)
            syn_flag = 0
            ack_flag = 1
            label = "BENIGN"
            
        elif profile == "BENIGN_DATABASE":
            port = random.choice([3306, 5432, 1433, 27017])
            duration = random.uniform(200, 25000)
            fwd_pkts = random.randint(4, 30)
            bwd_pkts = random.randint(4, 35)
            fwd_len = fwd_pkts * random.uniform(80, 600)
            bwd_len = bwd_pkts * random.uniform(150, 1200)
            syn_flag = 0
            ack_flag = 1
            label = "BENIGN"
            
        elif profile == "DDOS_SYN_FLOOD":
            port = random.choice([80, 443, 8080, 53])
            duration = random.uniform(100, 20000)
            fwd_pkts = random.randint(80, 600)
            bwd_pkts = 0  # Targets overwhelmed, no response
            fwd_len = fwd_pkts * random.uniform(40, 80)
            bwd_len = 0
            syn_flag = 1
            ack_flag = 0
            label = "DDoS"
            
        elif profile == "DDOS_HTTP_VOLUMETRIC":
            port = random.choice([80, 443, 8080])
            duration = random.uniform(100000, 5000000)
            fwd_pkts = random.randint(150, 1200)
            bwd_pkts = random.randint(0, 10)
            fwd_len = fwd_pkts * random.uniform(400, 1460)
            bwd_len = bwd_pkts * random.uniform(0, 80)
            syn_flag = 1
            ack_flag = random.choice([0, 1])
            label = "DDoS"
            
        elif profile == "PORTSCAN_HORIZONTAL":
            port = random.randint(1, 65535)
            duration = random.uniform(1, 150)
            fwd_pkts = 1
            bwd_pkts = 0
            fwd_len = 0
            bwd_len = 0
            syn_flag = 1
            ack_flag = 0
            label = "PortScan"
            
        elif profile == "PORTSCAN_SYN_STEALTH":
            port = random.choice([21, 23, 25, 110, 139, 445, 1433, 3389, 5900, 8000, 8888])
            duration = random.uniform(10, 300)
            fwd_pkts = random.randint(1, 3)
            bwd_pkts = random.randint(0, 1)
            fwd_len = fwd_pkts * random.uniform(0, 40)
            bwd_len = bwd_pkts * random.uniform(0, 40)
            syn_flag = 1
            ack_flag = 0
            label = "PortScan"
            
        elif profile == "SSH_PATATOR_BRUTEFORCE":
            port = 22
            duration = random.uniform(15000, 400000)
            fwd_pkts = random.randint(20, 180)
            bwd_pkts = random.randint(18, 160)
            fwd_len = fwd_pkts * random.uniform(30, 80)
            bwd_len = bwd_pkts * random.uniform(30, 90)
            syn_flag = 0
            ack_flag = 1
            psh_flag = 1
            label = "SSH-Patator"
            
        else:  # ANOMALY_OUTLIER
            port = random.randint(1024, 65535)
            duration = random.uniform(50, 50000)
            fwd_pkts = random.randint(5, 50)
            bwd_pkts = random.randint(0, 5)
            fwd_len = fwd_pkts * random.uniform(200, 1400)
            bwd_len = bwd_pkts * random.uniform(0, 200)
            syn_flag = random.choice([0, 1])
            ack_flag = random.choice([0, 1])
            rst_flag = random.choice([0, 1])
            label = "BENIGN"  # Model should evaluate outlier / threshold
            
        # Rates calculations
        dur_sec = duration / 1000000.0 if duration > 0 else 0.000001
        pkt_rate = (fwd_pkts + bwd_pkts) / dur_sec
        byte_rate = (fwd_len + bwd_len) / dur_sec
        fwd_pkt_rate = fwd_pkts / dur_sec
        bwd_pkt_rate = bwd_pkts / dur_sec
        
        fwd_mean = (fwd_len / fwd_pkts) if fwd_pkts > 0 else 0
        bwd_mean = (bwd_len / bwd_pkts) if bwd_pkts > 0 else 0
        tot_pkts = fwd_pkts + bwd_pkts
        avg_pkt_size = ((fwd_len + bwd_len) / tot_pkts) if tot_pkts > 0 else 0
        down_up_ratio = round(bwd_pkts / fwd_pkts, 2) if fwd_pkts > 0 else 0.0
        
        row = []
        for h in headers:
            if h == " Destination Port": row.append(port)
            elif h == " Flow Duration": row.append(int(duration))
            elif h == " Total Fwd Packets": row.append(fwd_pkts)
            elif h == " Total Backward Packets": row.append(bwd_pkts)
            elif h == "Total Length of Fwd Packets": row.append(int(fwd_len))
            elif h == " Total Length of Bwd Packets": row.append(int(bwd_len))
            elif h == " Fwd Packet Length Max": row.append(int(fwd_mean * random.uniform(1.0, 1.4)))
            elif h == " Fwd Packet Length Min": row.append(int(fwd_mean * 0.2) if fwd_pkts > 1 else int(fwd_mean))
            elif h == " Fwd Packet Length Mean": row.append(int(fwd_mean))
            elif h == " Fwd Packet Length Std": row.append(round(random.uniform(0, 45.0), 3))
            elif h == " Bwd Packet Length Max": row.append(int(bwd_mean * random.uniform(1.0, 1.3)))
            elif h == " Bwd Packet Length Min": row.append(0)
            elif h == " Bwd Packet Length Mean": row.append(int(bwd_mean))
            elif h == " Bwd Packet Length Std": row.append(round(random.uniform(0, 45.0), 3))
            elif h == "Flow Bytes/s": row.append(int(byte_rate))
            elif h == " Flow Packets/s": row.append(int(pkt_rate))
            elif h == " Flow IAT Mean": row.append(int(duration / tot_pkts) if tot_pkts > 0 else 0)
            elif h == " Flow IAT Std": row.append(round(random.uniform(0, 500.0), 2))
            elif h == " Flow IAT Max": row.append(int(duration))
            elif h == " Flow IAT Min": row.append(random.randint(1, 15))
            elif h == "Fwd IAT Total": row.append(int(duration * 0.85))
            elif h == " Fwd IAT Mean": row.append(int(duration * 0.85 / fwd_pkts) if fwd_pkts > 0 else 0)
            elif h == " Fwd IAT Std": row.append(0)
            elif h == " Fwd IAT Max": row.append(int(duration * 0.85))
            elif h == " Fwd IAT Min": row.append(0)
            elif h == "Bwd IAT Total": row.append(int(duration * 0.70))
            elif h == " Bwd IAT Mean": row.append(int(duration * 0.70 / bwd_pkts) if bwd_pkts > 0 else 0)
            elif h == " Bwd IAT Std": row.append(0)
            elif h == " Bwd IAT Max": row.append(int(duration * 0.70))
            elif h == " Bwd IAT Min": row.append(0)
            elif h == "Fwd PSH Flags": row.append(psh_flag)
            elif h == " Bwd PSH Flags": row.append(0)
            elif h == " Fwd URG Flags": row.append(urg_flag)
            elif h == " Bwd URG Flags": row.append(0)
            elif h == " Fwd Header Length": row.append(fwd_pkts * 20)
            elif h == " Bwd Header Length": row.append(bwd_pkts * 20)
            elif h == "Fwd Packets/s": row.append(int(fwd_pkt_rate))
            elif h == " Bwd Packets/s": row.append(int(bwd_pkt_rate))
            elif h == " Min Packet Length": row.append(0)
            elif h == " Max Packet Length": row.append(1500 if profile.startswith("DDOS") else 1460)
            elif h == " Packet Length Mean": row.append(int(avg_pkt_size))
            elif h == " Packet Length Std": row.append(round(random.uniform(0, 95.0), 2))
            elif h == " Packet Length Variance": row.append(round(random.uniform(0, 900.0), 2))
            elif h == "FIN Flag Count": row.append(fin_flag)
            elif h == " SYN Flag Count": row.append(syn_flag)
            elif h == " RST Flag Count": row.append(rst_flag)
            elif h == " PSH Flag Count": row.append(psh_flag)
            elif h == " ACK Flag Count": row.append(ack_flag)
            elif h == " URG Flag Count": row.append(urg_flag)
            elif h == " CWE Flag Count": row.append(cwe_flag)
            elif h == " ECE Flag Count": row.append(ece_flag)
            elif h == " Down/Up Ratio": row.append(down_up_ratio)
            elif h == " Average Packet Size": row.append(int(avg_pkt_size))
            elif h == " Avg Fwd Segment Size": row.append(int(fwd_mean))
            elif h == " Avg Bwd Segment Size": row.append(int(bwd_mean))
            elif h == " Fwd Header Length.1": row.append(fwd_pkts * 20)
            elif h == "Fwd Avg Bytes/Bulk": row.append(0)
            elif h == " Fwd Avg Packets/Bulk": row.append(0)
            elif h == " Fwd Avg Bulk Rate": row.append(0)
            elif h == " Bwd Avg Bytes/Bulk": row.append(0)
            elif h == " Bwd Avg Packets/Bulk": row.append(0)
            elif h == " Bwd Avg Bulk Rate": row.append(0)
            elif h == "Subflow Fwd Packets": row.append(fwd_pkts)
            elif h == " Subflow Fwd Bytes": row.append(int(fwd_len))
            elif h == " Subflow Bwd Packets": row.append(bwd_pkts)
            elif h == " Subflow Bwd Bytes": row.append(int(bwd_len))
            elif h == "Init_Win_bytes_forward": row.append(random.randint(29200, 65535))
            elif h == " Init_Win_bytes_backward": row.append(random.randint(29200, 65535))
            elif h == " act_data_pkt_fwd": row.append(max(0, fwd_pkts - 1))
            elif h == " min_seg_size_forward": row.append(20)
            elif h == "Active Mean": row.append(0)
            elif h == " Active Std": row.append(0)
            elif h == " Active Max": row.append(0)
            elif h == " Active Min": row.append(0)
            elif h == "Idle Mean": row.append(0)
            elif h == " Idle Std": row.append(0)
            elif h == " Idle Max": row.append(0)
            elif h == " Idle Min": row.append(0)
            elif h == " Label": row.append(label)
            else: row.append(0)
            
        rows.append(row)
        
    # Write to both destinations
    for target in [filepath_backend, filepath_root]:
        with open(target, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
            
    print(f"[SUCCESS] Generated {len(rows)} diverse network flow records:")
    print(f"  - Backend dataset path: {filepath_backend}")
    print(f"  - Workspace root path:  {filepath_root}")
    return filepath_backend, len(rows)

if __name__ == '__main__':
    generate_test_dataset(1500)

import os
import csv
import random

def generate_sample():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(base_dir, 'dataset')
    os.makedirs(dataset_dir, exist_ok=True)
    
    filepath = os.path.join(dataset_dir, 'CICIDS2017.csv')
    
    # Standard columns of CIC-IDS2017 (including leading spaces)
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
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for i in range(1500):
            # Pick a target label
            label_choice = random.choices(
                ["BENIGN", "DDoS", "PortScan", "SSH-Patator"], 
                weights=[0.75, 0.15, 0.07, 0.03]
            )[0]
            
            # Generate feature ranges based on attack type
            if label_choice == "BENIGN":
                port = random.choice([80, 443, 22, 53, 123])
                duration = random.uniform(10, 5000)
                fwd_pkts = random.randint(1, 10)
                bwd_pkts = random.randint(1, 12)
                fwd_len = fwd_pkts * random.uniform(40, 1000)
                bwd_len = bwd_pkts * random.uniform(40, 1200)
                rate = (fwd_pkts + bwd_pkts) / (duration / 1000000.0) if duration > 0 else 0
                syn_flag = random.choice([0, 1])
                ack_flag = random.choice([0, 1])
            elif label_choice == "DDoS":
                port = random.choice([80, 443, 3306, 8080])
                duration = random.uniform(50000, 5000000)
                fwd_pkts = random.randint(50, 500)
                bwd_pkts = random.randint(0, 5)
                fwd_len = fwd_pkts * random.uniform(100, 1400)
                bwd_len = bwd_pkts * random.uniform(0, 50)
                rate = (fwd_pkts + bwd_pkts) / (duration / 1000000.0) if duration > 0 else 0
                syn_flag = 1
                ack_flag = 0
            elif label_choice == "PortScan":
                port = random.randint(1, 65535)
                duration = random.uniform(1, 200)
                fwd_pkts = random.randint(1, 2)
                bwd_pkts = random.randint(0, 1)
                fwd_len = fwd_pkts * 0
                bwd_len = bwd_pkts * 0
                rate = (fwd_pkts + bwd_pkts) / (duration / 1000000.0) if duration > 0 else 0
                syn_flag = 1
                ack_flag = 0
            else: # SSH-Patator brute force
                port = 22
                duration = random.uniform(10000, 600000)
                fwd_pkts = random.randint(10, 150)
                bwd_pkts = random.randint(8, 140)
                fwd_len = fwd_pkts * random.uniform(20, 80)
                bwd_len = bwd_pkts * random.uniform(20, 90)
                rate = (fwd_pkts + bwd_pkts) / (duration / 1000000.0) if duration > 0 else 0
                syn_flag = 0
                ack_flag = 1

            # Populate row
            row = []
            for h in headers:
                if h == " Destination Port": row.append(port)
                elif h == " Flow Duration": row.append(int(duration))
                elif h == " Total Fwd Packets": row.append(fwd_pkts)
                elif h == " Total Backward Packets": row.append(bwd_pkts)
                elif h == "Total Length of Fwd Packets": row.append(int(fwd_len))
                elif h == " Total Length of Bwd Packets": row.append(int(bwd_len))
                elif h == " Fwd Packet Length Max": row.append(int(fwd_len / fwd_pkts) if fwd_pkts > 0 else 0)
                elif h == " Fwd Packet Length Min": row.append(10 if label_choice == "BENIGN" else 0)
                elif h == " Fwd Packet Length Mean": row.append(int(fwd_len / fwd_pkts) if fwd_pkts > 0 else 0)
                elif h == " Fwd Packet Length Std": row.append(random.uniform(0, 50))
                elif h == " Bwd Packet Length Max": row.append(int(bwd_len / bwd_pkts) if bwd_pkts > 0 else 0)
                elif h == " Bwd Packet Length Min": row.append(0)
                elif h == " Bwd Packet Length Mean": row.append(int(bwd_len / bwd_pkts) if bwd_pkts > 0 else 0)
                elif h == " Bwd Packet Length Std": row.append(random.uniform(0, 50))
                elif h == "Flow Bytes/s": row.append(int((fwd_len + bwd_len) / (duration / 1000000.0)) if duration > 0 else 0)
                elif h == " Flow Packets/s": row.append(int(rate))
                elif h == " Flow IAT Mean": row.append(int(duration / (fwd_pkts + bwd_pkts)) if (fwd_pkts + bwd_pkts) > 0 else 0)
                elif h == " Flow IAT Std": row.append(random.uniform(0, 1000))
                elif h == " Flow IAT Max": row.append(int(duration))
                elif h == " Flow IAT Min": row.append(random.randint(1, 10))
                elif h == "Fwd IAT Total": row.append(int(duration * 0.8))
                elif h == " Fwd IAT Mean": row.append(int(duration * 0.8 / fwd_pkts) if fwd_pkts > 0 else 0)
                elif h == " Fwd IAT Std": row.append(0)
                elif h == " Fwd IAT Max": row.append(int(duration * 0.8))
                elif h == " Fwd IAT Min": row.append(0)
                elif h == "Bwd IAT Total": row.append(int(duration * 0.6))
                elif h == " Bwd IAT Mean": row.append(int(duration * 0.6 / bwd_pkts) if bwd_pkts > 0 else 0)
                elif h == " Bwd IAT Std": row.append(0)
                elif h == " Bwd IAT Max": row.append(int(duration * 0.6))
                elif h == " Bwd IAT Min": row.append(0)
                elif h == "Fwd PSH Flags": row.append(0)
                elif h == " Bwd PSH Flags": row.append(0)
                elif h == " Fwd URG Flags": row.append(0)
                elif h == " Bwd URG Flags": row.append(0)
                elif h == " Fwd Header Length": row.append(fwd_pkts * 20)
                elif h == " Bwd Header Length": row.append(bwd_pkts * 20)
                elif h == "Fwd Packets/s": row.append(int(fwd_pkts / (duration / 1000000.0)) if duration > 0 else 0)
                elif h == " Bwd Packets/s": row.append(int(bwd_pkts / (duration / 1000000.0)) if duration > 0 else 0)
                elif h == " Min Packet Length": row.append(0)
                elif h == " Max Packet Length": row.append(1500 if label_choice == "DDoS" else 1000)
                elif h == " Packet Length Mean": row.append(int((fwd_len + bwd_len)/(fwd_pkts + bwd_pkts)) if (fwd_pkts + bwd_pkts) > 0 else 0)
                elif h == " Packet Length Std": row.append(random.uniform(0, 100))
                elif h == " Packet Length Variance": row.append(random.uniform(0, 1000))
                elif h == "FIN Flag Count": row.append(0)
                elif h == " SYN Flag Count": row.append(syn_flag)
                elif h == " RST Flag Count": row.append(0)
                elif h == " PSH Flag Count": row.append(0)
                elif h == " ACK Flag Count": row.append(ack_flag)
                elif h == " URG Flag Count": row.append(0)
                elif h == " CWE Flag Count": row.append(0)
                elif h == " ECE Flag Count": row.append(0)
                elif h == " Down/Up Ratio": row.append(round(bwd_pkts / fwd_pkts, 2) if fwd_pkts > 0 else 0)
                elif h == " Average Packet Size": row.append(int((fwd_len + bwd_len)/(fwd_pkts + bwd_pkts)) if (fwd_pkts + bwd_pkts) > 0 else 0)
                elif h == " Avg Fwd Segment Size": row.append(int(fwd_len / fwd_pkts) if fwd_pkts > 0 else 0)
                elif h == " Avg Bwd Segment Size": row.append(int(bwd_len / bwd_pkts) if bwd_pkts > 0 else 0)
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
                elif h == " act_data_pkt_fwd": row.append(fwd_pkts - 1 if fwd_pkts > 0 else 0)
                elif h == " min_seg_size_forward": row.append(20)
                elif h == "Active Mean": row.append(0)
                elif h == " Active Std": row.append(0)
                elif h == " Active Max": row.append(0)
                elif h == " Active Min": row.append(0)
                elif h == "Idle Mean": row.append(0)
                elif h == " Idle Std": row.append(0)
                elif h == " Idle Max": row.append(0)
                elif h == " Idle Min": row.append(0)
                elif h == " Label": row.append(label_choice)
                
            writer.writerow(row)
            
    print(f"Generated 1500 mock CIC-IDS2017 log rows at {filepath}")

if __name__ == '__main__':
    generate_sample()

import pandas as pd
from joblib import load
import os
import time

# Constants for files and stuff 
MODEL_PATH = "anomaly_model.joblib"
LOG_PATH = "packet_log.csv"
ANOMALY_PATH = "anomalies_detected.csv"
BATCH_SIZE = 1000

pipeline = load(MODEL_PATH)
print("STARTING anomaly detection: ")

#function that flags sus packets from other devices on network incase model doesnt detect them
def is_suspicious(pkt):
    if pkt['protocol_name'] == 'ICMP':
        return True
    if pkt['protocol_name'] == 'TCP' and 'S' in pkt['tcp_flags'] and 'A' not in pkt['tcp_flags']:
        return True
    return False

while True:
    try:
        # Wait until the log file exists
        if not os.path.exists(LOG_PATH):
            time.sleep(1)
            continue

        df = pd.read_csv(LOG_PATH)
        if len(df) < BATCH_SIZE:
            time.sleep(1)  # Wait for more data
            continue

        batch = df.iloc[:BATCH_SIZE].copy()

        # Select and clean features
        features = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol_name', 'length', 'tcp_flags']
        batch = batch[features]

        for col in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol_name', 'tcp_flags']:
            batch[col] = batch[col].replace("-", "unknown").fillna("unknown").astype(str)

        for col in ['src_port', 'dst_port', 'length']:
            batch[col] = pd.to_numeric(batch[col], errors='coerce').fillna(-1)

        # Predict anomalies
        preds = pipeline.predict(batch.drop(columns=["timestamp"]))
        batch['anomaly'] = preds

        batch['alert_level'] = batch.apply(
            lambda row: 'ALERT' if row['anomaly'] == -1 or is_suspicious(row) else 'normal',
            axis=1
        )

        # save only alert rows (by model or rule)
        alerts = batch[batch['alert_level'] == 'ALERT']
        if not alerts.empty:
            print(f"🚨 Detected {len(alerts)} alerts.")
            alerts_to_save = alerts.drop(columns=["alert_level"])
            reordered = alerts[['timestamp'] + [col for col in alerts.columns if col != 'timestamp']]
            reordered.to_csv(ANOMALY_PATH, mode='a', index=False, header=not os.path.exists(ANOMALY_PATH))
        else:
            print("No anomalies this cycle.")

        #trim processed entries
        df.iloc[BATCH_SIZE:].to_csv(LOG_PATH, index=False)
    
    #error handling for mismatched formats and stuff, print debugged
    except Exception as e:
        print(f"Unexpected error: {e}")
        try:
            print("Batch causing issue:\n", batch.head(5))
        except:
            print("Failed to print batch due to earlier error.")

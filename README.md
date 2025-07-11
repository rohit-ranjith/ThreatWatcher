This project is a lightweight SIEM I built to learn more about SOC operations as a student.
I got the idea after looking at people online making homelabs using VirtualBox, and I decided to implement this with a sort of SIEM functionality.
I built it using packet logging, machine learning, authentication logs, and ELK Stack visualization. 
It monitors network packets on a Virtual Machine network and detects anomalous packets using an Isolation Forest ML model I trained. 
I also used simple rule-based heuristics (e.g., unusual TCP flags, ICMP pings) to detect unusual traffic from other devices on the network.
The elk stack is used to visualize these packet anomalies in detail along with auth logs from the VM (including alert tags for certain commands like if a user enters a "sudo" command)

(see below for project demo pics)

General Project Structure:
![image](https://github.com/user-attachments/assets/4a5ee7e6-1054-4401-9f66-383a7e9fc732)


VM Setups:
I used VirtualBox to manage the two VMs for this project. They both run on Ubuntu 24.04.

dependencies and python libraries for Logger VM:
scapy: packet capture
pandas: data manipulation and analysis from csv files
scikit-learn: ML model 


Detection functionality explained:
- Logger Script (packet_logger.py) captures live packets using Scapy, extracts features (IP addresses, ports, protocol, TCP flags, etc.), and writes them to a CSV.
- Trainer Script (anomaly_trainer.py):
    Cleans and preprocesses the captured packets.
    Encodes categorical fields and scales numeric ones.
    Trains an Isolation Forest model with 1% contamination.
- Detector Script (anomaly_detector.py):
    Loads batches of new packets in real time.
    Applies the ML model to flag outliers.
    Writes anomalies to anomalies_detected.csv.


To train the model effectively, I generated mixed traffic by:
pinging sites like google, youtube from the logger VM. 
From the attacker VM, I ran commands like, 
   nmap -sS <IP>, 
   ping <IP> -c 5,
   hydra -l root -P passwords.txt ssh://<IP>.
This helped introduce some real anomaly examples to the data.



ELK Stack setup:
I referred to https://portforwarded.com/install-elastic-elk-stack-8-x-on-ubuntu-22-04-lts/) to install Elasticsearch, Logstash, and Kibana manually on the logger VM.
I then configured filebeat.yml to ship the network packet logs (from anomalies_detected.csv) and auth.log from the VM.
My beats.conf handles both types of logs by routing based on a log_type field.

Kibana Setup:
To visualize the logs, I created data views for packet and auth log indices.
In Kibana, I then built dashboards to show anomalous packets by time, IP, ports, size, and protocol.
I also displayed auth log alerts with timestamp filters. Alerts are displayed in real time and are detected by the use of certain keywords in commands entered in the VM (eg: sudo, invalid, failed...etc).


Generating anomalous network traffic/packets:
From the attacker VM I ran variations of commands like nmap, ping, and hydra with the logger VM's IP address, and made sure they were picked up from the packet logger running on the logger VM.


Overall I thought this was a fun way to learn how data flows at the packet level. While making this, I did run into many challenges like fine-tuning the ML model and configuration errors, and I believe I learned a lot by debugging and ssolving these issues as they came about. For this project I kept things simple but extendable if I ever decide to build on top of it. 

ELASTIC (KIBANA) DASHBOARD IMAGES:

Network/Packet logging:
![Image](https://github.com/user-attachments/assets/16001a09-8ea7-4226-9364-cdf1e512d86f)

VM Authentication Logging (The pie chart looks off because it was representative of a very small sample of auth logs):
![Image](https://github.com/user-attachments/assets/58edbc26-81fc-415f-8d73-4f50e511c6ce)

![Image](https://github.com/user-attachments/assets/6315b0c6-f3a5-4bbb-8ac4-9b9f4695c9b9)






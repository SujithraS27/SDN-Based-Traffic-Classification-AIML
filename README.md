# SDN-Based-Traffic-Classification-AIML
SDN-based traffic classification using Mininet, RYU controller, and machine learning to differentiate real-time and bulk flows.
# 5G-Like Traffic Generation Using SDN (Mininet + RYU)

This document records the complete workflow and commands used to generate 5G-like traffic patterns using Mininet, RYU SDN Controller, and iperf3. The goal is to emulate eMBB, URLLC, and mMTC services in a controlled SDN environment.

---

## Step 1: Start the SDN Controller (Control Plane)

The SDN control plane is started using the RYU controller. A Python virtual environment is activated before launching the controller.

**Commands:**
```bash
source ~/ryuenv/bin/activate
ryu-manager ryu.app.simple_switch_13
```

*This initializes the SDN control plane and enables OpenFlow communication between the controller and Open vSwitch.*

---

## Step 2: Create the Mininet Network (Data Plane)

Mininet is used to create the SDN data plane. A tree topology is chosen to emulate a 5G-like core–access network structure.



**Command:**
sudo mn --controller=remote --topo=tree,depth=2,fanout=3 --switch=ovs

**This command:**
* Creates multiple Open vSwitch instances
* Builds a hierarchical topology
* Connects all switches to the remote RYU controller
* Treats hosts as UEs or IoT devices

---

## Step 3: Verify Network Connectivity

Before generating traffic, connectivity between all hosts is verified.

**Command:**
mininet> pingall

**Expected output:**
0% packet loss (Confirms that the SDN topology is correctly configured and stable).

---

## Step 4: Generate eMBB Traffic (High Throughput)

To emulate eMBB (Enhanced Mobile Broadband) traffic, TCP-based high-throughput traffic is generated.

1. Start an iperf3 server on host h1:
   mininet> h1 iperf3 -s &

2. Generate TCP traffic from host h2 to host h1:
   mininet> h2 iperf3 -c h1 -t 20

3. Save and view the output for analysis:
   mininet> h2 iperf3 -c h1 -t 20 > embb.txt
   mininet> h2 cat embb.txt

*This traffic represents 5G eMBB, characterized by sustained high bandwidth usage.*

---

## Step 5: Generate URLLC Traffic (Low Latency)

To emulate URLLC (Ultra-Reliable Low-Latency Communication), UDP traffic with controlled bandwidth is generated.

**Command:**
mininet> h3 iperf3 -u -b 1M -c h1 -t 20

**This traffic characteristics:**
* Uses UDP instead of TCP
* Maintains low latency
* Sends small packets
* Uses controlled bandwidth

---

## Step 6: Generate mMTC Traffic (IoT-Type Communication)

To emulate mMTC (Massive Machine-Type Communication), frequent small packets are generated using ICMP.

**Command:**
mininet> h4 ping h1 -i 0.2 -c 50

**Observed behavior:**
* RTT ≈ 0.05–0.07 ms
* 0% packet loss
* Reflects IoT-style communication with small packet sizes and high frequency.

---

## Traffic Validation Summary

The generated traffic patterns are clearly distinguishable:

| Service Type | Protocol | Characterization |
| :--- | :--- | :--- |
| eMBB | TCP | High-throughput / Large Data Transfer |
| URLLC | UDP | Low-latency / High Reliability |
| mMTC | ICMP | Massive connections / Small frequent packets |

---

## Final Status

**Completed tasks:**
- SDN controller initialized
- Mininet topology created
- Network connectivity verified
- eMBB traffic generated
- URLLC traffic generated
- mMTC traffic generated
- Traffic behavior validated

**Pending tasks:**
- Flow statistics collection
- Dataset creation (CSV)
- Machine learning classification

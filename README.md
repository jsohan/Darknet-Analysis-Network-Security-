# Description
Darknet is a term used to describe a portion of IP addresses that are purposefully unused in a networking system. Because this portion of the network is supposedly unused there should not be any traffic back and forth. By monitoring this section, we can use it as a trap to detect potential probs searching for open IPs and ports that can be used to attack the system such as a DDoS attack. 

This program takes a Pcap file that has been monitoring a daknet trap on a network system and analyses it for potential probs.

#### Probe Types Looked For:
- Horizontal
- Vertical
- Strobe

# Instillation
1.	Download repository and place inside your projects folder for your complier (Visual studio recommended).
2.	Download the [pcap file](https://drive.google.com/open?id=1jWuCKoDL5kHzjsJhS9TyHVh4abY_fflo "Google Drive") (contailing 2 million data packets) we will be using.
3.	Place this pcap file within the “Network” folder. 
..* If using your own pcap file, remember to format the file  as libcap. You can do this by using editcap -F in comand line. This comes with wireshark.
4.	Open the project, build and run it.




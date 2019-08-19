# Description
Darknet is a term used to describe a portion of IP addresses that are purposefully unused in a networking system. Because this portion of the network is supposedly unused there should not be any traffic back and forth. By monitoring this section, we can use it as a trap to detect potential probs searching for open IPs and ports that can be used to attack the system such as a DDoS attack. 

This program takes a Pcap file that has been monitoring a daknet trap on a network system and analyses it for potential probs.

### Probe Types Looked For
- Horizontal
- Vertical
- Strobe


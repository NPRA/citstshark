# citstshark
Helper program to decode cits messages using tshark.
It can also be used to turn hex-encoded c-its messags (with Geonetworking headers) in to pcap-files that can be opened in wireshark.

Requires:
- Python 3
- tshark (for decoding the c-its payload) or wireshark if only used for pcap generation

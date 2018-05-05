import dpkt
import socket 

f = open("sniff.pcapng", mode="rb")
pcap = dpkt.pcapng.Reader(f)

size_sum = 0
first = True
ts_first = 0
ts_last = 0

for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data
	if type(ip) == dpkt.ip.IP and socket.inet_ntoa(ip.src) == "185.37.148.243":
		if first:
			first =False
			ts_first = ts
		size_sum += ip.len
		ts_last=ts

ts_diff = ts_last - ts_first
speed = size_sum/ts_diff


f.close()

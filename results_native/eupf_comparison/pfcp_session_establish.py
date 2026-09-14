#!/usr/bin/env python3
"""PFCP client: plain decap-and-forward FAR (no re-encapsulation),
matching our own prototype's FAR_FORWARD semantics, for a directly
comparable functional test against eUPF."""
import socket, sys, time
from scapy.contrib.pfcp import *

UPF_ADDR = ("127.0.0.1", 8805)

def send_recv(pkt, sock, label):
    sock.sendto(bytes(pkt), UPF_ADDR)
    sock.settimeout(3)
    try:
        data, _ = sock.recvfrom(4096)
        resp = PFCP(data)
        print(f"{label}: response type={resp.message_type}")
        return resp
    except socket.timeout:
        print(f"{label}: TIMEOUT")
        return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    sess_est = PFCP(version=1, S=1, seq=10, seid=0, spare_oct=0) / \
        PFCPSessionEstablishmentRequest(IE_list=[
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(instance="access"),
                ])
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=2),
                IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
                IE_PDI(IE_list=[
                    IE_FTEID(V4=1, TEID=0x00001001, ipv4="10.99.0.1"),
                    IE_NetworkInstance(instance="access"),
                    IE_SourceInterface(interface="Access"),
                ]),
                IE_PDR_Id(id=2),
                IE_Precedence(precedence=100)
            ]),
            IE_FSEID(v4=1, seid=0x2, ipv4="127.0.0.1"),
            IE_NodeId(id_type="FQDN", id="test-smf")
        ])
    send_recv(sess_est, sock, "SessionEstablishmentRequest(plain-forward)")
    sock.close()

if __name__ == "__main__":
    main()

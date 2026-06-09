import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END   = 1
TYPE_DATA  = 2
TYPE_ACK   = 3

HEADER_SIZE = 16
MAX_PAYLOAD = 1472 - HEADER_SIZE


def make_ack(seq_num: int) -> bytes:
    hdr = PacketHeader(type=TYPE_ACK, seq_num=seq_num, length=0)
    hdr.checksum = compute_checksum(hdr / b"")
    return bytes(hdr / b"")


def parse_packet(raw: bytes):
    if len(raw) < HEADER_SIZE:
        return None
    hdr = PacketHeader(raw[:HEADER_SIZE])
    payload = raw[HEADER_SIZE: HEADER_SIZE + hdr.length]
    saved = hdr.checksum
    hdr.checksum = 0
    if compute_checksum(hdr / payload) != saved:
        return None
    return hdr.type, hdr.seq_num, payload


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    # ---------- STATE: START ----------
    while True:
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)
        if parsed and parsed[0] == TYPE_START:
            s.sendto(make_ack(seq_num=1), sender_addr)
            break

    # ---------- STATE: DATA ----------
    next_expected = 1
    received_data = bytearray()  

    while True:
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)

        if parsed is None:
            continue

        pkt_type, seq_num, payload = parsed

        if pkt_type == TYPE_END:
            s.sendto(make_ack(seq_num=seq_num + 1), sender_addr)
            break

        if pkt_type != TYPE_DATA:
            continue

        if seq_num == next_expected:
            received_data.extend(payload)
            next_expected += 1
        s.sendto(make_ack(seq_num=next_expected), sender_addr)

    # ---------- OUTPUT ----------
    sys.stdout.buffer.write(received_data)
    sys.stdout.buffer.flush()

    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()

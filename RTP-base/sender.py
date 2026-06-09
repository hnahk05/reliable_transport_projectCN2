import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END   = 1
TYPE_DATA  = 2
TYPE_ACK   = 3

HEADER_SIZE = 16 
MAX_PAYLOAD = 1472 - HEADER_SIZE 


def make_packet(pkt_type: int, seq_num: int, payload: bytes = b"") -> bytes:
    hdr = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(payload))
    hdr.checksum = compute_checksum(hdr / payload)
    return bytes(hdr / payload)


def parse_packet(raw: bytes):
    """Trả về (type, seq_num) hoặc None nếu checksum sai."""
    if len(raw) < HEADER_SIZE:
        return None
    hdr = PacketHeader(raw[:HEADER_SIZE])
    payload = raw[HEADER_SIZE: HEADER_SIZE + hdr.length]

    saved = hdr.checksum
    hdr.checksum = 0
    if compute_checksum(hdr / payload) != saved:
        return None
    return hdr.type, hdr.seq_num, payload


def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    dest = (receiver_ip, receiver_port)

    TIMEOUT = 0.5  

    # ---------- STATE: START ----------
    start_pkt = make_packet(TYPE_START, seq_num=0)
    s.sendto(start_pkt, dest)
    deadline = time.time() + TIMEOUT

    while True:
        now = time.time()
        if now >= deadline:
            s.sendto(start_pkt, dest)
            deadline = now + TIMEOUT
        ready = select.select([s], [], [], max(0, deadline - time.time()))
        if not ready[0]:
            continue
        try:
            raw, _ = s.recvfrom(2048)
        except BlockingIOError:
            continue
        parsed = parse_packet(raw)
        if parsed and parsed[0] == TYPE_ACK and parsed[1] == 1:
            break   

    # ---------- STATE: DATA ----------
    chunks = []
    while True:
        chunk = sys.stdin.buffer.read(MAX_PAYLOAD)
        if not chunk:
            break
        chunks.append(chunk)

    total = len(chunks)
    base = 1 
    next_send = 1 
    timer_start = None 

    def chunk_of(seq):
        return chunks[seq - 1]

    def send_pkt(seq):
        pkt = make_packet(TYPE_DATA, seq_num=seq, payload=chunk_of(seq))
        s.sendto(pkt, dest)

    def fill_window():
        nonlocal next_send
        while next_send <= total and next_send < base + window_size:
            send_pkt(next_send)
            next_send += 1

    fill_window()
    if base <= total:
        timer_start = time.time()

    while base <= total:
        if timer_start and time.time() - timer_start >= TIMEOUT:
            for seq in range(base, next_send):
                send_pkt(seq)
            timer_start = time.time()

        wait = max(0, TIMEOUT - (time.time() - (timer_start or time.time())))
        ready = select.select([s], [], [], min(0.05, wait))
        if not ready[0]:
            continue

        try:
            raw, _ = s.recvfrom(2048)
        except BlockingIOError:
            continue

        parsed = parse_packet(raw)
        if not parsed or parsed[0] != TYPE_ACK:
            continue

        ack_seq = parsed[1]
        if base < ack_seq <= total + 1:
            base = ack_seq 
            fill_window()
            timer_start = time.time() if base <= total else None

    # ---------- STATE: END ----------
    end_seq = total + 1
    end_pkt = make_packet(TYPE_END, seq_num=end_seq)
    s.sendto(end_pkt, dest)
    deadline = time.time() + TIMEOUT

    while True:
        now = time.time()
        if now >= deadline:
            break
        ready = select.select([s], [], [], max(0, deadline - now))
        if not ready[0]:
            break
        try:
            raw, _ = s.recvfrom(2048)
        except BlockingIOError:
            continue
        parsed = parse_packet(raw)
        if parsed and parsed[0] == TYPE_ACK and parsed[1] == end_seq + 1:
            break

    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()

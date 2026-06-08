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
MAX_PAYLOAD = 1472 - HEADER_SIZE  # 1456 bytes


def make_packet(pkt_type: int, seq_num: int, payload: bytes = b"") -> bytes:
    hdr = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(payload))
    hdr.checksum = compute_checksum(hdr / payload)
    return bytes(hdr / payload)


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


def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    dest = (receiver_ip, receiver_port)
    TIMEOUT = 0.5

    # ---------- START ----------
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

    # ---------- DATA ----------
    chunks = []
    while True:
        chunk = sys.stdin.buffer.read(MAX_PAYLOAD)
        if not chunk:
            break
        chunks.append(chunk)

    total = len(chunks)
    # window: {seq_num: {"sent_time": float, "acked": bool}}
    window = {}
    base = 1
    next_send = 1
    timer_start = time.time()

    def send_pkt(seq):
        pkt = make_packet(TYPE_DATA, seq_num=seq, payload=chunks[seq - 1])
        s.sendto(pkt, dest)
        if seq in window:
            window[seq]["sent_time"] = time.time()
        else:
            window[seq] = {"sent_time": time.time(), "acked": False}

    # Gửi window đầu tiên
    while next_send <= min(base + window_size - 1, total):
        send_pkt(next_send)
        next_send += 1

    while base <= total:
        # Kiểm tra timeout 500ms — chỉ gửi lại gói chưa ACK (Selective Repeat)
        if time.time() - timer_start >= TIMEOUT:
            for seq, entry in window.items():
                if not entry["acked"]:
                    send_pkt(seq)
            timer_start = time.time()

        ready = select.select([s], [], [], 0.05)
        if not ready[0]:
            continue

        try:
            raw, _ = s.recvfrom(2048)
        except BlockingIOError:
            continue

        parsed = parse_packet(raw)
        if not parsed or parsed[0] != TYPE_ACK:
            continue

        ack_seq = parsed[1]  # individual ACK: ack_seq = seq của gói được xác nhận

        if ack_seq in window:
            window[ack_seq]["acked"] = True

        # Trượt base qua các gói liên tiếp đã ACK
        advanced = False
        while base in window and window[base]["acked"]:
            del window[base]
            base += 1
            advanced = True

        if advanced:
            timer_start = time.time()
            # Gửi thêm gói mới vào window
            while next_send <= min(base + window_size - 1, total):
                send_pkt(next_send)
                next_send += 1

    # ---------- END ----------
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
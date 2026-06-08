import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Packet types theo spec
TYPE_START = 0
TYPE_END   = 1
TYPE_DATA  = 2
TYPE_ACK   = 3

HEADER_SIZE = 16      # 4 x IntField
MAX_PAYLOAD = 1472 - HEADER_SIZE  # = 1456 bytes


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

    TIMEOUT = 0.5   # 500ms theo spec

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
            break   # START ACK nhận được (seq_num=1 theo spec)

    # ---------- STATE: DATA ----------
    # Đọc hết stdin thành chunks
    chunks = []
    while True:
        chunk = sys.stdin.buffer.read(MAX_PAYLOAD)
        if not chunk:
            break
        chunks.append(chunk)

    # seq_num của DATA bắt đầu từ 1
    total = len(chunks)
    base = 1            # seq_num nhỏ nhất chưa ACK
    next_send = 1       # seq_num tiếp theo sẽ gửi
    sent_time = {}      # seq_num -> thời điểm gửi gần nhất
    timer_start = None  # thời điểm bắt đầu đếm 500ms

    def chunk_of(seq):
        return chunks[seq - 1]

    def send_pkt(seq):
        pkt = make_packet(TYPE_DATA, seq_num=seq, payload=chunk_of(seq))
        s.sendto(pkt, dest)
        sent_time[seq] = time.time()

    # Gửi window đầu tiên
    while next_send <= min(base + window_size - 1, total):
        send_pkt(next_send)
        next_send += 1
    if base <= total:
        timer_start = time.time()

    while base <= total:
        # Kiểm tra timeout 500ms: nếu window không tiến thêm
        if timer_start and time.time() - timer_start >= TIMEOUT:
            # Retransmit tất cả gói trong window (Go-Back-N style theo spec base)
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
        if ack_seq > base:
            base = ack_seq          # cumulative ACK
            timer_start = time.time()   # reset timer khi window tiến
            # Gửi thêm gói mới vào window
            while next_send <= min(base + window_size - 1, total):
                send_pkt(next_send)
                next_send += 1

    # ---------- STATE: END ----------
    end_seq = total + 1   # seq_num của END = next sau DATA cuối
    end_pkt = make_packet(TYPE_END, seq_num=end_seq)
    s.sendto(end_pkt, dest)
    deadline = time.time() + TIMEOUT

    while True:
        now = time.time()
        if now >= deadline:
            break   # 500ms trôi qua, thoát dù chưa nhận ACK (theo spec)
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
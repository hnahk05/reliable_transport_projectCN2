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

    # start
    while True:
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)
        if parsed and parsed[0] == TYPE_START:
            # ACK của START có seq_num=1 theo spec
            s.sendto(make_ack(seq_num=1), sender_addr)
            break

    # data
    # next_expected bắt đầu từ 1 (DATA seq bắt đầu từ 1)
    next_expected = 1
    buffer = {}         # {seq_num: payload} — lưu gói lệch thứ tự
    received_data = {}  # {seq_num: payload} — tất cả data đã nhận

    while True:
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)

        if parsed is None:
            # Checksum sai, bỏ qua, k gửi ACK
            continue

        pkt_type, seq_num, payload = parsed

        if pkt_type == TYPE_END:
            # Gửi ACK cho END rồi thoát
            s.sendto(make_ack(seq_num=seq_num + 1), sender_addr)
            break

        if pkt_type != TYPE_DATA:
            continue

        # Drop nếu ngoài cửa sổ nhận
        if seq_num >= next_expected + window_size:
            continue

        # Buffer gói này nếu chưa có
        if seq_num not in received_data:
            received_data[seq_num] = payload
            buffer[seq_num] = payload

        # Trượt next_expected qua các gói liên tiếp đã có
        while next_expected in buffer:
            next_expected += 1

        # Gửi cumulative ACK (next_expected là seq tiếp theo mong chờ)
        s.sendto(make_ack(seq_num=next_expected), sender_addr)

    # Ghi data theo thứ tự seq_num
    for seq in sorted(received_data.keys()):
        sys.stdout.buffer.write(received_data[seq])
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
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum
# tín hiệu bdau kết nối
TYPE_START = 0
# tín hiệu kthuc kết nối
TYPE_END   = 1
# gói data
TYPE_DATA  = 2
# gói ACK
TYPE_ACK   = 3

HEADER_SIZE = 16
MAX_PAYLOAD = 1472 - HEADER_SIZE


def make_ack(seq_num: int) -> bytes:
    # tạo gói tin ack, tính checksum, đóng gói thành bytes
    hdr = PacketHeader(type=TYPE_ACK, seq_num=seq_num, length=0)
    hdr.checksum = compute_checksum(hdr / b"")
    return bytes(hdr / b"")


def parse_packet(raw: bytes):
    # nếu raw bytes ngắn hơn header size thì bỏ qua
    if len(raw) < HEADER_SIZE:
        return None
    # đọc header
    hdr = PacketHeader(raw[:HEADER_SIZE])
    # đọc payload
    payload = raw[HEADER_SIZE: HEADER_SIZE + hdr.length]
    saved = hdr.checksum
    hdr.checksum = 0
    if compute_checksum(hdr / payload) != saved:
        return None
    return hdr.type, hdr.seq_num, payload


def receiver(receiver_ip, receiver_port, window_size):
    # tạo socket UDP và mở địa chỉ port nhận
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    # start
    while True:
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)
        if parsed and parsed[0] == TYPE_START:
            s.sendto(make_ack(seq_num=1), sender_addr)
            break

    # data
    next_expected = 1
    buffer = {}       # {seq_num: payload} — gói lệch thứ tự
    received = {}     # {seq_num: payload} — tất cả gói đã nhận

    while True:
        # đọc gói mới
        raw, sender_addr = s.recvfrom(2048)
        parsed = parse_packet(raw)

        if parsed is None:
            continue  # checksum sai, bỏ qua

        pkt_type, seq_num, payload = parsed

        if pkt_type == TYPE_END:
            # gửi ack cho gói thứ seq_num+1, tức là nhận được đến gói thứ seq_num rồi và kết thúc
            s.sendto(make_ack(seq_num=seq_num + 1), sender_addr)
            break

        if pkt_type != TYPE_DATA:
            continue

        # Drop nếu ngoài cửa sổ nhận vì buffer k đủ lớn để chứa
        if seq_num >= next_expected + window_size:
            continue

        # Bỏ qua duplicate
        if seq_num in received:
            # Vẫn gửi lại ACK để sender không bị treo
            s.sendto(make_ack(seq_num=seq_num), sender_addr)
            continue

        # Lưu gói
        received[seq_num] = payload
        buffer[seq_num] = payload

        # Trượt next_expected
        while next_expected in buffer:
            next_expected += 1

        # Individual ACK: ack_num = seq của gói vừa nhận (không phải next_expected)
        s.sendto(make_ack(seq_num=seq_num), sender_addr)

    # output
    for seq in sorted(received.keys()):
        #ghi data theo dict seq_num:payload 
        sys.stdout.buffer.write(received[seq])
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
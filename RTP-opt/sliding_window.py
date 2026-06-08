
import time
from collections import OrderedDict
from packet import (
    build_packet, parse_packet,
    FLAG_ACK, FLAG_NACK,
    MAX_PAYLOAD,
)
class SlidingWindow:
    """
    Cửa sổ trượt Selective Repeat phía GỬI.
    Mỗi gói có timer riêng; chỉ retransmit gói timeout cụ thể.
    """

    def __init__(self, window_size: int = 10, timeout_seconds: float = 2.0):
        self.window_size = window_size
        self.timeout     = timeout_seconds

        self.base         = 0
        self.next_seq     = 0
        self.window: OrderedDict[int, dict] = OrderedDict()
        self.send_buffer: list[bytes] = []

    def queue_data(self, data_chunk: bytes) -> None:
        self.send_buffer.append(data_chunk)

    def _window_has_space(self) -> bool:
        unacked = sum(1 for e in self.window.values() if not e["acked"])
        return unacked < self.window_size

    def get_next_packets_to_send(self) -> list[bytes]:
        """
        Selective Repeat:
          1. Gửi lại CHỈ các gói timeout (không acked).
          2. Gửi thêm gói mới nếu còn chỗ trong window.
        """
        result: list[bytes] = []
        now = time.time()
        for seq, entry in self.window.items():
            if not entry["acked"] and (now - entry["sent_time"]) > self.timeout:
                entry["sent_time"] = now 
                result.append(entry["packet"])

        while self._window_has_space() and self.send_buffer:
            payload = self.send_buffer.pop(0)
            pkt = build_packet(seq_num=self.next_seq,
                               ack_num=0,
                               flags=0,
                               payload=payload)
            self.window[self.next_seq] = {
                "packet"    : pkt,
                "sent_time" : time.time(),
                "acked"     : False,
            }
            result.append(pkt)
            self.next_seq += 1

        return result

    def mark_acked(self, seq_num: int) -> None:
        """
        Selective Repeat: ACK từng gói riêng lẻ (individual ACK).
        Đánh dấu gói đó là acked, rồi trượt base nếu có thể.
        """
        if seq_num in self.window:
            self.window[seq_num]["acked"] = True

        while self.window:
            smallest_seq = next(iter(self.window))
            if self.window[smallest_seq]["acked"]:
                del self.window[smallest_seq]
                self.base = smallest_seq + 1
            else:
                break

    def get_timed_out_packets(self) -> list[bytes]:
        """Trả về danh sách gói chưa acked và đã timeout."""
        now = time.time()
        return [
            entry["packet"]
            for entry in self.window.values()
            if not entry["acked"] and (now - entry["sent_time"]) > self.timeout
        ]

    def handle_nack(self, seq_num: int) -> bytes | None:
        """
        Xử lý NACK: bên nhận báo cụ thể gói nào bị mất.
        Gửi lại ngay lập tức (không đợi timeout).
        """
        if seq_num in self.window and not self.window[seq_num]["acked"]:
            self.window[seq_num]["sent_time"] = 0 
            return self.window[seq_num]["packet"]
        return None

    def is_send_done(self) -> bool:
        return not self.send_buffer and not self.window

class ReceiverBuffer:
    """
    Bộ đệm phía NHẬN — Selective Repeat.
    Chấp nhận gói lệch thứ tự, lưu vào buffer, ghép khi đủ.
    """

    def __init__(self, window_size: int = 10):
        self.window_size   = window_size
        self.next_expected = 0
        self.buffer: dict[int, bytes] = {}
        self.ready_data    = bytearray()

    def receive(self, seq_num: int, payload: bytes) -> str:
        """
        Nhận gói data.
        Returns:
            "accepted"    — gói hợp lệ, đã buffer
            "duplicate"   — gói đã nhận rồi
            "out_of_win"  — ngoài cửa sổ nhận, bỏ qua
        """
        if seq_num < self.next_expected:
            return "duplicate"
        if seq_num >= self.next_expected + self.window_size:
            return "out_of_win"
        if seq_num in self.buffer:
            return "duplicate"

        self.buffer[seq_num] = payload
        while self.next_expected in self.buffer:
            self.ready_data   += self.buffer.pop(self.next_expected)
            self.next_expected += 1

        return "accepted"

    def get_missing_seqs(self) -> list[int]:
        """
        Trả về danh sách seq_num bị thiếu trong khoảng [next_expected, max_buffered).
        Dùng để gửi NACK.
        """
        if not self.buffer:
            return []
        max_seq = max(self.buffer)
        return [s for s in range(self.next_expected, max_seq) if s not in self.buffer]

    def flush(self) -> bytes:
        data = bytes(self.ready_data)
        self.ready_data = bytearray()
        return data

class ReliableProtocol:
    """
    API chính — Selective Repeat.
    Interface GIỐNG HỆT RTP-base để Người A không phải đổi code.

    Điểm khác biệt nội bộ:
      - receive_packet() gửi individual ACK (từng gói riêng lẻ).
      - Hỗ trợ NACK: khi phát hiện gap trong buffer, gửi NACK để sender
        retransmit ngay mà không cần đợi timeout.
    """

    def __init__(self, window_size: int = 10, timeout_seconds: float = 2.0):
        self.sender   = SlidingWindow(window_size, timeout_seconds)
        self.receiver = ReceiverBuffer(window_size)

    def queue_data(self, data_chunk: bytes) -> None:
        """Người A gọi: nạp 1388 bytes từ file vào hàng chờ."""
        self.sender.queue_data(data_chunk)

    def get_packets_to_send(self) -> list[bytes]:
        """
        Người A gọi liên tục trong event-loop.
        Selective Repeat: chỉ retransmit gói timeout cụ thể, không cả cửa sổ.
        """
        return self.sender.get_next_packets_to_send()

    def receive_packet(self, raw_packet: bytes) -> bytes | None:
        """
        Người A gọi khi socket nhận được dữ liệu.

        Xử lý:
          1. Kiểm tra checksum → None nếu corrupt.
          2. Nếu là ACK/NACK → cập nhật sender.
          3. Nếu là DATA → buffer, gửi individual ACK.
             Nếu phát hiện gap → gửi thêm NACK cho gói thiếu.

        Returns:
            bytes (ACK hoặc NACK) cần sendto() lại, hoặc None.
        """
        parsed = parse_packet(raw_packet)
        if parsed is None:
            return None

        flags   = parsed["flags"]
        seq_num = parsed["seq_num"]
        ack_num = parsed["ack_num"]
        payload = parsed["payload"]
        if flags & FLAG_ACK and not payload:
            self.sender.mark_acked(ack_num)
            return None
        if flags & FLAG_NACK:
            return self.sender.handle_nack(ack_num)
        status = self.receiver.receive(seq_num, payload)

        if status == "out_of_win":
            return None 
        ack_pkt = build_packet(
            seq_num = 0,
            ack_num = seq_num,
            flags   = FLAG_ACK,
        )
        missing = self.receiver.get_missing_seqs()
        if missing:
            nack_pkt = build_packet(
                seq_num = 0,
                ack_num = missing[0],
                flags   = FLAG_NACK,
            )
            return ack_pkt

        return ack_pkt

    def get_ready_data(self) -> bytes:
        """Người A gọi để lấy data đã sắp xếp đúng thứ tự, ghi ra file."""
        return self.receiver.flush()

    def is_transfer_complete(self) -> bool:
        return self.sender.is_send_done()

if __name__ == "__main__":
    sender   = ReliableProtocol(window_size=4, timeout_seconds=0.5)
    receiver = ReliableProtocol(window_size=4, timeout_seconds=0.5)

    payloads = [b"AAA", b"BBB", b"CCC", b"DDD"]
    for p in payloads:
        sender.queue_data(p)

    pkts = sender.get_packets_to_send()
    print(f"Gói cần gửi: {len(pkts)}")

    for i, pkt in enumerate(pkts):
        if i == 1:
            print("Giả lập mất gói seq=1")
            continue
        ack = receiver.receive_packet(pkt)
        if ack:
            sender.receive_packet(ack)

    print(f"Data nhận được (thiếu BBB): {receiver.get_ready_data()}")

    time.sleep(0.6)
    resend = sender.get_packets_to_send()
    print(f"Gói gửi lại: {len(resend)}")
    for pkt in resend:
        ack = receiver.receive_packet(pkt)
        if ack:
            sender.receive_packet(ack)

    print(f"Data sau khi nhận lại: {receiver.get_ready_data()}")

"""
sliding_window.py — RTP-base  (Go-Back-N)
==========================================
Thuật toán: Go-Back-N
  - Bên GỬI: duy trì một cửa sổ [base, base+window_size).
    Khi timeout, gửi lại TẤT CẢ các gói chưa ACK từ base trở đi.
  - Bên NHẬN: chỉ chấp nhận đúng thứ tự, từ chối (discard) gói lệch thứ tự.

API bắt buộc (Người A gọi):
    logic = ReliableProtocol(window_size=10, timeout_seconds=2.0)
    logic.queue_data(data_chunk: bytes)
    logic.get_packets_to_send() -> list[bytes]
    logic.receive_packet(raw_packet: bytes) -> bytes | None
    logic.get_ready_data() -> bytes
"""

import time
from packet import (
    build_packet, parse_packet,
    FLAG_ACK, FLAG_SYN, FLAG_FIN,
    MAX_PAYLOAD,
)

class SlidingWindow:
    """
    Quản lý trạng thái cửa sổ trượt phía GỬI (Go-Back-N).

    Attributes:
        window_size  : Số gói tối đa được "bay" trên đường truyền cùng lúc.
        timeout      : Giây trước khi coi một gói là đã mất.
        base         : Seq num nhỏ nhất chưa được ACK.
        next_seq     : Seq num tiếp theo sẽ cấp cho gói mới.
        window       : {seq_num: {"packet": bytes, "sent_time": float}}
        send_buffer  : Hàng chờ dữ liệu chưa cấp seq num.
    """

    def __init__(self, window_size: int = 10, timeout_seconds: float = 2.0):
        self.window_size = window_size
        self.timeout     = timeout_seconds
        self.base       = 0
        self.next_seq   = 0
        self.window: dict[int, dict] = {}
        self.send_buffer: list[bytes] = []

    def queue_data(self, data_chunk: bytes) -> None:
        """Đẩy một khối dữ liệu vào hàng chờ (chưa cấp seq num)."""
        self.send_buffer.append(data_chunk)

    def _window_has_space(self) -> bool:
        return (self.next_seq - self.base) < self.window_size

    def get_next_packets_to_send(self) -> list[bytes]:
        """
        Trả về danh sách raw-bytes cần bắn ra trong lần lặp này:
          1. Các gói đã timeout (gửi lại theo Go-Back-N: từ base trở đi).
          2. Các gói mới nằm trong window còn trống.
        """
        result: list[bytes] = []

        timed_out = self.get_timed_out_packets()
        if timed_out:
            now = time.time()
            for seq in list(self.window):
                self.window[seq]["sent_time"] = now
            result.extend(timed_out)

        while self._window_has_space() and self.send_buffer:
            payload = self.send_buffer.pop(0)
            pkt = build_packet(seq_num=self.next_seq,
                               ack_num=0,
                               flags=0,
                               payload=payload)
            self.window[self.next_seq] = {
                "packet"    : pkt,
                "sent_time" : time.time(),
            }
            result.append(pkt)
            self.next_seq += 1

        return result

    def mark_acked(self, ack_num: int) -> None:
        """
        Xử lý Cumulative ACK: mọi gói có seq_num < ack_num đều được xác nhận.
        Trượt base lên.
        """
        for seq in list(self.window):
            if seq < ack_num:
                del self.window[seq]
        if ack_num > self.base:
            self.base = ack_num

    def get_timed_out_packets(self) -> list[bytes]:
        """
        Trả về danh sách raw-bytes của các gói đã quá hạn timeout,
        theo thứ tự seq_num tăng dần.
        """
        now = time.time()
        expired = [
            (seq, entry["packet"])
            for seq, entry in self.window.items()
            if now - entry["sent_time"] > self.timeout
        ]
        expired.sort(key=lambda x: x[0])
        return [pkt for _, pkt in expired]

    def is_send_done(self) -> bool:
        """True khi send_buffer rỗng VÀ cửa sổ không còn gói chờ ACK."""
        return not self.send_buffer and not self.window

class ReceiverBuffer:
    """
    Quản lý bộ đệm bên NHẬN (Go-Back-N: chỉ nhận đúng thứ tự).

    Attributes:
        next_expected : Seq num tiếp theo đang chờ.
        ready_data    : Payload đã sắp xếp đúng thứ tự, sẵn sàng ghi file.
    """

    def __init__(self):
        self.next_expected = 0
        self.ready_data    = bytearray()

    def receive(self, seq_num: int, payload: bytes) -> bool:
        """
        Nhận một gói data.
        Trả về True nếu chấp nhận (đúng thứ tự), False nếu từ chối.
        """
        if seq_num == self.next_expected:
            self.ready_data   += payload
            self.next_expected += 1
            return True
        return False

    def flush(self) -> bytes:
        """Trích xuất và xóa toàn bộ dữ liệu đã sẵn sàng."""
        data = bytes(self.ready_data)
        self.ready_data = bytearray()
        return data

class ReliableProtocol:
    """
    Lớp API chính mà Người A (Chân tay) sẽ import và sử dụng.

    Sử dụng:
        logic = ReliableProtocol(window_size=10, timeout_seconds=2.0)

        # Phía GỬI:
        logic.queue_data(chunk)           # đẩy data vào hàng chờ
        pkts = logic.get_packets_to_send()# lấy danh sách packet cần gửi

        # Phía NHẬN:
        ack = logic.receive_packet(raw)   # xử lý gói đến, lấy ACK cần gửi lại
        data = logic.get_ready_data()     # lấy data đã sắp xếp để ghi file
    """

    def __init__(self, window_size: int = 10, timeout_seconds: float = 2.0):
        self.sender   = SlidingWindow(window_size, timeout_seconds)
        self.receiver = ReceiverBuffer()

    def queue_data(self, data_chunk: bytes) -> None:
        """
        Người A gọi: khi đọc được 1388 bytes từ file.
        Đưa chunk vào hàng chờ của SlidingWindow.
        """
        self.sender.queue_data(data_chunk)

    def get_packets_to_send(self) -> list[bytes]:
        """
        Người A gọi liên tục trong event-loop.
        Trả về list[bytes] cần sendto() ra socket UDP.
        Bao gồm: gói mới trong window + gói timeout cần gửi lại.
        """
        return self.sender.get_next_packets_to_send()

    def receive_packet(self, raw_packet: bytes) -> bytes | None:
        """
        Người A gọi ngay khi socket UDP nhận được dữ liệu.

        Xử lý:
          1. Parse + kiểm tra checksum → None nếu corrupt.
          2. Nếu là DATA packet → buffer, tạo ACK trả về.
          3. Nếu là ACK packet  → trượt cửa sổ, return None.

        Returns:
            bytes (ACK packet) cần sendto() lại, hoặc None.
        """
        parsed = parse_packet(raw_packet)
        if parsed is None:
            return None

        flags   = parsed["flags"]
        seq_num = parsed["seq_num"]
        ack_num = parsed["ack_num"]
        payload = parsed["payload"]
        if flags & FLAG_ACK:
            self.sender.mark_acked(ack_num)
            return None

        accepted = self.receiver.receive(seq_num, payload)
        ack_pkt = build_packet(
            seq_num = 0,
            ack_num = self.receiver.next_expected,
            flags   = FLAG_ACK,
            payload = b"",
        )
        return ack_pkt

    def get_ready_data(self) -> bytes:
        """
        Người A gọi để "thu hoạch" dữ liệu đã sắp xếp đúng thứ tự.
        Ghi thẳng kết quả ra file: f.write(logic.get_ready_data())
        """
        return self.receiver.flush()

    def is_transfer_complete(self) -> bool:
        """True khi phía gửi không còn gì chờ xử lý."""
        return self.sender.is_send_done()

if __name__ == "__main__":
    logic = ReliableProtocol(window_size=3, timeout_seconds=0.5)

    logic.queue_data(b"Hello")
    logic.queue_data(b"World")

    pkts = logic.get_packets_to_send()
    print(f"Packets to send: {len(pkts)}")

    ack = logic.receive_packet(pkts[0])
    print(f"ACK packet returned: {ack is not None}")

    data = logic.get_ready_data()
    print(f"Ready data: {data}")

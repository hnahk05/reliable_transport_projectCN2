"""
test_sliding_window.py — RTP-base
===================================
Unit Test cho SlidingWindow (Go-Back-N) và ReliableProtocol.
Chạy: python test_sliding_window.py   hoặc   python -m pytest test_sliding_window.py -v

KHÔNG cần mạng, KHÔNG cần socket.
Dùng "gói tin giả" (dict/bytes) để kiểm tra thuật toán.
"""

import time
import unittest
from packet import (
    build_packet, parse_packet,
    calculate_checksum,
    FLAG_ACK, FLAG_SYN, FLAG_FIN,
    HEADER_SIZE, MAX_PAYLOAD,
)
from sliding_window import SlidingWindow, ReceiverBuffer, ReliableProtocol

class TestPacket(unittest.TestCase):
    """Kiểm tra tầng đóng/giải gói và checksum."""

    def test_build_and_parse_roundtrip(self):
        """Build rồi parse lại phải cho kết quả đúng."""
        payload = b"Hello RTP!"
        pkt = build_packet(seq_num=42, ack_num=7, flags=FLAG_ACK, payload=payload)
        parsed = parse_packet(pkt)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["seq_num"],  42)
        self.assertEqual(parsed["ack_num"],  7)
        self.assertEqual(parsed["flags"],    FLAG_ACK)
        self.assertEqual(parsed["payload"],  payload)

    def test_parse_corrupt_packet_returns_none(self):
        """Packet bị lỗi 1 byte → parse_packet phải trả None."""
        pkt = build_packet(seq_num=1, ack_num=0, flags=0, payload=b"data")
        corrupt = bytearray(pkt)
        corrupt[HEADER_SIZE] ^= 0xFF
        self.assertIsNone(parse_packet(bytes(corrupt)))

    def test_parse_too_short_returns_none(self):
        """Packet ngắn hơn header → parse_packet trả None."""
        self.assertIsNone(parse_packet(b"\x00" * 5))

    def test_payload_size_limit(self):
        """Payload vượt MAX_PAYLOAD → ValueError."""
        with self.assertRaises(ValueError):
            build_packet(0, 0, 0, payload=b"x" * (MAX_PAYLOAD + 1))

    def test_empty_payload(self):
        """Packet không có payload (dùng cho ACK)."""
        pkt = build_packet(seq_num=0, ack_num=5, flags=FLAG_ACK)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["payload"], b"")

    def test_checksum_correctness(self):
        """Checksum tính đi tính lại phải nhất quán."""
        data = b"test checksum data"
        c1 = calculate_checksum(data)
        c2 = calculate_checksum(data)
        self.assertEqual(c1, c2)

class TestSlidingWindowSender(unittest.TestCase):
    """Kiểm tra logic cửa sổ phía GỬI."""

    def setUp(self):
        self.sw = SlidingWindow(window_size=4, timeout_seconds=1.0)

    def test_queue_and_send_within_window(self):
        """queue 3 chunk → get_next_packets_to_send → phải ra đúng 3 gói."""
        self.sw.queue_data(b"chunk1")
        self.sw.queue_data(b"chunk2")
        self.sw.queue_data(b"chunk3")

        pkts = self.sw.get_next_packets_to_send()
        self.assertEqual(len(pkts), 3)
        for pkt in pkts:
            self.assertIsNotNone(parse_packet(pkt))

    def test_window_blocks_excess_packets(self):
        """Queue 6 gói với window_size=4 → chỉ gửi được 4 trong lần đầu."""
        for i in range(6):
            self.sw.queue_data(f"chunk{i}".encode())

        pkts = self.sw.get_next_packets_to_send()
        self.assertEqual(len(pkts), 4)
        self.assertEqual(len(self.sw.send_buffer), 2)

    def test_ack_slides_window(self):
        """ACK gói 0 → base trượt lên 1, có chỗ trống để gửi thêm."""
        for i in range(4):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.queue_data(b"extra")

        pkts = self.sw.get_next_packets_to_send()
        self.assertEqual(len(pkts), 0)

        self.sw.mark_acked(ack_num=1)
        self.assertEqual(self.sw.base, 1)

        pkts = self.sw.get_next_packets_to_send()
        self.assertEqual(len(pkts), 1)

    def test_cumulative_ack_slides_multiple(self):
        """ACK số lớn → xác nhận nhiều gói cùng lúc."""
        for i in range(4):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.mark_acked(ack_num=3)
        self.assertEqual(self.sw.base, 3)
        self.assertEqual(len(self.sw.window), 1)

    def test_timeout_detection(self):
        """Gói đã gửi và quá hạn timeout → get_timed_out_packets trả về nó."""
        self.sw.timeout = 0.05
        self.sw.queue_data(b"data")
        self.sw.get_next_packets_to_send()

        self.assertEqual(len(self.sw.get_timed_out_packets()), 0)

        time.sleep(0.1)

        timed_out = self.sw.get_timed_out_packets()
        self.assertEqual(len(timed_out), 1)
        self.assertIsNotNone(parse_packet(timed_out[0]))

    def test_no_timeout_before_deadline(self):
        """Gói chưa quá hạn → không được báo timeout."""
        self.sw.timeout = 5.0 
        self.sw.queue_data(b"data")
        self.sw.get_next_packets_to_send()
        self.assertEqual(len(self.sw.get_timed_out_packets()), 0)

    def test_is_send_done_when_all_acked(self):
        """is_send_done() True khi buffer rỗng và window rỗng."""
        self.sw.queue_data(b"data")
        self.sw.get_next_packets_to_send()

        self.assertFalse(self.sw.is_send_done())

        self.sw.mark_acked(ack_num=1)
        self.assertTrue(self.sw.is_send_done())

    def test_seq_numbers_are_incremental(self):
        """Các gói phải được cấp seq_num tăng dần từ 0."""
        for i in range(3):
            self.sw.queue_data(f"d{i}".encode())
        pkts = self.sw.get_next_packets_to_send()

        for expected_seq, pkt in enumerate(pkts):
            parsed = parse_packet(pkt)
            self.assertEqual(parsed["seq_num"], expected_seq)

class TestReceiverBuffer(unittest.TestCase):
    """Kiểm tra bộ đệm phía NHẬN (Go-Back-N: chỉ nhận đúng thứ tự)."""

    def setUp(self):
        self.rb = ReceiverBuffer()

    def test_in_order_receive(self):
        """Nhận đúng thứ tự → accepted=True, data tích lũy."""
        self.assertTrue(self.rb.receive(0, b"A"))
        self.assertTrue(self.rb.receive(1, b"B"))
        self.assertEqual(self.rb.flush(), b"AB")

    def test_out_of_order_rejected(self):
        """Nhận lệch thứ tự (Go-Back-N) → rejected, flush rỗng."""
        self.assertTrue(self.rb.receive(0, b"A"))
        self.assertFalse(self.rb.receive(2, b"C"))  
        self.assertEqual(self.rb.flush(), b"A") 

    def test_flush_clears_buffer(self):
        """flush() lấy data rồi gọi lần nữa → rỗng."""
        self.rb.receive(0, b"X")
        self.rb.flush()
        self.assertEqual(self.rb.flush(), b"")

    def test_next_expected_advances(self):
        """next_expected tăng theo gói nhận đúng thứ tự."""
        self.rb.receive(0, b"a")
        self.assertEqual(self.rb.next_expected, 1)
        self.rb.receive(1, b"b")
        self.assertEqual(self.rb.next_expected, 2)

class TestReliableProtocol(unittest.TestCase):
    """Kiểm tra API tổng hợp mà Người A sẽ dùng."""

    def setUp(self):
        self.logic = ReliableProtocol(window_size=5, timeout_seconds=1.0)

    def test_queue_data_and_get_packets(self):
        """queue_data + get_packets_to_send phải ra bytes hợp lệ."""
        self.logic.queue_data(b"Hello")
        self.logic.queue_data(b"World")
        pkts = self.logic.get_packets_to_send()
        self.assertEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertIsInstance(pkt, bytes)
            self.assertIsNotNone(parse_packet(pkt))

    def test_receive_data_packet_returns_ack(self):
        """receive_packet(DATA) → phải trả về ACK bytes."""
        data_pkt = build_packet(seq_num=0, ack_num=0, flags=0, payload=b"hi")
        ack = self.logic.receive_packet(data_pkt)
        self.assertIsNotNone(ack)
        parsed_ack = parse_packet(ack)
        self.assertIsNotNone(parsed_ack)
        self.assertTrue(parsed_ack["flags"] & FLAG_ACK)

    def test_receive_ack_updates_sender_window(self):
        """receive_packet(ACK) → cửa sổ gửi trượt lên."""
        self.logic.queue_data(b"data")
        pkts = self.logic.get_packets_to_send()

        ack_pkt = build_packet(seq_num=0, ack_num=1, flags=FLAG_ACK)
        result = self.logic.receive_packet(ack_pkt)
        self.assertIsNone(result)
        self.assertEqual(self.logic.sender.base, 1)

    def test_receive_corrupt_packet_returns_none(self):
        """Packet bị lỗi → receive_packet trả None."""
        data_pkt = build_packet(seq_num=0, ack_num=0, flags=0, payload=b"x")
        corrupt = bytearray(data_pkt)
        corrupt[-1] ^= 0xFF
        result = self.logic.receive_packet(bytes(corrupt))
        self.assertIsNone(result)

    def test_get_ready_data_after_receive(self):
        """Nhận data packet → get_ready_data trả payload đúng."""
        data_pkt = build_packet(seq_num=0, ack_num=0, flags=0, payload=b"FileData")
        self.logic.receive_packet(data_pkt)
        data = self.logic.get_ready_data()
        self.assertEqual(data, b"FileData")

    def test_full_send_receive_cycle(self):
        """
        Mô phỏng 1 vòng hoàn chỉnh:
          Sender queue → get_packets → Receiver receive_packet → get_ready_data
        Dùng 2 instance ReliableProtocol giả lập 2 máy.
        """
        sender   = ReliableProtocol(window_size=3, timeout_seconds=1.0)
        receiver = ReliableProtocol(window_size=3, timeout_seconds=1.0)

        payloads = [b"Packet_A", b"Packet_B", b"Packet_C"]
        for p in payloads:
            sender.queue_data(p)

        pkts_to_send = sender.get_packets_to_send()
        self.assertEqual(len(pkts_to_send), 3)

        for pkt in pkts_to_send:
            ack = receiver.receive_packet(pkt)
            if ack:
                sender.receive_packet(ack) 

        data = receiver.get_ready_data()
        self.assertEqual(data, b"".join(payloads))

        self.assertTrue(sender.is_transfer_complete())

    def test_timeout_triggers_resend(self):
        """Sau timeout → get_packets_to_send phải trả lại gói cũ."""
        self.logic = ReliableProtocol(window_size=3, timeout_seconds=0.05)
        self.logic.queue_data(b"data")
        self.logic.get_packets_to_send()

        time.sleep(0.1)

        resend = self.logic.get_packets_to_send()
        self.assertEqual(len(resend), 1)

    def test_is_transfer_complete_false_while_pending(self):
        """is_transfer_complete False khi còn gói chưa ACK."""
        self.logic.queue_data(b"pending")
        self.logic.get_packets_to_send()
        self.assertFalse(self.logic.is_transfer_complete())

if __name__ == "__main__":
    unittest.main(verbosity=2)

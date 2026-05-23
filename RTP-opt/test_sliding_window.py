"""
test_sliding_window.py — RTP-opt  (Selective Repeat)
======================================================
Unit Test cho SlidingWindow Selective Repeat và ReliableProtocol.
Chạy: python test_sliding_window.py   hoặc   python -m pytest test_sliding_window.py -v

KHÔNG cần mạng. Dùng gói tin giả (bytes/dict) để test thuật toán.
"""

import time
import unittest
from packet import (
    build_packet, parse_packet,
    FLAG_ACK, FLAG_NACK, FLAG_SYN, FLAG_FIN,
    HEADER_SIZE, MAX_PAYLOAD,
)
from sliding_window import SlidingWindow, ReceiverBuffer, ReliableProtocol

class TestPacketOpt(unittest.TestCase):
    """Kiểm tra packet layer của RTP-opt (thêm FLAG_NACK)."""

    def test_build_parse_roundtrip(self):
        pkt = build_packet(seq_num=10, ack_num=3, flags=FLAG_ACK, payload=b"opt")
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["seq_num"], 10)
        self.assertEqual(parsed["payload"], b"opt")

    def test_nack_flag(self):
        pkt = build_packet(seq_num=0, ack_num=5, flags=FLAG_NACK)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["flags"] & FLAG_NACK)

    def test_corrupt_returns_none(self):
        pkt = build_packet(0, 0, 0, b"data")
        bad = bytearray(pkt)
        bad[HEADER_SIZE] ^= 0xFF
        self.assertIsNone(parse_packet(bytes(bad)))

class TestSelectiveRepeatSender(unittest.TestCase):
    """Kiểm tra SlidingWindow phía GỬI — Selective Repeat."""

    def setUp(self):
        self.sw = SlidingWindow(window_size=4, timeout_seconds=1.0)

    def test_individual_ack_marks_specific_packet(self):
        """
        SR: ACK cho seq=1 chỉ đánh dấu gói đó, base không trượt nếu seq=0 chưa ACK.
        """
        for i in range(3):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.mark_acked(1)
        self.assertEqual(self.sw.base, 0)

    def test_base_slides_after_contiguous_acks(self):
        """
        SR: ACK seq=0 rồi seq=1 → base trượt lên 2.
        """
        for i in range(3):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.mark_acked(0)
        self.assertEqual(self.sw.base, 1)
        self.sw.mark_acked(1)
        self.assertEqual(self.sw.base, 2)

    def test_out_of_order_acks_then_base_jumps(self):
        """
        SR: ACK 1, 2, 0 → sau khi ACK 0, base nhảy lên 3.
        """
        for i in range(3):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.mark_acked(1)
        self.sw.mark_acked(2)
        self.assertEqual(self.sw.base, 0)

        self.sw.mark_acked(0)
        self.assertEqual(self.sw.base, 3)

    def test_only_timeout_packets_resent(self):
        """
        SR: chỉ gói timeout được gửi lại, gói còn trong hạn thì không.
        """
        self.sw.timeout = 0.05
        for i in range(3):
            self.sw.queue_data(f"d{i}".encode())
        self.sw.get_next_packets_to_send()

        self.sw.mark_acked(1)
        time.sleep(0.1)

        timed_out = self.sw.get_timed_out_packets()
        self.assertEqual(len(timed_out), 2)

    def test_nack_triggers_immediate_resend(self):
        """handle_nack() phải trả về đúng packet của seq bị mất."""
        self.sw.queue_data(b"lost_packet")
        self.sw.get_next_packets_to_send()

        pkt = self.sw.handle_nack(seq_num=0)
        self.assertIsNotNone(pkt)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["seq_num"], 0)
        self.assertEqual(parsed["payload"], b"lost_packet")

    def test_window_blocks_beyond_size(self):
        """Queue 6 gói, window=4 → chỉ gửi 4."""
        for i in range(6):
            self.sw.queue_data(f"x{i}".encode())
        pkts = self.sw.get_next_packets_to_send()
        self.assertEqual(len(pkts), 4)
        self.assertEqual(len(self.sw.send_buffer), 2)

    def test_is_send_done(self):
        self.sw.queue_data(b"data")
        self.sw.get_next_packets_to_send()
        self.assertFalse(self.sw.is_send_done())
        self.sw.mark_acked(0)
        self.assertTrue(self.sw.is_send_done())

class TestSelectiveRepeatReceiver(unittest.TestCase):
    """Kiểm tra ReceiverBuffer — Selective Repeat."""

    def setUp(self):
        self.rb = ReceiverBuffer(window_size=4)

    def test_in_order_accepted(self):
        self.assertEqual(self.rb.receive(0, b"A"), "accepted")
        self.assertEqual(self.rb.receive(1, b"B"), "accepted")
        self.assertEqual(self.rb.flush(), b"AB")

    def test_out_of_order_buffered(self):
        """SR: gói lệch thứ tự vẫn được buffer (khác Go-Back-N)."""
        self.rb.receive(0, b"A")
        result = self.rb.receive(2, b"C")   
        self.assertEqual(result, "accepted")
        self.assertEqual(self.rb.flush(), b"A")

    def test_out_of_order_assembles_after_gap_filled(self):
        """Nhận 0, 2, 1 → sau khi nhận 1, flush ra A+B+C đúng thứ tự."""
        self.rb.receive(0, b"A")
        self.rb.receive(2, b"C")
        self.rb.receive(1, b"B")
        self.assertEqual(self.rb.flush(), b"ABC")

    def test_duplicate_returns_duplicate(self):
        self.rb.receive(0, b"A")
        result = self.rb.receive(0, b"A")
        self.assertEqual(result, "duplicate")

    def test_out_of_window_returns_out_of_win(self):
        result = self.rb.receive(10, b"far")  
        self.assertEqual(result, "out_of_win")

    def test_get_missing_seqs(self):
        """Nhận 0 và 2, thiếu 1 → get_missing_seqs trả [1]."""
        self.rb.receive(0, b"A")
        self.rb.receive(2, b"C")
        missing = self.rb.get_missing_seqs()
        self.assertIn(1, missing)

    def test_flush_clears(self):
        self.rb.receive(0, b"X")
        self.rb.flush()
        self.assertEqual(self.rb.flush(), b"")

class TestReliableProtocolOpt(unittest.TestCase):
    """Kiểm tra API tổng hợp — Selective Repeat."""

    def setUp(self):
        self.logic = ReliableProtocol(window_size=4, timeout_seconds=1.0)

    def test_queue_and_send(self):
        self.logic.queue_data(b"Hello")
        pkts = self.logic.get_packets_to_send()
        self.assertEqual(len(pkts), 1)
        self.assertIsNotNone(parse_packet(pkts[0]))

    def test_receive_data_returns_individual_ack(self):
        """Mỗi DATA packet → ACK riêng với ack_num = seq của gói đó."""
        data_pkt = build_packet(seq_num=3, ack_num=0, flags=0, payload=b"hi")
        ack = self.logic.receive_packet(data_pkt)
        self.assertIsNotNone(ack)
        parsed = parse_packet(ack)
        self.assertTrue(parsed["flags"] & FLAG_ACK)
        self.assertEqual(parsed["ack_num"], 3)
    def test_receive_ack_updates_sender(self):
        self.logic.queue_data(b"data")
        self.logic.get_packets_to_send()
        ack = build_packet(seq_num=0, ack_num=0, flags=FLAG_ACK)
        self.logic.receive_packet(ack)
        self.assertEqual(self.logic.sender.base, 1)

    def test_receive_corrupt_returns_none(self):
        pkt = build_packet(0, 0, 0, b"x")
        bad = bytearray(pkt)
        bad[-1] ^= 0xFF
        self.assertIsNone(self.logic.receive_packet(bytes(bad)))

    def test_full_sr_cycle_with_lost_packet(self):
        """
        Mô phỏng đầy đủ Selective Repeat:
          - Gửi 4 gói
          - Giả lập mất gói seq=1
          - Receiver buffer seq 2,3 (SR chấp nhận)
          - Sau timeout, sender chỉ gửi lại seq=1
          - Receiver lắp gap, flush ra đúng thứ tự
        """
        sender   = ReliableProtocol(window_size=4, timeout_seconds=0.05)
        receiver = ReliableProtocol(window_size=4, timeout_seconds=0.05)

        payloads = [b"PKT0", b"PKT1", b"PKT2", b"PKT3"]
        for p in payloads:
            sender.queue_data(p)

        pkts = sender.get_packets_to_send()
        self.assertEqual(len(pkts), 4)

        for i, pkt in enumerate(pkts):
            if i == 1:
                continue
            ack = receiver.receive_packet(pkt)
            if ack:
                sender.receive_packet(ack)
        partial = receiver.get_ready_data()
        self.assertEqual(partial, b"PKT0")

        time.sleep(0.1)
        resend = sender.get_packets_to_send()
        self.assertEqual(len(resend), 1)
        parsed_resend = parse_packet(resend[0])
        self.assertEqual(parsed_resend["seq_num"], 1)
        ack = receiver.receive_packet(resend[0])
        if ack:
            sender.receive_packet(ack)

        rest = receiver.get_ready_data()
        self.assertEqual(rest, b"PKT1PKT2PKT3")

    def test_get_ready_data(self):
        pkt = build_packet(seq_num=0, ack_num=0, flags=0, payload=b"FileContent")
        self.logic.receive_packet(pkt)
        data = self.logic.get_ready_data()
        self.assertEqual(data, b"FileContent")

    def test_is_transfer_complete(self):
        self.logic.queue_data(b"d")
        self.logic.get_packets_to_send()
        self.assertFalse(self.logic.is_transfer_complete())
        self.logic.sender.mark_acked(0)
        self.assertTrue(self.logic.is_transfer_complete())

    def test_sr_vs_gbn_difference(self):
        """
        Kiểm tra SR KHÔNG từ chối gói lệch thứ tự (khác Go-Back-N).
        """
        pkt2 = build_packet(seq_num=2, ack_num=0, flags=0, payload=b"C")
        ack2 = self.logic.receive_packet(pkt2)
        self.assertIsNotNone(ack2)
        parsed = parse_packet(ack2)
        self.assertEqual(parsed["ack_num"], 2)

if __name__ == "__main__":
    unittest.main(verbosity=2)

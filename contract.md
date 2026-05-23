# Contract — Giao kèo Người A & Người B
> **Không ai được tự ý thay đổi file này sau khi đã ký kết.**

---

## 1. Cấu trúc Packet Header (12 bytes)

| Field           | Size    | Struct | Ý nghĩa                                      |
|-----------------|---------|--------|----------------------------------------------|
| Sequence Number | 4 bytes | `I`    | Số thứ tự gói tin                            |
| ACK Number      | 4 bytes | `I`    | Xác nhận đã nhận đến gói này                 |
| Flags           | 1 byte  | `B`    | SYN=0x04, FIN=0x02, ACK=0x01, NACK=0x08     |
| Padding         | 1 byte  | `B`    | Luôn = 0                                     |
| Checksum        | 2 bytes | `H`    | Internet Checksum (RFC 1071) của header+data |

**Format struct:** `!IIBBH` (Big-Endian / Network Byte Order)  
**Tổng header:** 12 bytes  
**Payload tối đa:** 1400 - 12 = **1388 bytes**

---

## 2. API bắt buộc (Người A gọi vào code Người B)

```python
from sliding_window import ReliableProtocol

logic = ReliableProtocol(window_size=10, timeout_seconds=2.0)
```

### Phía GỬI (Sender)

| Hàm | Người A truyền vào | Người B trả về | Mô tả |
|-----|--------------------|----------------|-------|
| `logic.queue_data(data_chunk)` | `bytes` (≤1388 bytes đọc từ file) | `None` | Nạp data vào hàng chờ |
| `logic.get_packets_to_send()` | — | `list[bytes]` | Lấy danh sách packet cần `sendto()` |

### Phía NHẬN (Receiver)

| Hàm | Người A truyền vào | Người B trả về | Mô tả |
|-----|--------------------|----------------|-------|
| `logic.receive_packet(raw_packet)` | `bytes` từ `recvfrom()` | `bytes` (ACK cần gửi lại) hoặc `None` | Xử lý gói đến |
| `logic.get_ready_data()` | — | `bytes` | Lấy data đã sắp xếp để `f.write()` |

### Tiện ích

| Hàm | Trả về | Mô tả |
|-----|--------|-------|
| `logic.is_transfer_complete()` | `bool` | True khi không còn gì chờ gửi/ACK |

---

## 3. Ví dụ Event Loop (Người A dùng)

```python
# ── Phía SENDER ──────────────────────────────────────────
logic = ReliableProtocol(window_size=10, timeout_seconds=2.0)

with open("file.dat", "rb") as f:
    while chunk := f.read(1388):
        logic.queue_data(chunk)

while not logic.is_transfer_complete():
    for pkt in logic.get_packets_to_send():
        sock.sendto(pkt, (dest_ip, dest_port))

    raw, addr = sock.recvfrom(1400)
    logic.receive_packet(raw)   # xử lý ACK

# ── Phía RECEIVER ─────────────────────────────────────────
logic = ReliableProtocol(window_size=10, timeout_seconds=2.0)

with open("output.dat", "wb") as f:
    while True:
        raw, addr = sock.recvfrom(1400)
        ack = logic.receive_packet(raw)
        if ack:
            sock.sendto(ack, addr)
        data = logic.get_ready_data()
        if data:
            f.write(data)
```

---

## 4. Quy ước Flags

| Flag | Hex  | Ý nghĩa                        |
|------|------|--------------------------------|
| ACK  | 0x01 | Xác nhận nhận được             |
| FIN  | 0x02 | Kết thúc kết nối               |
| SYN  | 0x04 | Bắt đầu kết nối                |
| NACK | 0x08 | Báo gói bị mất (chỉ RTP-opt)  |

---

## 5. Sự khác biệt Base vs Opt

| Tiêu chí              | RTP-base (Go-Back-N)         | RTP-opt (Selective Repeat)       |
|-----------------------|------------------------------|----------------------------------|
| Retransmit khi timeout | Toàn bộ window từ base       | Chỉ gói cụ thể bị mất           |
| Receiver buffer        | Từ chối gói lệch thứ tự      | Chấp nhận & buffer gói lệch     |
| ACK type               | Cumulative (ack_num = next)  | Individual (ack_num = seq gói)  |
| NACK support           | Không                        | Có (FLAG_NACK = 0x08)           |
| API với Người A        | **Giống hệt nhau**           | **Giống hệt nhau**              |

---

*Ký kết ngày: ___________*  
*Người A: ___________*  
*Người B: ___________*

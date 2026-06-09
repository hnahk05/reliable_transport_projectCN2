import struct
HEADER_FORMAT  = "!IIBBH"
HEADER_SIZE    = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD    = 1400 - HEADER_SIZE

FLAG_SYN = 0x04
FLAG_FIN = 0x02
FLAG_ACK = 0x01

def calculate_checksum(data: bytes) -> int:
    """
    Tính Internet Checksum 16-bit (RFC 1071).
    Truyền vào: header (checksum field = 0) + payload.
    Trả về: giá trị checksum 16-bit (int).
    """
    if len(data) % 2 != 0:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF

def build_packet(seq_num: int,
                 ack_num: int,
                 flags: int,
                 payload: bytes = b"") -> bytes:
    
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Payload vượt quá {MAX_PAYLOAD} bytes")

    header_no_cksum = struct.pack(HEADER_FORMAT,
                                  seq_num, ack_num, flags, 0, 0)
    cksum = calculate_checksum(header_no_cksum + payload)

    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, 0, cksum)
    return header + payload

def parse_packet(raw: bytes) -> dict | None: 
    if len(raw) < HEADER_SIZE:
        return None

    seq_num, ack_num, flags, _pad, received_cksum = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    payload = raw[HEADER_SIZE:]

    header_zeroed = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, 0, 0)
    expected_cksum = calculate_checksum(header_zeroed + payload)

    if received_cksum != expected_cksum:
        return None

    return {
        "seq_num"  : seq_num,
        "ack_num"  : ack_num,
        "flags"    : flags,
        "checksum" : received_cksum,
        "payload"  : payload,
    }

def is_ack(flags: int) -> bool:
    return bool(flags & FLAG_ACK)

def is_syn(flags: int) -> bool:
    return bool(flags & FLAG_SYN)

def is_fin(flags: int) -> bool:
    return bool(flags & FLAG_FIN)

if __name__ == "__main__":
    pkt = build_packet(seq_num=1, ack_num=0, flags=0, payload=b"Hello RTP!")
    parsed = parse_packet(pkt)
    print("Build + Parse OK:", parsed)

    corrupt = bytearray(pkt)
    corrupt[14] ^= 0xFF
    result = parse_packet(bytes(corrupt))
    print("Corrupt packet -> None:", result is None)

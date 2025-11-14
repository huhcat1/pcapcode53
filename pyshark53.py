import pyshark

INTERFACE = 'vmx0'

def parse_dns_response_flag(dns):
    #dns.flags_response を 0/1 に正規化
    val = getattr(dns, "flags_response", "").lower()

    if val in ["0", "false"]:
        return 0
    if val in ["1", "true"]:
        return 1

    return 0  # 不明な場合は問い合わせ扱い

def main():
    print("リアルタイムDNS監視を開始...")

    cap = pyshark.LiveCapture(
        interface=INTERFACE,
        bpf_filter='port 53'
    )

    for packet in cap:
        try:
            # DNSパケットでなければスキップ
            if not hasattr(packet, 'dns'):
                continue

            dns = packet.dns

            # IPアドレス
            src = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
            dst = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'

            # トランスポート層（UDP/TCP）
            if hasattr(packet, packet.transport_layer):
                layer = packet.transport_layer
                sport = getattr(packet[layer], 'srcport', 'N/A')
                dport = getattr(packet[layer], 'dstport', 'N/A')
            else:
                sport = dport = "N/A"

            # Query / Response 判定
            is_response = parse_dns_response_flag(dns)

            # DNS情報
            qname = getattr(dns, 'qry_name', 'N/A')
            qtype = getattr(dns, 'qry_type', 'N/A')
            dns_id = getattr(dns, 'id', 'N/A')

            # 出力
            if is_response == 0:
                print(f"[DNS] Query: {src}:{sport} -> {dst}:{dport} "
                      f"(ID: {dns_id}) Domain: {qname} QTYPE: {qtype}")

            elif is_response == 1:
                print(f"[DNS] Response: {src}:{sport} -> {dst}:{dport} "
                      f"(ID: {dns_id}) Domain: {qname} QTYPE: {qtype}")

        except Exception as e:
            print("ERROR:", e)
            continue


if __name__ == '__main__':
    main()

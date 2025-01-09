import socket
import struct
import textwrap

def format_multi_line(prefix, string, size=80):
    """Format multi-line string with a prefix for each line."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(f'\\x{byte:02x}' for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_frame(data):
    """Unpacks Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Convert a MAC address from bytes to a human-readable string."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    """Unpacks IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Convert an IPv4 address from bytes to a human-readable string."""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Unpacks TCP segment."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    """Unpacks UDP segment."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    """Unpacks ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def main():
    # Create a raw socket to listen for all packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'    Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # Check if it's an IPv4 packet
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'    IPv4 Packet:')
            print(f'        Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'        Protocol: {proto}, Source: {src}, Target: {target}')

            # Check protocol and handle accordingly
            if proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'        ICMP Packet:')
                print(f'            Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(format_multi_line('            Data: ', data))

            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                print(f'        TCP Segment:')
                print(f'            Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'            Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'            Flags: {flags}')
                print(format_multi_line('            Data: ', data))

            elif proto == 17:  # UDP
                src_port, dest_port, size, data = udp_segment(data)
                print(f'        UDP Segment:')
                print(f'            Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}')
                print(format_multi_line('            Data: ', data))

            else:
                print(f'        Other Protocol: {proto}')
                print(format_multi_line('        Data: ', data))

if __name__ == "__main__":
    main()

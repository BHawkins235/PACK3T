"""
Packet Capture Module - Handles packet capture, storage, and filtering
"""

import scapy
from scapy.all import sniff, get_if_list
from typing import List, Optional
import traceback
import storage
from scapy.utils import wrpcap


def get_interfaces() -> List[str]:
    """Get list of available network interfaces."""
    try:
        return get_if_list()
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []


def get_packet_protocol(packet) -> str:
    """Extract protocol name from scapy packet."""
    try:
        if packet.haslayer('Ether'):
            if packet.haslayer('IP'):
                if packet.haslayer('TCP'):
                    return 'TCP'
                elif packet.haslayer('UDP'):
                    return 'UDP'
                elif packet.haslayer('ICMP'):
                    return 'ICMP'
                return 'IP'
            elif packet.haslayer('ARP'):
                return 'ARP'
            return 'Ethernet'
        return 'Unknown'
    except:
        return 'Unknown'


def filter_packets(packets: List, protocol: Optional[str] = None) -> List:
    """Filter packets by protocol."""
    if not protocol:
        return packets
    
    protocol = protocol.upper()
    filtered = []
    
    for packet in packets:
        # Handle both packet objects and dicts from storage
        if isinstance(packet, dict):
            pkt_protocol = packet.get('protocol', '').upper()
        else:
            pkt_protocol = get_packet_protocol(packet)
        
        if protocol in pkt_protocol:
            filtered.append(packet)
    
    return filtered


def capture_packets(interface: str, timeout: int, count: int = None, protocol: str = None) -> List:
    """Capture packets from the specified interface using scapy."""
    try:
        print(f"  Interface: {interface}, Timeout: {timeout}s, Count: {count}, Protocol: {protocol}")
        
        # Build BPF filter if protocol specified
        bpf_filter = protocol.upper() if protocol else None
        
        # Scapy sniff - interface can be interface name or number
        iface = interface if interface != "0" else None
        
        print(f"  Sniffing for {timeout} seconds...")
        packets = sniff(iface=iface, timeout=timeout, filter=bpf_filter, count=count or 0)
        
        # Handle None return
        if packets is None:
            print("  No packets captured (result is None)")
            return []
        
        # Convert to list if needed
        if not isinstance(packets, list):
            packets = list(packets) if packets else []
        
        print(f"  Captured {len(packets)} packets")
        return packets
    except Exception as e:
        print(f"Capture error: {e}")
       
        traceback.print_exc()
        return []


def add_packets(packets: List):
    """Add packets to the global store."""
    print(f"  Adding {len(packets)} packets to store...")
    storage.add_to_store(packets)
    print(f"  Store now has {storage.get_store_count()} packets")


def get_packets(protocol: Optional[str] = None) -> List:
    """Get packets from store, optionally filtered."""
    packets = storage.get_store()
    if protocol:
        return filter_packets(packets, protocol)
    return packets


def get_packet_count() -> int:
    """Get total packet count."""
    return storage.get_store_count()


def clear_store():
    """Clear all packets from memory."""
    storage.clear_the_store()


def list_packets(protocol: Optional[str] = None):
    """List all packets currently in memory."""
    packets = get_packets(protocol)
    
    if not packets:
        print("No packets in memory.")
        return
    
    print(f"\n--- {len(packets)} Packets in Memory ---\n")
    for i, packet in enumerate(packets):
        print(f"[{i}] {packet}")
    print()

def pcap_store(packets: List, filename: str, destination: str = "local"):
    """Store packets to a PCAP file."""
    try:
        if not packets:
            print("Warning: No packets to store. PCAP file not created.")
            return
        
        # Use storage module to export packets from cache to PCAP
        storage.export_to_pcap(filename)
    except Exception as e:
        print(f"Error storing to PCAP file '{filename}': {e}")

"""Fix the destination parameter to allow for future local or cloud storage options."""
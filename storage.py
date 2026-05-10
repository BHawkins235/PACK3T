"""
Shared packet storage - SQLite database for persistence
"""

import sqlite3
import json
from typing import List, Optional
from datetime import datetime
import scapy.all
from scapy.compat import raw

# Database file
DB_PATH = "packets.db"

# In-memory cache for raw scapy packets (needed for PCAP export)
_packet_cache: List = []

# Initialize database
def _init_db():
    """Initialize the SQLite database and create tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            protocol TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            raw_data TEXT,
            raw_bytes BLOB,
            info TEXT
        )
    ''')
    conn.commit()
    conn.close()


def get_store() -> List:
    """Get all packets from the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to dict list (not full packet objects, but metadata)
    return [dict(row) for row in rows]


def add_to_store(packets: List):
    """Add packets to the database and cache for PCAP export."""
    if not packets:
        return
    
    # Cache raw scapy packets for PCAP export
    global _packet_cache
    _packet_cache.extend(packets)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for packet in packets:
        try:
            # Extract packet metadata
            timestamp = datetime.now().isoformat()
            protocol = _get_packet_field(packet, 'protocol')
            source_ip = _get_packet_field(packet, 'source')
            dest_ip = _get_packet_field(packet, 'destination')
            source_port = _get_packet_field(packet, 'srcport')
            dest_port = _get_packet_field(packet, 'dstport')
            raw_data = str(packet)
            # Store raw bytes for PCAP export
            raw_bytes = raw(packet)
            info = _get_packet_field(packet, 'info')
            
            cursor.execute('''
                INSERT INTO packets (timestamp, protocol, source_ip, dest_ip, 
                                    source_port, dest_port, raw_data, raw_bytes, info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, protocol, source_ip, dest_ip, source_port, 
                  dest_port, raw_data, raw_bytes, info))
        except Exception as e:
            print(f"Error adding packet: {e}")
    
    conn.commit()
    conn.close()


def _get_packet_field(packet, field: str) -> str:
    """Safely extract field from packet object (supports scapy packets)."""
    try:
        # Handle scapy packets
        if hasattr(packet, 'haslayer'):
            if field == 'protocol':
                from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP
                if packet.haslayer(TCP):
                    return 'TCP'
                elif packet.haslayer(UDP):
                    return 'UDP'
                elif packet.haslayer(ICMP):
                    return 'ICMP'
                elif packet.haslayer(ARP):
                    return 'ARP'
                elif packet.haslayer(IP):
                    return 'IP'
                elif packet.haslayer(Ether):
                    return 'Ethernet'
                return 'Unknown'
            elif field == 'source':
                if packet.haslayer('IP'):
                    return packet['IP'].src
                elif packet.haslayer('ARP'):
                    return packet['ARP'].psrc
                return ''
            elif field == 'destination':
                if packet.haslayer('IP'):
                    return packet['IP'].dst
                elif packet.haslayer('ARP'):
                    return packet['ARP'].pdst
                return ''
            elif field == 'srcport':
                if packet.haslayer('TCP'):
                    return packet['TCP'].sport
                elif packet.haslayer('UDP'):
                    return packet['UDP'].sport
                return 0
            elif field == 'dstport':
                if packet.haslayer('TCP'):
                    return packet['TCP'].dport
                elif packet.haslayer('UDP'):
                    return packet['UDP'].dport
                return 0
            elif field == 'info':
                return str(packet.summary())
        
        # Handle dict from storage
        if isinstance(packet, dict):
            return packet.get(field, '')
        
        # Default handling
        if hasattr(packet, field):
            return str(getattr(packet, field))
        return ""
    except Exception as e:
        return ""


def clear_the_store():
    """Clear all packets from the database and cache."""
    global _packet_cache
    _packet_cache = []
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM packets")
    conn.commit()
    conn.close()


def get_store_count() -> int:
    """Get packet count in database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM packets")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def query_packets(protocol: str = None, limit: int = 100) -> List:
    """Query packets with optional filters."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM packets"
    params = []
    
    if protocol:
        query += " WHERE protocol = ?"
        params.append(protocol.upper())
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def export_to_pcap(filename: str):
    """Export packets from database to a PCAP file."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT raw_bytes FROM packets WHERE raw_bytes IS NOT NULL")
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print("No packets with raw bytes to export.")
        return
    
    # Convert raw bytes back to scapy packets
    scapy_packets = []
    for row in rows:
        try:
            raw_bytes = row['raw_bytes']
            if raw_bytes:
                # Reconstruct packet from raw bytes using Ether wrapper
                from scapy.all import Ether
                pkt = Ether(raw_bytes)
                if pkt:
                    scapy_packets.append(pkt)
        except Exception as e:
            print(f"Error converting packet: {e}")
    
    if scapy_packets:
        try:
            scapy.all.wrpcap(filename, scapy_packets)
            print(f"Exported {len(scapy_packets)} packets to {filename}")
        except Exception as e:
            print(f"Error writing PCAP: {e}")
    else:
        print("No valid packets to export.")


# Initialize on module load
_init_db()
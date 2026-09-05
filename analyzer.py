"""
Packet Analyzer - Uses local LLM to analyze captured packets
Requires Ollama: https://ollama.ai/
"""

import json
import subprocess
import requests
from typing import List, Dict, Any, Optional


def packet_to_text(packets: List) -> str:
    """Convert packet objects to readable text format."""
    lines = []
    for i, pkt in enumerate(packets):
        try:
            # Handle dict from storage
            if isinstance(pkt, dict):
                info = []
                proto = pkt.get('protocol', '')
                src = pkt.get('source_ip', '')
                dst = pkt.get('dest_ip', '')
                sport = pkt.get('source_port', '')
                dport = pkt.get('dest_port', '')
                
                if proto:
                    info.append(proto)
                if src and dst:
                    info.append(f"{src} -> {dst}")
                if sport and dport:
                    info.append(f"port {sport} -> {dport}")
                
                lines.append(f"Packet {i}: {' | '.join(info)}")
            else:
                # Original scapy packet handling
                info = {"index": i, "layers": []}
                
                if hasattr(pkt, 'eth'):
                    info["layers"].append("Ethernet")
                if hasattr(pkt, 'ip'):
                    info["layers"].append(f"IP: {getattr(pkt.ip, 'src', '?')} -> {getattr(pkt.ip, 'dst', '?')}")
                if hasattr(pkt, 'tcp'):
                    info["layers"].append(f"TCP: {getattr(pkt.tcp, 'srcport', '?')} -> {getattr(pkt.tcp, 'dstport', '?')}")
                if hasattr(pkt, 'udp'):
                    info["layers"].append(f"UDP: {getattr(pkt.udp, 'srcport', '?')} -> {getattr(pkt.udp, 'dstport', '?')}")
                if hasattr(pkt, 'icmp'):
                    info["layers"].append("ICMP")
                if hasattr(pkt, 'arp'):
                    info["layers"].append("ARP")
                    
                lines.append(f"Packet {i}: {' | '.join(info['layers'])}")
        except Exception as e:
            lines.append(f"Packet {i}: {str(pkt)[:100]}")
    
    return "\n".join(lines)


def query_ollama(prompt: str, model: str = "llama3.2") -> Optional[str]:
    """Query local Ollama model via CLI."""
    try:
        # Write prompt to temp file and use ollama with file input
        import tempfile
        import os
        
        # Create temp file with prompt
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(prompt)
            temp_file = f.name
        
        try:
            # Use PowerShell Get-Content to pipe the file content to ollama
            result = subprocess.run(
                f'powershell -Command "Get-Content {temp_file} | ollama run {model}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"Ollama error: {result.stderr}")
                return None
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.remove(temp_file)
    except FileNotFoundError:
        print("Ollama not found. Install from https://ollama.ai/")
        return None
    except subprocess.TimeoutExpired:
        print("Request timed out")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def analyze_packets(packets: List, model: str = "llama3.2") -> str:
    """Analyze packets using local LLM."""
    if not packets:
        return "No packets to analyze."
    
    packet_text = packet_to_text(packets)
    
    prompt = f"""You are a network traffic analyst. Analyze these captured network packets and provide a summary.
Explain what type of traffic this is, notable patterns, and any important observations in technical language . List out the key Statistics in levels of severarity of the traffic (Critical, High, Medium, Low,), also use details from the packets such as protocols used, source/destination IPs, ports, and any anomalies you notice.

Packets:
{packet_text}

Provide a clear, concise analysis:"""
    
    response = query_ollama(prompt, model)
    return response if response else "Failed to get analysis."


def analyze_single_packet(packet, model: str = "llama3.2") -> str:
    """Analyze a single packet."""
    packet_text = packet_to_text([packet])
    
    prompt = f"""You are a network traffic analyst. Explain this packet in simple terms.

Packet:
{packet_text}

What does this packet do? What is its purpose?"""
    
    response = query_ollama(prompt, model)
    return response if response else "Failed to get analysis."


def detect_anomalies(packets: List, model: str = "llama3.2") -> str:
    """Look for suspicious patterns in packets."""
    packet_text = packet_to_text(packets)
    
    prompt = f"""You are a cybersecurity analyst. Review these packets for potential security concerns, and scale them from critical to low risk. Provide a summary of any anomalies or suspicious activity you detect.

Look for:
- Unusual ports or protocols
- Suspicious IP addresses
- Potential attack patterns
- Data exfiltration indicators
- Anomalous traffic patterns

Packets:
{packet_text}

Report any concerns:"""
    
    response = query_ollama(prompt, model)
    return response if response else "Failed to get analysis."


# Example usage
if __name__ == "__main__":
    # Test with sample data
    sample_packets = [
        {"layers": ["Ethernet", "IP: 192.168.1.5 -> 8.8.8.8", "ICMP"]},
        {"layers": ["Ethernet", "IP: 192.168.1.5 -> 10.0.0.1", "TCP: 443 -> 52341"]},
    ]
    
    print("Testing packet analyzer...")
    result = analyze_packets(sample_packets)
    print(result)
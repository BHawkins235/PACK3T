
"""
Command Line Interface - Handles all CLI commands
"""

import argparse
import packets as packet_module
import analyzer


def main_cli():
    parser = argparse.ArgumentParser(
        description="Packet capture CLI tool",
        prog="packet"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture packets")
    capture_parser.add_argument("-i", "--interface", default="0", help="Capture interface (default: 0)")
    capture_parser.add_argument("-t", "--timeout", type=int, default=10, help="Capture duration in seconds")
    capture_parser.add_argument("-c", "--count", type=int, help="Limit packets after capture")
    capture_parser.add_argument("-p", "--protocol", help="Protocol filter (e.g., tcp, udp, icmp)")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List packets in memory")
    list_parser.add_argument("-p", "--protocol", help="Filter by protocol (e.g., tcp, udp, icmp)")
    
    # Clear command
    subparsers.add_parser("clear", help="Clear packets from memory")
    
    # Stats command

    # Interfaces command
    subparsers.add_parser("interfaces", help="List available network interfaces")
    
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze packets with LLM")
    analyze_parser.add_argument("-m", "--model", default="llama3.2", help="Ollama model to use")
    
    # Detect anomalies command
    detect_parser = subparsers.add_parser("detect", help="Detect security anomalies")
    detect_parser.add_argument("-m", "--model", default="llama3.2", help="Ollama model to use")

    # PCAP file storing for packets 
    pcapFile = (subparsers.add_parser("store", help="Store captured packets to a PCAP file"))
    pcapFile.add_argument("-f", "--file", type=str, default="packets.pcap", help="Output PCAP file name")
    pcapFile.add_argument("-d", "--destination", type=str, default="local", help="Storage destination (default: local)")
    
    args = parser.parse_args()
    
    if args.command == "capture":
        print(f"Capturing on interface {args.interface}...")
        if args.protocol:
            print(f"Filtering by protocol: {args.protocol}")
        packets = packet_module.capture_packets(args.interface, args.timeout, args.count, args.protocol)
        print(f"  Packets returned from capture: {len(packets)}")
        packet_module.add_packets(packets)
        print(f"Captured {len(packets)} packets. Total in memory: {packet_module.get_packet_count()}")
    
    elif args.command == "list":
        print(f"  Packets in store: {packet_module.get_packet_count()}")
        packet_module.list_packets(args.protocol if hasattr(args, 'protocol') else None)
    
    elif args.command == "clear":
        count = packet_module.get_packet_count()
        packet_module.clear_store()
        print(f"Cleared {count} packets from memory.")
        
    elif args.command == "interfaces":
        print("Available network interfaces:")
        try:
            for iface in packet_module.get_interfaces():
                # Shorten the interface name for display
                short_name = iface.split('{')[0] if '{' in iface else iface
                print(f"  - {iface}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
    
    elif args.command == "analyze":
        packets_to_analyze = packet_module.get_packets()
        print(f"Analyzing {len(packets_to_analyze)} packets with LLM...")
        result = analyzer.analyze_packets(packets_to_analyze, args.model)
        print("\n" + "="*50)
        print("ANALYSIS RESULT:")
        print("="*50)
        print(result)
    
    elif args.command == "detect":  
        packets_to_analyze = packet_module.get_packets()
        print(f"Scanning {len(packets_to_analyze)} packets for anomalies...")
        result = analyzer.detect_anomalies(packets_to_analyze, args.model)
        print("\n" + "="*50)
        print("SECURITY SCAN RESULT:")
        print("="*50)
        print(result)
    
    elif args.command == "store":
        packets_to_store = packet_module.get_packets()
        print(f"Storing {len(packets_to_store)} packets to {args.file}...")
        packet_module.pcap_store(packets_to_store, args.file, args.destination)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main_cli()
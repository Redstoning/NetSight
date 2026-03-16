import sys
import time
from collections import Counter, defaultdict
from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP, DNS
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def slow_print(text, delay=0.02):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

def boot_sequence():
    console.clear()

    title = r"""
 ███╗   ██╗███████╗████████╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██╔██╗ ██║█████╗     ██║   ███████╗██║██║  ███╗███████║   ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██║██║   ██║██╔══██║   ██║
 ██║ ╚████║███████╗   ██║   ███████║██║╚██████╔╝██║  ██║   ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
"""

    console.print(f"[bold cyan]{title}[/bold cyan]")
    slow_print("[*] ...", 0.015)
    slow_print("[*] ...", 0.015)
    slow_print("[*] ...", 0.015)
    console.print("[bold white][+] NetSight ready.[/bold white]")
    time.sleep(0.3)

def analyze_packets(packets):
    protocol_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports_by_src = defaultdict(set)
    dns_queries_by_src = Counter()
    icmp_by_src = Counter()
    syn_by_src = Counter()

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            src_ips[src] += 1
            dst_ips[dst] += 1

            if TCP in packet:
                protocol_counts["TCP"] += 1
                dst_ports_by_src[src].add(packet[TCP].dport)

                if packet[TCP].flags & 0x02:
                    syn_by_src[src] += 1

                raw_payload = bytes(packet[TCP].payload).lower()
                if b"http" in raw_payload or packet[TCP].dport in [80, 8080, 8000]:
                    protocol_counts["HTTP-like"] += 1
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    protocol_counts["HTTPS-like"] += 1

            elif UDP in packet:
                protocol_counts["UDP"] += 1

            elif ICMP in packet:
                protocol_counts["ICMP"] += 1
                icmp_by_src[src] += 1

            if DNS in packet:
                protocol_counts["DNS"] += 1
                dns_queries_by_src[src] += 1

    show_summary(len(packets), protocol_counts, src_ips, dst_ips)
    show_suspicious(dst_ports_by_src, dns_queries_by_src, icmp_by_src, syn_by_src)

def inspect_pcap(file_path):
    console.print(f"[cyan][*] Reading capture:[/cyan] [white]{file_path}[/white]")
    packets = rdpcap(file_path)
    console.print(f"[green][+] Loaded {len(packets)} packets.[/green]")
    analyze_packets(packets)

def live_capture(interface):
    console.print(f"[cyan][*] Starting live capture on interface:[/cyan] [white]{interface}[/white]")
    console.print("[yellow][*] Press CTRL+C to stop capture[/yellow]")

    try:
        packets = sniff(iface=interface, count=200)
        console.print(f"[green][+] Captured {len(packets)} packets.[/green]")
        analyze_packets(packets)
    except PermissionError:
        console.print("[bold red][-] Permission denied. Run live capture with sudo.[/bold red]")
        sys.exit(1)
    except OSError:
        console.print("[bold red][-] Invalid interface.[/bold red]")
        sys.exit(1)

def show_summary(total_packets, protocol_counts, src_ips, dst_ips):
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]NetSight Analysis Report[/bold cyan]\n[white]Total Packets:[/white] {total_packets}"
        )
    )

    protocol_table = Table(title="Protocol Distribution")
    protocol_table.add_column("Protocol", style="cyan")
    protocol_table.add_column("Count", style="green")
    for proto, count in protocol_counts.most_common():
        protocol_table.add_row(proto, str(count))
    console.print(protocol_table)

    src_table = Table(title="Top Source IPs")
    src_table.add_column("Source IP", style="cyan")
    src_table.add_column("Packets", style="green")
    for ip, count in src_ips.most_common(10):
        src_table.add_row(ip, str(count))
    console.print(src_table)

    dst_table = Table(title="Top Destination IPs")
    dst_table.add_column("Destination IP", style="cyan")
    dst_table.add_column("Packets", style="green")
    for ip, count in dst_ips.most_common(10):
        dst_table.add_row(ip, str(count))
    console.print(dst_table)

def show_suspicious(dst_ports_by_src, dns_queries_by_src, icmp_by_src, syn_by_src):
    findings = []

    for ip, ports in dst_ports_by_src.items():
        if len(ports) >= 20:
            findings.append(
                f"[yellow]Possible port scan[/yellow] from [white]{ip}[/white] across [green]{len(ports)}[/green] unique ports"
            )

    for ip, count in dns_queries_by_src.items():
        if count >= 50:
            findings.append(
                f"[yellow]High DNS activity[/yellow] from [white]{ip}[/white]: [green]{count}[/green] queries"
            )

    for ip, count in icmp_by_src.items():
        if count >= 20:
            findings.append(
                f"[yellow]ICMP-heavy traffic[/yellow] from [white]{ip}[/white]: [green]{count}[/green] packets"
            )

    for ip, count in syn_by_src.items():
        if count >= 30:
            findings.append(
                f"[yellow]Potential SYN scan/flood behavior[/yellow] from [white]{ip}[/white]: [green]{count}[/green] SYN packets"
            )

    console.print()
    if findings:
        console.print(
            Panel.fit(
                "\n".join(findings),
                title="[bold red]Suspicious Indicators[/bold red]"
            )
        )
    else:
        console.print(
            Panel.fit(
                "[green]No obvious suspicious indicators detected.[/green]",
                title="[bold green]Suspicious Indicators[/bold green]"
            )
        )

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red]")
        console.print("python netsight.py <pcap_file>")
        console.print("sudo python netsight.py --live <interface>")
        sys.exit(1)

    boot_sequence()

    if sys.argv[1] == "--live":
        if len(sys.argv) != 3:
            console.print("[red]Usage:[/red] sudo python netsight.py --live <interface>")
            sys.exit(1)
        live_capture(sys.argv[2])
    else:
        if len(sys.argv) != 2:
            console.print("[red]Usage:[/red] python netsight.py <pcap_file>")
            sys.exit(1)
        inspect_pcap(sys.argv[1])

if __name__ == "__main__":
    main()
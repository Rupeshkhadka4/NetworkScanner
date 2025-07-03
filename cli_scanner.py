#!/usr/bin/env python3
import nmap

def get_scan_ports():
    """Prompt user to choose scan type and return appropriate port string."""
    top_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,   # Top 10
        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,  # Top 20
        20, 111, 161, 389, 514, 1025, 1080, 1433, 1521, 3128     # Top 30
    ]

    print("\nChoose scan option:")
    print("1. All ports (1-65535)")
    print("2. Specific port or range (e.g., 80 or 20-100)")
    print("3. Top 10 common ports")
    print("4. Top 20 common ports")
    print("5. Top 30 common ports")

    choice = input("Enter choice (1-5): ").strip()

    if choice == "1":
        return "1-65535"
    elif choice == "2":
        return input("Enter port(s)/range (e.g., 80 or 20-25): ").strip()
    elif choice == "3":
        return ",".join(map(str, top_ports[:10]))
    elif choice == "4":
        return ",".join(map(str, top_ports[:20]))
    elif choice == "5":
        return ",".join(map(str, top_ports[:30]))
    else:
        print("[!] Invalid choice. Defaulting to Top 10 ports.")
        return ",".join(map(str, top_ports[:10]))


def main():
    print("🔍 Advanced Nmap Port Scanner")
    print("-----------------------------")

    targets_input = input("Enter target IPs or hostnames (comma-separated): ")
    targets = [t.strip() for t in targets_input.split(',')]

    ports = get_scan_ports()

    print(f"\n[+] Starting scan on {len(targets)} target(s), ports: {ports}")
    scanner = nmap.PortScanner()

    for target in targets:
        print(f"\n🚀 Scanning {target}...")
        try:
            scanner.scan(hosts=target, ports=ports, arguments='-sS -T4')

            if not scanner.scaninfo():
                print(f"[-] No results for {target}. Host may be unreachable.")
                continue

            for host in scanner.all_hosts():
                print(f"\nHost: {host} ({scanner[host].hostname()})")
                print(f"State: {scanner[host].state()}")

                for proto in scanner[host].all_protocols():
                    print(f"\nProtocol: {proto.upper()}")
                    ports_dict = scanner[host][proto]
                    open_ports = sorted(ports_dict.keys())

                    if open_ports:
                        for port in open_ports:
                            info = ports_dict[port]
                            print(f"Port {port}/{proto.upper()} - {info['name']} - {info['state'].upper()}")
                    else:
                        print("No open ports found.")

        except Exception as e:
            print(f"[-] Error scanning {target}: {str(e)}")


if __name__ == "__main__":
    main()
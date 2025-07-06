from flask import Flask, render_template, request, jsonify, send_file
from fpdf import FPDF
import nmap
import os
import tempfile

app = Flask(__name__)
nm = nmap.PortScanner()

COMMON_PORTS = {
    "basic": "21,22,23,25,53,80,110,135,139,143,443,445",
    "top10": "21,22,23,25,53,80,110,135,139,443",
    "top20": "21,22,23,25,53,79,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
    "top30": "21,22,23,25,53,79,80,81,110,111,135,139,143,443,445,993,995,1723,3000,3306,3389,5000,5900,7070,8000,8080,8888,9090,9091,9200",
    "top40": "21,22,23,25,53,79,80,81,110,111,119,123,135,139,143,443,445,500,514,515,993,995,1025,1026,1027,1028,1029,1080,1194,1433,1723,1900,2049,3000,3306,3389,5000,5060,5900,7070,8000,8080",
    "top50": "21,22,23,25,53,79,80,81,88,110,111,119,123,135,139,143,161,443,445,500,514,515,587,993,995,1025,1026,1027,1028,1029,1080,1194,1433,1723,1900,2049,3000,3306,3389,5000,5060,5900,7070,8000,8080,8888,9090,9091,9200,9999,30000",
    "range50to100": "1-100",
    "range100to200": "100-200",
    "allports": "1-65535"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    targets = [t.strip() for t in data.get("targets", "").split(",") if t.strip()]
    port_type = data.get("port_type")
    custom_ports = data.get("custom_ports", "")
    scan_type = data.get("scan_type", "-sT")
    os_detection = data.get("os_detection", False)
    aggressive = data.get("aggressive", False)
    no_ping = data.get("no_ping", False)

    if port_type == "custom":
        ports = custom_ports
    else:
        ports = COMMON_PORTS.get(port_type, "21,22,25,80")

    args = scan_type
    if os_detection:
        args += " -O"
    if aggressive:
        args += " -A"
    if no_ping:
        args += " -Pn"

    results = []

    for target in targets:
        try:
            nm.scan(hosts=target, ports=ports, arguments=args)
            host_data = {}

            if not nm.scaninfo():
                host_data[target] = {"error": "No response or host unreachable."}
            else:
                for host in nm.all_hosts():
                    host_info = {
                        "hostname": nm[host].hostname(),
                        "state": nm[host].state(),
                        "protocols": {},
                        "os_match": []
                    }

                    if 'osmatch' in nm[host]:
                        for os_info in nm[host]['osmatch']:
                            host_info["os_match"].append({
                                "name": os_info['name'],
                                "accuracy": os_info['accuracy']
                            })

                    for proto in nm[host].all_protocols():
                        proto_data = {}
                        ports_dict = nm[host][proto]
                        for port in sorted(ports_dict.keys()):
                            proto_data[port] = {
                                "name": ports_dict[port]['name'],
                                "state": ports_dict[port]['state'],
                                "reason": ports_dict[port].get('reason', 'unknown')
                            }
                        host_info["protocols"][proto] = proto_data
                    host_data[host] = host_info
            results.append(host_data)
        except Exception as e:
            results.append({target: {"error": str(e)}})

    return jsonify(results)

@app.route('/export_pdf', methods=['POST'])
def export_pdf():
    scan_results = request.json.get("results", [])

    if not scan_results:
        return jsonify({"error": "No scan results provided"}), 400

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    for result in scan_results:
        for host, info in result.items():
            pdf.cell(0, 10, txt=f"Host: {host}", ln=True)
            if "hostname" in info and info["hostname"]:
                pdf.cell(0, 10, txt=f"Hostname: {info['hostname']}", ln=True)
            if "state" in info:
                pdf.cell(0, 10, txt=f"State: {info['state']}", ln=True)

            if "os_match" in info and info["os_match"]:
                pdf.cell(0, 10, txt="OS Matches:", ln=True)
                for os_info in info["os_match"]:
                    pdf.cell(0, 10, txt=f" - {os_info['name']} ({os_info['accuracy']}%)", ln=True)

            if "protocols" in info:
                for proto, ports in info["protocols"].items():
                    pdf.cell(0, 10, txt=f"{proto.upper()} Ports:", ln=True)
                    for port, pinfo in ports.items():
                        pdf.cell(0, 10, txt=f" - Port {port}: {pinfo['name']} - {pinfo['state']}", ln=True)

            pdf.ln(10)

    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, "scan_report.pdf")
    try:
        pdf.output(file_path)
    except Exception as e:
        print("PDF Generation Error:", str(e))
        return jsonify({"error": "Could not generate PDF"}), 500

    return send_file(file_path, as_attachment=True, download_name="scan_report.pdf")

if __name__ == '__main__':
    app.run(debug=True)
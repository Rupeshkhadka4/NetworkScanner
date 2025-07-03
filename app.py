# app.py
from flask import Flask, render_template, request, jsonify
import nmap

app = Flask(__name__)
nm = nmap.PortScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    targets = [t.strip() for t in data.get("targets", "").split(",")]
    ports = data.get("ports", "21,22,23,25,53,80,110,135,139,143")

    results = []

    for target in targets:
        try:
            nm.scan(hosts=target, ports=ports, arguments='-sS -T4')
            host_data = {}

            if not nm.scaninfo():
                host_data[target] = {"error": "Host unreachable or no response"}
            else:
                for host in nm.all_hosts():
                    host_info = {
                        "hostname": nm[host].hostname(),
                        "state": nm[host].state(),
                        "protocols": {}
                    }

                    for proto in nm[host].all_protocols():
                        proto_data = {}
                        ports_dict = nm[host][proto]
                        for port in sorted(ports_dict.keys()):
                            proto_data[port] = {
                                "name": ports_dict[port]['name'],
                                "state": ports_dict[port]['state']
                            }
                        host_info["protocols"][proto] = proto_data
                    host_data[host] = host_info
            results.append(host_data)
        except Exception as e:
            results.append({target: {"error": str(e)}})

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
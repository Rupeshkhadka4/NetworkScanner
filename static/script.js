document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("portType").addEventListener("change", function () {
        const customGroup = document.getElementById("customPortGroup");
        customGroup.style.display = (this.value === "custom") ? "block" : "none";
    });

    document.getElementById("scanForm").addEventListener("submit", function (e) {
        e.preventDefault();

        const formData = {
            targets: document.getElementById("targets").value,
            port_type: document.getElementById("portType").value,
            custom_ports: document.getElementById("customPorts").value,
            scan_type: document.getElementById("scanType").value,
            os_detection: document.getElementById("osDetection").checked,
            aggressive: document.getElementById("aggressive").checked,
            no_ping: document.getElementById("noPing").checked
        };

        fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(formData)
        })
        .then(res => res.json())
        .then(data => {
            window.scanResults = data;
            displayResults(data);
            document.getElementById("exportPdf").disabled = false;
        });
    });

    document.getElementById("exportPdf").addEventListener("click", function () {
        const exportBtn = document.getElementById("exportPdf");
        const loading = document.getElementById("loading");

        if (!window.scanResults || window.scanResults.length === 0) {
            alert("❌ No scan results to export.");
            return;
        }

        exportBtn.disabled = true;
        loading.style.display = "block";

        fetch("/export_pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ results: window.scanResults })
        })
        .then(response => {
            if (!response.ok) throw new Error("Export failed");
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "scan_report.pdf";
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            alert("✅ PDF exported successfully!");
        })
        .catch(err => {
            console.error("Export error:", err);
            alert("❌ Error exporting to PDF.");
        })
        .finally(() => {
            exportBtn.disabled = false;
            loading.style.display = "none";
        });
    });
});

function displayResults(data) {
    const resultsDiv = document.getElementById("results");
    resultsDiv.innerHTML = "";

    data.forEach(result => {
        for (const [host, info] of Object.entries(result)) {
            const box = document.createElement("div");
            box.className = "result-box";

            if ("error" in info) {
                box.innerHTML = `<strong>Error scanning ${host}:</strong> ${info.error}`;
            } else {
                let output = `
                    <strong>Host:</strong> ${host}<br>
                    <strong>Hostname:</strong> ${info.hostname || "Unknown"}<br>
                    <strong>State:</strong> ${info.state}<br>
                `;

                if (info.os_match.length > 0) {
                    output += `<strong>Possible OS:</strong><ul>`;
                    info.os_match.forEach(os_info => {
                        output += `<li>${os_info.name} (${os_info.accuracy}% accuracy)</li>`;
                    });
                    output += `</ul>`;
                }

                output += `<strong>Port Status:</strong><ul>`;
                for (const [proto, ports] of Object.entries(info.protocols)) {
                    for (const [port, pinfo] of Object.entries(ports)) {
                        output += `<li>${proto.toUpperCase()} ${port}: ${pinfo.name} - <b>${pinfo.state}</b></li>`;
                    }
                }
                output += `</ul>`;

                box.innerHTML = output;
            }

            resultsDiv.appendChild(box);
        }
    });
}
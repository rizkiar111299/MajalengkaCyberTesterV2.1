import os
from jinja2 import Template
from collections import Counter
import datetime
import webbrowser
import re

def sanitize_filename(filename):
    return re.sub(r'[<>:"/\\|?*]+', '_', filename)

def generate_report(url, info, vulnerabilities, open_ports):
    report_template = """
    <html>
    <head>
        <title>Security Report for {{ url }}</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.3/css/jquery.dataTables.css">
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                color: #333;
            }
            .container {
                margin-top: 20px;
                padding: 20px;
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: #333;
                color: #fff;
                padding: 20px;
                border-radius: 8px 8px 0 0;
            }
            .header h1 {
                margin: 0;
            }
            .badge {
                font-size: 1em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Report for {{ url }}</h1>
            </div>
            
            <h2>Information Gathering</h2>
            <table id="info-table" class="table table-striped">
                <thead>
                    <tr>
                        <th>Key</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {% for key, value in info.items() %}
                    <tr>
                        <td>{{ key }}</td>
                        <td>{{ value }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <h2>Open Ports</h2>
            <table id="ports-table" class="table table-striped">
                <thead>
                    <tr>
                        <th>Port</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port in open_ports %}
                    <tr>
                        <td>{{ port }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <h2>Vulnerabilities</h2>
            <div class="row">
                {% for type, count in vuln_counts.items() %}
                <div class="col-md-4">
                    <div class="alert alert-warning">
                        <strong>{{ type }}</strong> <span class="badge badge-pill badge-danger">{{ count }}</span>
                    </div>
                </div>
                {% endfor %}
            </div>
            <table id="vuln-table" class="table table-striped">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Type</th>
                        <th>Payload</th>
                        <th>Method</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in vulnerabilities %}
                    <tr>
                        <td>{{ vuln[0] }}</td>
                        <td>{{ vuln[1] }}</td>
                        <td>{{ vuln[2] }}</td>
                        <td>{{ vuln[3] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
        <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.11.3/js/jquery.dataTables.js"></script>
        <script>
            $(document).ready(function() {
                $('#info-table').DataTable();
                $('#ports-table').DataTable();
                $('#vuln-table').DataTable();
            });
        </script>
    </body>
    </html>
    """
    tanggal = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    vuln_counts = Counter(vuln[1] for vuln in vulnerabilities)

    template = Template(report_template)
    report_html = template.render(url=url, info=info, vulnerabilities=vulnerabilities, open_ports=open_ports, vuln_counts=vuln_counts)

    sanitized_url = sanitize_filename(url)
    report_dir = os.path.join(os.getcwd(), "report")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{sanitized_url}_{tanggal}.html")

    with open(report_path, "w") as report_file:
        report_file.write(report_html)
    
    print(f"Report generated: {report_path}")

    # Buka laporan di browser default untuk mencetak
    webbrowser.open(f"file://{report_path}")
import os
from jinja2 import Template

def generate_report(url, info, vulnerabilities, open_ports):
    report_template = """
    <html>
    <head>
        <title>Security Report for {{ url }}</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
                color: #333;
            }
            .container {
                width: 80%;
                margin: auto;
                overflow: hidden;
            }
            header {
                background: #333;
                color: #fff;
                padding-top: 30px;
                min-height: 70px;
                border-bottom: #77aaff 3px solid;
            }
            header a {
                color: #fff;
                text-decoration: none;
                text-transform: uppercase;
                font-size: 16px;
            }
            header ul {
                padding: 0;
                list-style: none;
                display: flex;
                justify-content: space-around;
            }
            header li {
                display: inline;
                padding: 0 20px 0 20px;
            }
            table {
                width: 100%;
                margin: 20px 0;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            h1, h2 {
                color: #333;
            }
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <h1>Security Report for {{ url }}</h1>
            </div>
        </header>
        <div class="container">
            <h2>Information Gathering</h2>
            <table>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
                {% for key, value in info.items() %}
                <tr>
                    <td>{{ key }}</td>
                    <td>{{ value }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h2>Open Ports</h2>
            <table>
                <tr>
                    <th>Port</th>
                </tr>
                {% for port in open_ports %}
                <tr>
                    <td>{{ port }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Type</th>
                    <th>Payload</th>
                    <th>Method</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln[0] }}</td>
                    <td>{{ vuln[1] }}</td>
                    <td>{{ vuln[2] }}</td>
                    <td>{{ vuln[3] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    """

    template = Template(report_template)
    report_html = template.render(url=url, info=info, vulnerabilities=vulnerabilities, open_ports=open_ports)

    report_path = os.path.join(os.getcwd(), "security_report.html")
    with open(report_path, "w") as report_file:
        report_file.write(report_html)
    
    print(f"Report generated: {report_path}")
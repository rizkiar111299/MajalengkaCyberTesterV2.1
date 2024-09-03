import os
from jinja2 import Template

def generate_report(url, info, vulnerabilities, open_ports):
    report_template = """
    <html>
    <head>
        <title>Security Report for {{ url }}</title>
    </head>
    <body>
        <h1>Security Report for {{ url }}</h1>
        
        <h2>Information Gathering</h2>
        <table border="1">
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
        
        <h2>Vulnerabilities</h2>
        <table border="1">
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
        
        <h2>Open Ports</h2>
        <table border="1">
            <tr>
                <th>Port</th>
            </tr>
            {% for port in open_ports %}
            <tr>
                <td>{{ port }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """

    template = Template(report_template)
    report_html = template.render(url=url, info=info, vulnerabilities=vulnerabilities, open_ports=open_ports)

    report_path = os.path.join(os.getcwd(), "security_report.html")
    with open(report_path, "w") as report_file:
        report_file.write(report_html)
    
    print(f"Report generated: {report_path}")
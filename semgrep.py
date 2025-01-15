import json
import glob
import os
from html import escape

# Gather all JSON files in the current directory
json_files = glob.glob("*.json")

# Process each JSON file and generate a separate HTML file for each
for json_file in json_files:
    try:
        # Read the JSON file
        with open(json_file, "r") as file:
            content = file.read().strip()
            
            # Skip empty files
            if not content:
                print(f"Skipping empty file: {json_file}")
                continue
            
            semgrep_data = json.loads(content)

        # Initialize the HTML content for the current JSON file
        html_content = f"""
        <html>
        <head>
            <title>Semgrep Report for {json_file}</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/datatables.net-dt/css/jquery.dataTables.min.css">
            <style>
                body {{
                    font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f4;
                }}
                .container {{
                    max-width: 100%; width: 95%; margin: auto; padding: 30px; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow-x: auto;
                }}
                h1 {{
                    text-align: center; color: #333; font-size: 24px; margin-bottom: 20px;
                }}
                table {{
                    width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: auto;
                }}
                th, td {{
                    padding: 12px; border: 1px solid #ddd; text-align: left; word-wrap: break-word;
                }}
                th {{
                    background-color: #f2f2f2; color: #333; font-weight: bold;
                }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .impact-high {{ color: red; font-weight: bold; }}
                .impact-medium {{ color: orange; font-weight: bold; }}
                .impact-low {{ color: green; font-weight: bold; }}
                .impact-unknown {{ color: gray; font-weight: bold; }}
                .code-snippet {{
                    background-color: #f8f8f8; padding: 12px; border: 1px solid #ddd; font-family: monospace;
                    white-space: pre-wrap;
                }}
                .highlight {{
                    background-color: yellow; font-weight: bold;
                }}
                .no-results {{ text-align: center; color: #888; }}
                
                /* Media Queries for mobile responsiveness */
                @media (max-width: 768px) {{
                    h1 {{ font-size: 20px; }}
                    th, td {{ padding: 8px; font-size: 14px; }}
                    .container {{ padding: 10px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Semgrep Scan Report for {json_file}</h1>
                <table id="reportTable">
                    <thead>
                        <tr>
                            <th>CWE</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Severity</th>
                            <th>Impact</th>
                            <th>Likelihood</th>
                            <th>Message</th>
                            <th>Code</th>
                            <th>Semgrep URL</th>
                            <th>Dataflow Trace</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        # Add a message if there are no results
        if not semgrep_data.get("results", []):
            html_content += "<tr class='no-results'><td colspan='10'>No issues found in this report.</td></tr>"

        # Add each finding in the JSON file to the HTML table
        for result in semgrep_data.get("results", []):
            file_path = escape(result.get("path", "N/A"))
            line = result.get("start", {}).get("line", "N/A")
            severity = result.get("extra", {}).get("severity", "Unknown")
            
            # Accessing impact and likelihood from metadata inside extra
            metadata = result.get("extra", {}).get("metadata", {})
            CWE = metadata.get("cwe", "N/A")
            impact = metadata.get("impact", "N/A")
            likelihood = metadata.get("likelihood", "N/A")
            
            message = escape(result.get("extra", {}).get("message", "No message available."))
            
            # Semgrep URL from metadata > semgrepdev > source
            semgrep_url = result.get("extra", {}).get("metadata", {}).get("semgrep.dev", {}).get("rule", {}).get("url", "No Link available")
            
            # Accessing dataflow trace
            dataflow_trace = result.get("extra", {}).get("dataflow_trace", {})
            taint_sink = dataflow_trace.get("taint_sink", "N/A")
            taint_source = dataflow_trace.get("taint_source", "N/A")
            intermediate_vars = dataflow_trace.get("intermediate_vars", "N/A")
            
            # Check if lines are provided and extract the code snippet
            code_snippet = "No code available."
            lines = result.get("extra", {}).get("lines", [])
            if isinstance(lines, list) and len(lines) > 0:
                code_snippet = "\n".join(lines)
            elif isinstance(lines, str) and lines:
                code_snippet = lines  # If lines are stored as a single string

            # If there is a vulnerable parameter, highlight it in the code snippet
            vulnerable_param = None
            taint_source_list = result.get("extra", {}).get("dataflow_trace", {}).get("taint_source", [])
            if len(taint_source_list) > 1:
                vulnerable_param = taint_source_list[1][1]
                
            code_snippet = escape(code_snippet)
            if vulnerable_param:
                code_snippet = code_snippet.replace(vulnerable_param, f'<span class="highlight">{vulnerable_param}</span>')

            severity_class = f"severity-{severity.lower()}" if severity else "severity-unknown"
            
            if impact == "High":
                impact_class = "impact-high"
            elif impact == "Medium":
                impact_class = "impact-medium"
            elif impact == "Low":
                impact_class = "impact-low"
            else:
                impact_class = "impact-unknown"

            # Add the result to the HTML table
            html_content += f"""
            <tr>
                <td>{CWE}</td>
                <td>{file_path}</td>
                <td>{line}</td>
                <td class="{severity_class}">{severity}</td>
                <td><span class="{impact_class}">{impact}</span></td>
                <td>{likelihood}</td>
                <td>{message}</td>
                <td><pre class="code-snippet">{code_snippet}</pre></td>
                <td><a href="{semgrep_url}" target="_blank">View Rule</a></td>
                <td>
                    <p><strong>Taint Sink:</strong> {taint_sink}</p>
                    <p><strong>Taint Source:</strong> {taint_source}</p>
                    <p><strong>Intermediate Vars:</strong> {intermediate_vars}</p>
                </td>
            </tr>
            """
        
        # Close the HTML tags
        html_content += """
                    </tbody>
                </table>
            </div>

            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/datatables.net/js/jquery.dataTables.min.js"></script>
            <script>
                $(document).ready(function() {{
                    $('#reportTable').DataTable({
                        "paging": true,
                        "searching": true,
                        "ordering": true,
                        "info": false
                    });
                }});
            </script>
        </body>
        </html>
        """
        
        # Create an HTML file with the same name as the JSON file, but with .html extension
        html_filename = os.path.splitext(json_file)[0] + "_Report.html"
        with open(html_filename, "w") as html_file:
            html_file.write(html_content)
        
        print(f"HTML report generated: {html_filename}")

    except json.JSONDecodeError:
        print(f"Error decoding JSON in file: {json_file}")
    except Exception as e:
        print(f"An error occurred while processing {json_file}: {e}")

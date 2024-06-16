import json
import os

def print_vdr_table(vdr_path):
    with open(vdr_path, 'r') as f:
        vdr_data = json.load(f)
    
    if 'vulnerabilities' not in vdr_data:
        print('No vulnerabilities found.')
        return
    
    vulnerabilities = vdr_data['vulnerabilities']
    if not vulnerabilities:
        print('No vulnerabilities found.')
        return
    
    headers = ['Package', 'Version', 'Vulnerability', 'Severity', 'Score', 'Fix Version']
    print(f'| {' | '.join(headers)} |')
    print(f'| {' | '.join(['---'] * len(headers))} |')
    
    for vuln in vulnerabilities:
        package_name = vuln.get('packageName', 'N/A')
        version = vuln.get('version', 'N/A')
        title = vuln.get('title', 'N/A')
        severity = vuln.get('severity', 'N/A')
        score = str(vuln.get('cvssScore', 'N/A'))
        fix_version = vuln.get('fixVersion', 'N/A')
        
        print(f'| {package_name} | {version} | {title} | {severity} | {score} | {fix_version} |')

vdr_path = './reports/bom.vdr.json'
if os.path.exists(vdr_path):
    print_vdr_table(vdr_path)
else:
    print('VDR file not found.')
    # Prints the VDR as a table in the logs
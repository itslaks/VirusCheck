from flask import Flask, request, render_template, jsonify
import requests
import base64

app = Flask(__name__)

VIRUSTOTAL_API_KEY = '4b4ae68cf38ed487342818091ad6ea879d11207e57049616f55fcd5c869233f9'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_website():
    website = request.form['website']
    if not website:
        return jsonify({'error': 'Website URL or domain is required'}), 400

    scan_results = scan_with_virustotal(website)
    if 'error' in scan_results:
        return jsonify(scan_results), 500

    optimized_results = optimize_results(scan_results)
    return jsonify(optimized_results)

def scan_with_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.post(VIRUSTOTAL_URL, headers=headers, data={'url': url})
    if response.status_code == 200:
        analysis_response = requests.get(f"{VIRUSTOTAL_URL}/{url_id}", headers=headers)
        if analysis_response.status_code == 200:
            return analysis_response.json()
        else:
            return {'error': f'Error fetching analysis: {analysis_response.status_code} {analysis_response.reason}'}
    else:
        return {'error': f'Error scanning website: {response.status_code} {response.reason}'}

def optimize_results(results):
    # Analyze the results and filter out unnecessary details
    # Identify false negatives and true positives
    # This is a simplified example, adjust according to actual API response structure
    if 'error' in results:
        return {'error': results['error']}

    positives = []
    negatives = []
    scans = results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    for scan, result in scans.items():
        if result['category'] == 'malicious':
            positives.append(f"{scan}: {result['result']}")
        else:
            negatives.append(f"{scan}: {result['result']}")

    return {
        'positives': positives,
        'negatives': negatives
    }

if __name__ == '__main__':
    app.run(debug=True)

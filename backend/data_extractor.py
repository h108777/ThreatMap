import requests

def get_data(url):
    response = requests.get(url)
    
    return response.json()

def get_data_from_nist():
    try:
        cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
        cve_data = get_data(cve_url)
        source_url = "https://services.nvd.nist.gov/rest/json/source/2.0?resultsPerPage=50"
        source_data = get_data(source_url)
        result = {
            "cve_data": cve_data['vulnerabilities'],
            "source_data": source_data['sources']
        }
        return result
    except Exception as e:
        get_data_from_nist()

        #gghh
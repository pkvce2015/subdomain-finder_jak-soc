import requests
import concurrent.futures
import argparse
import dns.resolver

# Define API keys (replace with your own)
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"
SHODAN_API_KEY = "your_shodan_api_key"
CENSYS_API_ID = "your_censys_api_id"
CENSYS_API_SECRET = "your_censys_api_secret"
CERTIFICATE_TRANSPARENCY_API = "https://crt.sh/?q=%25.{}&output=json"

# Passive Enumeration with VirusTotal
def virustotal_subdomains(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return [item['id'] for item in response.json().get('data', [])]
    return []

# Passive Enumeration with SecurityTrails
def securitytrails_subdomains(domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('subdomains', [])
    return []

# Passive Enumeration with Shodan
def shodan_subdomains(domain):
    url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get('subdomains', [])
    return []

# Passive Enumeration with Censys
def censys_subdomains(domain):
    url = "https://search.censys.io/api/v2/hosts/search"
    auth = (CENSYS_API_ID, CENSYS_API_SECRET)
    params = {"q": domain, "per_page": 100}
    response = requests.get(url, auth=auth, params=params)
    if response.status_code == 200:
        return [result['ip'] for result in response.json().get('results', [])]
    return []

# Passive Enumeration with Certificate Transparency Logs
def certificate_transparency_subdomains(domain):
    response = requests.get(CERTIFICATE_TRANSPARENCY_API.format(domain))
    if response.status_code == 200:
        return list(set([entry['name_value'] for entry in response.json()]))
    return []

# Active Enumeration using DNS resolution
def resolve_subdomain(subdomain, domain):
    try:
        dns.resolver.resolve(f"{subdomain}.{domain}", 'A')
        return f"{subdomain}.{domain}"
    except:
        return None

# Bruteforce using a wordlist
def brute_force_subdomains(domain, wordlist):
    found_subdomains = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:  # Increased threading
        futures = [executor.submit(resolve_subdomain, sub, domain) for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_subdomains.append(result)
    return found_subdomains

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast Subdomain Finder")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for brute force")
    args = parser.parse_args()
    
    domain = args.domain
    
    # Passive enumeration
    print("[*] Fetching subdomains from VirusTotal...")
    subdomains = virustotal_subdomains(domain)
    
    print("[*] Fetching subdomains from SecurityTrails...")
    subdomains += securitytrails_subdomains(domain)
    
    print("[*] Fetching subdomains from Shodan...")
    subdomains += shodan_subdomains(domain)
    
    print("[*] Fetching subdomains from Censys...")
    subdomains += censys_subdomains(domain)
    
    print("[*] Fetching subdomains from Certificate Transparency logs...")
    subdomains += certificate_transparency_subdomains(domain)
    
    subdomains = list(set(subdomains))
    print(f"[+] Found {len(subdomains)} subdomains passively")
    
    # Brute-force subdomains if wordlist is provided
    if args.wordlist:
        print("[*] Starting brute-force enumeration...")
        with open(args.wordlist, 'r') as f:
            wordlist = [line.strip() for line in f]
        subdomains += brute_force_subdomains(domain, wordlist)
    
    # Display results
    subdomains = list(set(subdomains))
    print(f"[+] Total unique subdomains found: {len(subdomains)}")
    for sub in subdomains:
        print(sub)
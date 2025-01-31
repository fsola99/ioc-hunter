import requests

url = "https://www.virustotal.com/api/v3/files/ced3557310b98b8a1ede8c1c24c4997a2eb2e05e561dd0b6ca36627f0d987d14"

headers = {
    "accept": "application/json",
    "x-apikey": "REDACTED_API_KEY"
}

response = requests.get(url, headers=headers)

print(response.text)
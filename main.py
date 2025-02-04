from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
import io
import requests
import pandas as pd
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VirusTotal API Wrapper",
    description="An API to query VirusTotal information with additional functionalities.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount the "static" folder to serve HTML, CSS, and JS files
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory storage for results and API key
results_memory = []
user_api_key = None  # Store the user's API key

# Pydantic model for API key input
class ApiKeyInput(BaseModel):
    api_key: str

@app.get("/")
def serve_index():
    """Serve the index.html file at the root endpoint."""
    return FileResponse("static/index.html")

@app.post("/set-api-key")
def set_api_key(api_key_input: ApiKeyInput):
    """Set the user's VirusTotal API key."""
    global user_api_key
    if not api_key_input.api_key:
        raise HTTPException(status_code=400, detail="API key is required.")
    user_api_key = api_key_input.api_key
    logger.info("VirusTotal API key set successfully.")
    return {"message": "API key set successfully"}

@app.get("/check-hash/{file_hash}")
def check_hash(file_hash: str):
    """Check a file hash in VirusTotal using the user's API key."""
    global user_api_key
    if not user_api_key:
        raise HTTPException(status_code=400, detail="VirusTotal API key is not set. Please provide an API key.")

    headers = {"x-apikey": user_api_key}
    vt_base_url = "https://www.virustotal.com/api/v3/"

    # Get basic file information
    file_info_response = requests.get(f"{vt_base_url}files/{file_hash}", headers=headers)
    if file_info_response.status_code != 200:
        logger.error(f"Could not retrieve information for hash: {file_hash}")
        raise HTTPException(status_code=file_info_response.status_code, detail="Could not retrieve information for the hash.")

    file_info_data = file_info_response.json()
    attributes = file_info_data.get("data", {}).get("attributes", {})

    # Get behavior and MITRE TTPs information
    behaviour_response = requests.get(f"{vt_base_url}files/{file_hash}/behaviour_mitre_trees", headers=headers)
    mitre_ttps = {}
    if behaviour_response.status_code == 200:
        behaviour_data = behaviour_response.json()
        for sandbox_name, sandbox_data in behaviour_data.get("data", {}).items():
            tactics = []
            for tactic in sandbox_data.get("tactics", []):
                techniques = []
                for technique in tactic.get("techniques", []):
                    signatures = []
                    for signature in technique.get("signatures", []):
                        signatures.append({
                            "Severity": signature.get("severity", "N/A"),
                            "Description": signature.get("description", "N/A")
                        })
                    techniques.append({
                        "ID": technique.get("id", "N/A"),
                        "Name": technique.get("name", "N/A"),
                        "Description": technique.get("description", "N/A"),
                        "MITRE Link": technique.get("link", "N/A"),
                        "Signatures": signatures
                    })
                tactics.append({
                    "ID": tactic.get("id", "N/A"),
                    "Name": tactic.get("name", "N/A"),
                    "Description": tactic.get("description", "N/A"),
                    "MITRE Link": tactic.get("link", "N/A"),
                    "Techniques": techniques
                })
            mitre_ttps[sandbox_name] = tactics

    # Get sandbox behavior information
    sandbox_response = requests.get(f"{vt_base_url}files/{file_hash}/behaviour_summary", headers=headers)
    sandbox_info = {}
    if sandbox_response.status_code == 200:
        sandbox_data = sandbox_response.json().get("data", {})
        sandbox_info = {
            "Services Started": sandbox_data.get("services_started", []),
            "Processes Created": sandbox_data.get("processes_created", []),
            "Mutexes Created": sandbox_data.get("mutexes_created", []),
            "DNS Lookups": sandbox_data.get("dns_lookups", []),
            "Files Opened": sandbox_data.get("files_opened", []),
            "Modules Loaded": sandbox_data.get("modules_loaded", []),
            "Registry Keys Opened": sandbox_data.get("registry_keys_opened", []),
            "Processes Terminated": sandbox_data.get("processes_terminated", []),
        }

    # Financial sector relevant information
    financial_info = {
        "Is Ransomware?": "ransomware" in attributes.get("tags", []),
        "Is Banking Trojan?": "banker" in attributes.get("tags", []),
        "Is Credential Stealer?": "credential-stealing" in attributes.get("tags", []),
    }

    # Format the final response
    formatted_data = {
        "File Analysis": {
            "MD5": attributes.get("md5", "N/A"),
            "SHA-1": attributes.get("sha1", "N/A"),
            "SHA-256": attributes.get("sha256", "N/A"),
            "File Type": attributes.get("type_description", "Unknown"),
            "File Size (bytes)": attributes.get("size", "N/A")
        },
        "VirusTotal Analysis": {
            "Malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "Suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "Undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "Tags": ", ".join(attributes.get("tags", [])) or "N/A",
            "Associated Names": ", ".join(attributes.get("names", [])) or "N/A"
        },
        "Additional Information": {
            "First Analysis Date": attributes.get("first_submission_date", "N/A"),
            "Last Analysis Date": attributes.get("last_submission_date", "N/A"),
            "MITRE TTPs": mitre_ttps,
            "Sandbox Information": sandbox_info,
            "Financial Sector Information": financial_info
        }
    }

    results_memory.append(formatted_data)
    logger.info(f"Information retrieved for hash: {file_hash}")
    return JSONResponse(content=formatted_data, media_type="application/json")


@app.get("/download-csv")
def download_csv():
    """Generate and download a CSV file from the in-memory results."""
    if not results_memory:
        return {"message": "No data available"}

    # Dictionary to store CSV data
    csv_data = {}

    # Extract basic information (single value fields)
    result = results_memory[0]  # Assuming only one result (one hash)
    file_analysis = result.get("File Analysis", {})
    vt_analysis = result.get("VirusTotal Analysis", {})
    additional_info = result.get("Additional Information", {})
    sandbox_info = additional_info.get("Sandbox Information", {})
    financial_info = additional_info.get("Financial Sector Information", {})

    # Add single-value fields
    csv_data["MD5"] = [file_analysis.get("MD5", "N/A")]
    csv_data["SHA-1"] = [file_analysis.get("SHA-1", "N/A")]
    csv_data["SHA-256"] = [file_analysis.get("SHA-256", "N/A")]
    csv_data["File Type"] = [file_analysis.get("File Type", "N/A")]
    csv_data["File Size (bytes)"] = [file_analysis.get("File Size (bytes)", "N/A")]

    csv_data["Malicious"] = [vt_analysis.get("Malicious", "N/A")]
    csv_data["Suspicious"] = [vt_analysis.get("Suspicious", "N/A")]
    csv_data["Undetected"] = [vt_analysis.get("Undetected", "N/A")]
    csv_data["Tags"] = [vt_analysis.get("Tags", "N/A")]
    csv_data["Associated Names"] = [vt_analysis.get("Associated Names", "N/A")]

    csv_data["First Analysis Date"] = [additional_info.get("First Analysis Date", "N/A")]
    csv_data["Last Analysis Date"] = [additional_info.get("Last Analysis Date", "N/A")]

    csv_data["Services Started"] = sandbox_info.get("Services Started", [])
    csv_data["Processes Created"] = sandbox_info.get("Processes Created", [])
    csv_data["Mutexes Created"] = sandbox_info.get("Mutexes Created", [])
    csv_data["DNS Lookups"] = [f"{dns['hostname']}: {', '.join(dns['resolved_ips'])}" for dns in sandbox_info.get("DNS Lookups", [])]
    csv_data["Files Opened"] = sandbox_info.get("Files Opened", [])
    csv_data["Modules Loaded"] = sandbox_info.get("Modules Loaded", [])
    csv_data["Registry Keys Opened"] = sandbox_info.get("Registry Keys Opened", [])
    csv_data["Processes Terminated"] = sandbox_info.get("Processes Terminated", [])

    csv_data["Is Ransomware?"] = [financial_info.get("Is Ransomware?", "N/A")]
    csv_data["Is Banking Trojan?"] = [financial_info.get("Is Banking Trojan?", "N/A")]
    csv_data["Is Credential Stealer?"] = [financial_info.get("Is Credential Stealer?", "N/A")]

    # Extract MITRE TTPs from each sandbox (only technique IDs)
    mitre_ttps = additional_info.get("MITRE TTPs", {})
    for sandbox_name, ttp_list in mitre_ttps.items():
        column_name = f"MITRE TTPs_{sandbox_name}"
        technique_ids = []
        for ttp in ttp_list:
            if "Techniques" in ttp:
                for technique in ttp["Techniques"]:
                    technique_ids.append(technique.get("ID", "N/A"))
        csv_data[column_name] = technique_ids

    # Create a DataFrame from the dictionary
    df = pd.DataFrame({key: pd.Series(value) for key, value in csv_data.items()})

    # Create an in-memory buffer for the CSV
    stream = io.StringIO()
    df.to_csv(stream, index=False)

    # Configure the response to download the CSV
    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=results.csv"
    return response


@app.delete("/clear-results")
def clear_results():
    """Clear all results stored in memory."""
    results_memory.clear()
    logger.info("Results cleared from memory.")
    return {"message": "All results have been cleared."}
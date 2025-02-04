# IoC Hunter

This is a FastAPI-based wrapper for the VirusTotal API. It allows users to query VirusTotal for file hash information, store results in memory, and download the results as a CSV file. The API also provides a simple HTML interface for interacting with the backend.

---

## Features

- **Hash Lookup**: Query VirusTotal for detailed information about a file hash.
- **CSV Export**: Download the results of your queries as a CSV file.
- **In-Memory Storage**: Store query results temporarily in memory.
- **HTML Interface**: A user-friendly web interface for interacting with the API.

---

## Endpoints

### 1. **Set API Key**
- **Method**: `POST`
- **Endpoint**: `/set-api-key`
- **Description**: Set your VirusTotal API key for use in subsequent requests.
- **Request Body**:
  ```json
  {
    "api_key": "your_virustotal_api_key"
  }
  ```
- **Expected Response**:
  ```json
  {
    "message": "API key set successfully"
  }
  ```

### 2. **Check Hash**
- **Method**: `GET`
- **Endpoint**: `/check-hash/{file_hash}`
- **Description**: Query VirusTotal for information about a specific file hash.
- **Expected Response**:
  ```json
  {
    "File Analysis": { ... },
    "VirusTotal Analysis": { ... },
    "Additional Information": { ... }
  }
  ```

### 3. **Download CSV**
- **Method**: `GET`
- **Endpoint**: `/download-csv`
- **Description**: Download the results of your queries as a CSV file.
- **Expected Response**: A CSV file named `results.csv`.

### 4. **Clear Results**
- **Method**: `DELETE`
- **Endpoint**: `/clear-results`
- **Description**: Clear all results stored in memory.
- **Expected Response**:
  ```json
  {
    "message": "All results have been cleared."
  }
  ```

---

## How to Run the API

### Prerequisites
- Python 3.7 or higher
- FastAPI (`pip install fastapi`)
- Uvicorn (`pip install uvicorn`)
- Requests (`pip install requests`)
- Pandas (`pip install pandas`)

### Steps
1. Clone the repository or download the code.
2. Navigate to the project directory.
3. Install the required dependencies:
   ```bash
   pip install fastapi uvicorn requests pandas
   ```
4. Run the FastAPI server:
   ```bash
   uvicorn main:app --reload
   ```
5. The API will be available at `http://127.0.0.1:8000`.

---

## Using the HTML Interface

### Step 1: Set Your VirusTotal API Key
1. Open the HTML interface by navigating to `http://127.0.0.1:8000` in your browser.
2. Enter your VirusTotal API key in the "Enter your VirusTotal API Key" field.
3. Click the "Set API Key" button. You should see a success message.

### Step 2: Search for a Hash
1. Enter a file hash (MD5, SHA-1, or SHA-256) in the "Insert Indicator (Hash, IP Address, Or Domain)" field.
2. Click the "Search" button.
3. The results will be displayed in collapsible sections below the search bar.

### Step 3: Download Results as CSV
1. After performing a search, click the "Download CSV" button to download the results as a CSV file.

### Step 4: Clear Results
1. To clear all stored results, click the "Clear Results" button.

---

## Example Workflow

1. Set your VirusTotal API key:
   - Enter your API key and click "Set API Key".
2. Search for a hash:
   - Enter a hash (e.g., `ced3557310b98b8a1ede8c1c24c4997a2eb2e05e561dd0b6ca36627f0d987d14`) and click "Search".
3. View the results:
   - The results will be displayed in collapsible sections.
4. Download the results:
   - Click "Download CSV" to save the results as a CSV file.
5. Clear the results:
   - Click "Clear Results" to remove all stored data.

---

## Troubleshooting

- **API Key Not Set**: Ensure you set your VirusTotal API key before making any queries.
- **Invalid Hash**: Ensure the hash you are querying is valid (MD5, SHA-1, or SHA-256).
- **No Results**: If no results are displayed, check the hash and ensure it exists in VirusTotal's database.

---

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for providing the API.
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework.

---

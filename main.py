from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, StreamingResponse
import io
import requests
import pandas as pd
import os

# Configuración de la API de VirusTotal
VT_API_KEY = "REDACTED_API_KEY"
VT_BASE_URL = "https://www.virustotal.com/api/v3/"

app = FastAPI()

# Montar la carpeta "static" para servir el HTML, CSS y JS
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    """Redirigir la raíz al index.html."""
    return FileResponse("static/index.html")

# Lista en memoria para almacenar los resultados
results_memory = []

headers = {"x-apikey": VT_API_KEY}

@app.post("/add-result")
def add_result(result: dict):
    """Agrega un resultado a la memoria."""
    results_memory.append(result)
    return {"message": "Result added successfully", "data": result}

@app.get("/download-csv")
def download_csv():
    """Devuelve un CSV con los resultados en memoria."""
    if not results_memory:
        return {"message": "No data available"}

    df = pd.DataFrame(results_memory)
    stream = io.StringIO()
    df.to_csv(stream, index=False)

    response = StreamingResponse(
        io.StringIO(stream.getvalue()), media_type="text/csv"
    )
    response.headers["Content-Disposition"] = "attachment; filename=results.csv"
    return response

@app.get("/check-hash/{file_hash}")
def check_hash(file_hash: str):
    """Consulta un hash en VirusTotal y devuelve información formateada."""
    # Obtener información básica del archivo
    file_info_response = requests.get(f"{VT_BASE_URL}files/{file_hash}", headers=headers)
    if file_info_response.status_code != 200:
        return JSONResponse(content={"error": "No se pudo obtener información del hash"}, media_type="application/json")

    file_info_data = file_info_response.json()
    attributes = file_info_data.get("data", {}).get("attributes", {})

    # Obtener información de comportamiento y TTPs de MITRE
    behaviour_response = requests.get(f"{VT_BASE_URL}files/{file_hash}/behaviour_mitre_trees", headers=headers)
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
                            "Severidad": signature.get("severity", "N/A"),
                            "Descripción": signature.get("description", "N/A")
                        })
                    techniques.append({
                        "ID": technique.get("id", "N/A"),
                        "Nombre": technique.get("name", "N/A"),
                        "Descripción": technique.get("description", "N/A"),
                        "Enlace MITRE": technique.get("link", "N/A"),
                        "Firmas": signatures
                    })
                tactics.append({
                    "ID": tactic.get("id", "N/A"),
                    "Nombre": tactic.get("name", "N/A"),
                    "Descripción": tactic.get("description", "N/A"),
                    "Enlace MITRE": tactic.get("link", "N/A"),
                    "Técnicas": techniques
                })
            mitre_ttps[sandbox_name] = tactics


    # Información relevante para una empresa financiera
    financial_info = {
        "Es Ransomware?": "ransomware" in attributes.get("tags", []),
        "Es un Banking Trojan (aka Banker)?": "banker" in attributes.get("tags", [])
    }

    # Formatear la respuesta final
    formatted_data = {
        "Archivo Analizado": {
            "MD5": attributes.get("md5", "N/A"),
            "SHA-1": attributes.get("sha1", "N/A"),
            "SHA-256": attributes.get("sha256", "N/A"),
            "Tipo de Archivo": attributes.get("type_description", "Desconocido"),
            "Tamaño (bytes)": attributes.get("size", "N/A")
        },
        "Análisis de VirusTotal": {
            "Malicioso": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "Sospechoso": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "No Detectado": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "Etiquetas": ", ".join(attributes.get("tags", [])) or "N/A",
            "Nombres Asociados": ", ".join(attributes.get("names", [])) or "N/A"
        },
        "Información Adicional": {
            "Fecha de Primer Análisis": attributes.get("first_submission_date", "N/A"),
            "Fecha de Último Análisis": attributes.get("last_submission_date", "N/A"),
            "MITRE TTPs": mitre_ttps,
            "Información relacionada con el sector financiero": financial_info
        }
    }

    results_memory.append(formatted_data)
    return JSONResponse(content=formatted_data, media_type="application/json")
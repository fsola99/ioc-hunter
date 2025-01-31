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
    response = requests.get(f"{VT_BASE_URL}files/{file_hash}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

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
                "Sistema Operativo Detectado": ", ".join(attributes.get("os_execution_envs", [])) or "N/A",
                "Reglas YARA Coincidentes": attributes.get("crowdsourced_yara_results", [])
            }
        }

        results_memory.append(formatted_data)
        return JSONResponse(content=formatted_data, media_type="application/json")
    else:
        return JSONResponse(content={"error": "No se pudo obtener información del hash"}, media_type="application/json")

import requests
from bs4 import BeautifulSoup
import json
import pandas as pd

# Lista de TTPs
ttps = [
    "T1003", "T1005", "T1010", "T1012", "T1018", "T1027", "T1027.002", "T1027.009", 
    "T1033", "T1036", "T1047", "T1053", "T1055", "T1056", "T1057", "T1059", 
    "T1064", "T1070", "T1071", "T1082", "T1083", "T1095", "T1106", "T1129", 
    "T1140", "T1485", "T1497", "T1518", "T1518.001", "T1539", "T1552", "T1552.001", 
    "T1555", "T1555.003", "T1560", "T1562", "T1562.001", "T1564", "T1564.003", 
    "T1568", "T1571", "T1573", "T1574", "T1574.002"
]

# Diccionario para almacenar las mitigaciones
mitigations_data = {}

# Función para obtener las mitigaciones de una técnica
def get_mitigations(technique_id):
    url = f"https://attack.mitre.org/techniques/{technique_id}/"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Error al acceder a {url}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    mitigations = []

    # Buscar el encabezado de mitigaciones
    mitigations_header = soup.find("h2", {"id": "mitigations"})
    if not mitigations_header:
        return []

    # Buscar la tabla de mitigaciones justo después del encabezado
    mitigations_table = mitigations_header.find_next("table", {"class": "table table-bordered table-alternate mt-2"})
    if not mitigations_table:
        return []

    # Extraer las filas de la tabla (ignorar la fila de encabezado)
    rows = mitigations_table.find_all("tr")[1:]

    for row in rows:
        cols = row.find_all("td")
        if len(cols) >= 2:
            mitigation_id = cols[0].text.strip()  # Extraer el ID de la mitigación
            mitigation_name = cols[1].text.strip()  # Extraer el nombre de la mitigación
            mitigations.append(f"{mitigation_id} - {mitigation_name}")

    return mitigations

# Obtener las mitigaciones para cada técnica
for technique in ttps:
    mitigations = get_mitigations(technique)
    if mitigations:
        mitigations_data[technique] = mitigations
    print(f"Procesada técnica: {technique}")

# Guardar en JSON
with open("mitigations.json", "w") as file:
    json.dump(mitigations_data, file, indent=4)

# Convertir JSON a CSV
mitigations_list = []
for technique, mitigations in mitigations_data.items():
    for mitigation in mitigations:
        mitigations_list.append([mitigation])

# Crear DataFrame y guardar en CSV
df = pd.DataFrame(mitigations_list, columns=["Mitigations"])
df.to_csv("mitigations.csv", index=False)

print("Proceso completado. Los datos se han guardado en 'mitigations.json' y 'mitigations.csv'.")
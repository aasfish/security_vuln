import re
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class VulnerabilidadSimple:
    puerto_servicio: str
    nivel_amenaza: str
    descripcion: str = ""

@dataclass
class HostAnalisis:
    ip: str
    nombre_host: str
    vulnerabilidades: List[VulnerabilidadSimple]

def analizar_vulnerabilidades(filepath: str) -> Dict:
    """
    Analiza un archivo de reporte de vulnerabilidades en formato TXT.
    Retorna un diccionario con la información de vulnerabilidades por host.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            contenido = file.read()
            hosts_detalle = {}

            # Buscar secciones de host
            host_sections = re.finditer(r'Host ([\d\.]+)\n\*+\n(.*?)(?=(?:Host \d|$))', contenido, re.DOTALL)

            for host_match in host_sections:
                ip = host_match.group(1)
                host_content = host_match.group(2)

                # Extraer nombre del host
                nombre_host = ""
                host_name_match = re.search(rf'{ip}\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(.*?)$', contenido, re.MULTILINE)
                if host_name_match:
                    nombre_host = host_name_match.group(1).strip()

                vulnerabilidades = []

                # Buscar sección de puertos y servicios
                port_section = re.search(r'Port Summary.*?\n--+\n\nService \(Port\)\s+Threat Level\n(.*?)(?=\n\n)', host_content, re.DOTALL)
                if port_section:
                    port_lines = port_section.group(1).strip().split('\n')
                    for line in port_lines:
                        if line.strip():
                            # Dividir la línea en puerto/servicio y nivel de amenaza
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                puerto_servicio = parts[0]
                                nivel_amenaza = parts[-1]
                                descripcion = ' '.join(parts[1:-1]) if len(parts) > 2 else ""

                                vulnerabilidades.append(VulnerabilidadSimple(
                                    puerto_servicio=puerto_servicio,
                                    nivel_amenaza=nivel_amenaza,
                                    descripcion=descripcion
                                ))

                if vulnerabilidades:
                    hosts_detalle[ip] = HostAnalisis(
                        ip=ip,
                        nombre_host=nombre_host,
                        vulnerabilidades=vulnerabilidades
                    )

            return {
                'hosts_detalle': {
                    ip: {
                        'nombre_host': host.nombre_host,
                        'vulnerabilidades': [
                            {
                                'puerto_servicio': v.puerto_servicio,
                                'nivel_amenaza': v.nivel_amenaza,
                                'descripcion': v.descripcion
                            } for v in host.vulnerabilidades
                        ]
                    }
                    for ip, host in hosts_detalle.items()
                }
            }

    except Exception as e:
        raise Exception(f"Error al analizar el archivo: {str(e)}")
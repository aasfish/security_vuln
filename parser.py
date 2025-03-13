import re
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime

@dataclass
class DetalleVulnerabilidad:
    nvt: str
    oid: str
    nivel_amenaza: str
    puerto: str
    resumen: str
    impacto: str
    solucion: str
    producto_detectado: str = ""

@dataclass
class HostAnalisis:
    ip: str
    fecha_escaneo: str
    puertos_afectados: Dict[str, str]  # puerto -> nivel_amenaza
    vulnerabilidades: List[DetalleVulnerabilidad]
    nombre_host: str = ""

@dataclass
class ResultadoEscaneo:
    fecha_inicio: str
    fecha_fin: str
    nombre_tarea: str
    total_hosts: int
    total_vulnerabilidades: Dict[str, int]
    hosts_detalle: Dict[str, HostAnalisis] = None

def extraer_detalle_vulnerabilidad(contenido: str) -> List[DetalleVulnerabilidad]:
    """Extrae los detalles de vulnerabilidades de la sección de resultados por host"""
    vulnerabilidades = []

    # Buscar secciones de "Security Issues"
    security_sections = re.finditer(r'Issue\n-----\n(.*?)(?=\n\n(?:Issue|$))', contenido, re.DOTALL)

    for section in security_sections:
        texto = section.group(1)

        # Extraer campos principales
        nvt = re.search(r'NVT:\s+(.+?)(?=\n|$)', texto)
        oid = re.search(r'OID:\s+(.+?)(?=\n|$)', texto)
        threat = re.search(r'Threat:\s+(.+?)(?=\n|$)', texto)
        port = re.search(r'Port:\s+(.+?)(?=\n|$)', texto)

        # Extraer secciones más largas
        summary = re.search(r'Summary:\n(.*?)(?=\n\n|$)', texto, re.DOTALL)
        impact = re.search(r'Impact:\n(.*?)(?=\n\n|$)', texto, re.DOTALL)
        solution = re.search(r'Solution:\n(.*?)(?=\n\n|$)', texto, re.DOTALL)
        producto = re.search(r'Product detection result:\s+(.+?)(?=\n|$)', texto)

        vulnerabilidades.append(DetalleVulnerabilidad(
            nvt=nvt.group(1) if nvt else "No especificado",
            oid=oid.group(1) if oid else "No especificado",
            nivel_amenaza=threat.group(1) if threat else "No especificado",
            puerto=port.group(1) if port else "No especificado",
            resumen=summary.group(1).strip() if summary else "No disponible",
            impacto=impact.group(1).strip() if impact else "No disponible",
            solucion=solution.group(1).strip() if solution else "No disponible",
            producto_detectado=producto.group(1) if producto else ""
        ))

    return vulnerabilidades

def analizar_vulnerabilidades(filepath: str) -> Dict:
    """
    Analiza un archivo de reporte de vulnerabilidades en formato TXT.
    Retorna un diccionario con el resumen del análisis y detalles por host.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            contenido = file.read()

            # Extraer fechas del escaneo
            fecha_inicio = re.search(r'Scan started: (.+?) UTC', contenido)
            fecha_fin = re.search(r'Scan ended: (.+?) UTC', contenido)
            nombre_tarea = re.search(r'Task: (.+?)\n', contenido)

            # Extraer datos de hosts
            hosts_section = re.search(r'Host Summary\n\*+\n\nHost.*?\n(.*?)(?=\n\n)', contenido, re.DOTALL)
            if not hosts_section:
                raise Exception("No se encontró la sección de resumen de hosts")

            hosts_lines = hosts_section.group(1).strip().split('\n')
            hosts = []
            total_vulns = {'Alto': 0, 'Medio': 0, 'Bajo': 0, 'Log': 0, 'Falso Positivo': 0}
            hosts_detalle = {}

            # Procesar cada host en el resumen
            for line in hosts_lines:
                if 'Total:' in line:
                    continue

                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    alto = int(parts[1])
                    medio = int(parts[2])
                    bajo = int(parts[3])
                    log = int(parts[4])
                    falso_positivo = int(parts[5])
                    nombre_host = ' '.join(parts[6:]) if len(parts) > 6 else ''

                    total_vulns['Alto'] += alto
                    total_vulns['Medio'] += medio
                    total_vulns['Bajo'] += bajo
                    total_vulns['Log'] += log
                    total_vulns['Falso Positivo'] += falso_positivo

                    # Buscar detalles del host específico
                    host_section = re.search(
                        f'Host {ip}\n\\*+\\n(.*?)(?=(?:Host \\d|$))',
                        contenido,
                        re.DOTALL
                    )

                    if host_section:
                        host_content = host_section.group(1)
                        fecha_escaneo = re.search(r'Scanning of this host started at: (.+?) UTC', host_content)

                        # Extraer puertos afectados
                        puertos_section = re.search(r'Port Summary.*?\n(.*?)(?=\n\n)', host_content, re.DOTALL)
                        puertos_afectados = {}
                        if puertos_section:
                            for port_line in puertos_section.group(1).split('\n'):
                                if '/' in port_line and 'Threat Level' not in port_line:
                                    parts = port_line.strip().split()
                                    if len(parts) >= 2:
                                        puerto = parts[0]
                                        nivel = parts[-1]
                                        puertos_afectados[puerto] = nivel

                        # Extraer vulnerabilidades detalladas
                        vulnerabilidades = extraer_detalle_vulnerabilidad(host_content)

                        hosts_detalle[ip] = HostAnalisis(
                            ip=ip,
                            fecha_escaneo=fecha_escaneo.group(1) if fecha_escaneo else "",
                            puertos_afectados=puertos_afectados,
                            vulnerabilidades=vulnerabilidades,
                            nombre_host=nombre_host
                        )

            resultado = ResultadoEscaneo(
                fecha_inicio=fecha_inicio.group(1) if fecha_inicio else '',
                fecha_fin=fecha_fin.group(1) if fecha_fin else '',
                nombre_tarea=nombre_tarea.group(1) if nombre_tarea else '',
                total_hosts=len(hosts),
                total_vulnerabilidades=total_vulns,
                hosts_detalle=hosts_detalle
            )

            return {
                'resumen': {
                    'fecha_inicio': resultado.fecha_inicio,
                    'fecha_fin': resultado.fecha_fin,
                    'nombre_tarea': resultado.nombre_tarea,
                    'total_hosts': resultado.total_hosts,
                    'total_vulnerabilidades': resultado.total_vulnerabilidades
                },
                'hosts_detalle': {
                    ip: {
                        'nombre_host': host.nombre_host,
                        'fecha_escaneo': host.fecha_escaneo,
                        'puertos_afectados': host.puertos_afectados,
                        'vulnerabilidades': [vars(v) for v in host.vulnerabilidades]
                    }
                    for ip, host in resultado.hosts_detalle.items()
                }
            }

    except Exception as e:
        raise Exception(f"Error al analizar el archivo: {str(e)}")
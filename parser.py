import re
import logging
from dataclasses import dataclass
from typing import List, Dict

logger = logging.getLogger(__name__)

@dataclass
class Vulnerabilidad:
    nvt: str
    oid: str
    nivel_amenaza: str
    cvss: str
    puerto: str
    resumen: str
    impacto: str
    solucion: str
    metodo_deteccion: str = ""
    referencias: List[str] = None

@dataclass
class HostAnalisis:
    ip: str
    nombre_host: str
    vulnerabilidades: List[Vulnerabilidad]

def extraer_vulnerabilidad(texto: str) -> Vulnerabilidad:
    """Extrae los detalles de una vulnerabilidad del texto proporcionado"""
    nvt = re.search(r'NVT:\s+(.+?)(?=\n|$)', texto)
    oid = re.search(r'OID:\s+(.+?)(?=\n|$)', texto)
    threat = re.search(r'Threat:\s+(\w+)\s+\(CVSS:\s+([\d\.]+)\)', texto)
    port = re.search(r'Port:\s+(.+?)(?=\n|$)', texto)

    summary = re.search(r'Summary:\n(.*?)(?=\n\n|Impact:|$)', texto, re.DOTALL)
    impact = re.search(r'Impact:\n(.*?)(?=\n\n|Solution:|$)', texto, re.DOTALL)
    solution = re.search(r'Solution:\n(?:Solution type: [^\n]+\n)?(.*?)(?=\n\n|$)', texto, re.DOTALL)
    detection = re.search(r'Vulnerability Detection Method:\n(.*?)(?=\n\n|Details:|$)', texto, re.DOTALL)

    referencias = []
    refs_section = re.search(r'References:\n(.*?)(?=\n\n|$)', texto, re.DOTALL)
    if refs_section:
        for line in refs_section.group(1).split('\n'):
            if ':' in line and not line.startswith('    '):
                continue
            if line.strip():
                referencias.append(line.strip())

    return Vulnerabilidad(
        nvt=nvt.group(1) if nvt else "No especificado",
        oid=oid.group(1) if oid else "No especificado",
        nivel_amenaza=threat.group(1) if threat else "No especificado",
        cvss=threat.group(2) if threat else "No especificado",
        puerto=port.group(1) if port else "No especificado",
        resumen=summary.group(1).strip() if summary else "No disponible",
        impacto=impact.group(1).strip() if impact else "No disponible",
        solucion=solution.group(1).strip() if solution else "No disponible",
        metodo_deteccion=detection.group(1).strip() if detection else "",
        referencias=referencias
    )

def analizar_vulnerabilidades(filepath: str) -> Dict:
    """
    Analiza un archivo de reporte de vulnerabilidades en formato TXT.
    Retorna un diccionario con la información detallada de vulnerabilidades por host.
    """
    try:
        logger.debug(f"Iniciando análisis del archivo: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as file:
            contenido = file.read()
            logger.debug(f"Archivo leído correctamente, tamaño: {len(contenido)} caracteres")
            hosts_detalle = {}

            # Buscar secciones de host y sus vulnerabilidades
            host_sections = re.finditer(r'Security Issues for Host ([\d\.]+)\n-+\n\n((?:.*?\n)*?)(?=(?:Security Issues for Host|$))', contenido, re.DOTALL)

            for host_match in host_sections:
                ip = host_match.group(1)
                host_content = host_match.group(2)
                logger.debug(f"Procesando host {ip}")

                # Extraer nombre del host si existe
                nombre_host = ""
                host_name_match = re.search(rf'Host Information: {ip}\s+\((.*?)\)', contenido, re.MULTILINE)
                if host_name_match:
                    nombre_host = host_name_match.group(1).strip()
                elif re.search(rf'{ip}\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(.*?)$', contenido, re.MULTILINE):
                    # Buscar en el formato alternativo
                    nombre_host = re.search(rf'{ip}\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(.*?)$', contenido, re.MULTILINE).group(1).strip()

                # Limpiar el nombre del host de caracteres no deseados
                nombre_host = re.sub(r'[^\w\s\-\.]', '', nombre_host)
                if not nombre_host or nombre_host.isspace():
                    nombre_host = ""

                # Extraer vulnerabilidades
                vulnerabilidades = []
                vuln_sections = re.finditer(r'Issue\n-----\n(.*?)(?=\n\nIssue\n-----|$)', host_content, re.DOTALL)

                for vuln_match in vuln_sections:
                    try:
                        vuln = extraer_vulnerabilidad(vuln_match.group(1))
                        vulnerabilidades.append(vuln)
                        logger.debug(f"Vulnerabilidad procesada: {vuln.nvt} ({vuln.nivel_amenaza})")
                    except Exception as e:
                        logger.error(f"Error procesando vulnerabilidad: {str(e)}")
                        continue

                if vulnerabilidades:
                    hosts_detalle[ip] = {
                        'nombre_host': nombre_host,
                        'vulnerabilidades': [
                            {
                                'nvt': v.nvt,
                                'oid': v.oid,
                                'nivel_amenaza': v.nivel_amenaza,
                                'cvss': v.cvss,
                                'puerto': v.puerto,
                                'resumen': v.resumen,
                                'impacto': v.impacto,
                                'solucion': v.solucion,
                                'metodo_deteccion': v.metodo_deteccion,
                                'referencias': v.referencias
                            } for v in vulnerabilidades
                        ]
                    }
                    logger.info(f"Host {ip} procesado con {len(vulnerabilidades)} vulnerabilidades")

            if not hosts_detalle:
                logger.warning("No se encontraron hosts con vulnerabilidades")
                return None

            return {'hosts_detalle': hosts_detalle}

    except Exception as e:
        logger.error(f"Error al analizar el archivo: {str(e)}", exc_info=True)
        raise Exception(f"Error al analizar el archivo: {str(e)}")
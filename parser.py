import re
import logging
from dataclasses import dataclass
from typing import List, Dict

# Configuración de logging
logger = logging.getLogger(__name__)

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
        logger.debug(f"Iniciando análisis del archivo: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as file:
            contenido = file.read()
            logger.debug(f"Archivo leído correctamente, tamaño: {len(contenido)} caracteres")
            hosts_detalle = {}

            # Buscar secciones de host
            host_sections = re.finditer(r'Host ([\d\.]+)\n\*+\n(.*?)(?=(?:Host \d|$))', contenido, re.DOTALL)
            host_count = 0

            for host_match in host_sections:
                host_count += 1
                ip = host_match.group(1)
                host_content = host_match.group(2)
                logger.debug(f"Procesando host {ip}")

                # Extraer nombre del host
                nombre_host = ""
                host_name_match = re.search(rf'{ip}\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(.*?)$', contenido, re.MULTILINE)
                if host_name_match:
                    nombre_host = host_name_match.group(1).strip()
                    logger.debug(f"Nombre del host encontrado: {nombre_host}")

                vulnerabilidades = []

                # Buscar sección de puertos y servicios
                port_section = re.search(r'Port Summary.*?\n--+\n\nService \(Port\)\s+Threat Level\n(.*?)(?=\n\n)', host_content, re.DOTALL)
                if port_section:
                    port_lines = port_section.group(1).strip().split('\n')
                    logger.debug(f"Encontradas {len(port_lines)} líneas de puertos para el host {ip}")

                    for line in port_lines:
                        if line.strip():
                            # Dividir la línea en puerto/servicio y nivel de amenaza
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                puerto_servicio = parts[0]
                                nivel_amenaza = parts[-1]
                                descripcion = ' '.join(parts[1:-1]) if len(parts) > 2 else ""

                                logger.debug(f"Vulnerabilidad encontrada - Puerto: {puerto_servicio}, "
                                           f"Nivel: {nivel_amenaza}, Descripción: {descripcion}")

                                vulnerabilidades.append(VulnerabilidadSimple(
                                    puerto_servicio=puerto_servicio,
                                    nivel_amenaza=nivel_amenaza,
                                    descripcion=descripcion
                                ))

                if vulnerabilidades:
                    logger.debug(f"Agregando host {ip} con {len(vulnerabilidades)} vulnerabilidades")
                    hosts_detalle[ip] = HostAnalisis(
                        ip=ip,
                        nombre_host=nombre_host,
                        vulnerabilidades=vulnerabilidades
                    )
                else:
                    logger.warning(f"No se encontraron vulnerabilidades para el host {ip}")

            logger.info(f"Análisis completado. Hosts procesados: {host_count}, "
                       f"Hosts con vulnerabilidades: {len(hosts_detalle)}")

            if not hosts_detalle:
                logger.warning("No se encontraron hosts con vulnerabilidades")
                return None

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
        logger.error(f"Error al analizar el archivo: {str(e)}", exc_info=True)
        raise Exception(f"Error al analizar el archivo: {str(e)}")
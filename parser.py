import re
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime

@dataclass
class Vulnerabilidad:
    tipo: str
    descripcion: str
    nivel_riesgo: str
    fecha_deteccion: str

def analizar_vulnerabilidades(filepath: str) -> Dict:
    """
    Analiza un archivo de texto en busca de vulnerabilidades.
    Retorna un diccionario con los resultados del análisis.
    """
    vulnerabilidades = []
    patrones = {
        'sql_injection': r'(?i)(sql\s+injection|select\s+.*\s+from|union\s+select)',
        'xss': r'(?i)(<script>|javascript:|onerror=|onload=)',
        'path_traversal': r'(?i)(\.\.\/|\.\.\\|\.\.$)',
        'command_injection': r'(?i)(;\s*[\w\d]+\s+|&&|\|\|)',
        'weak_password': r'(?i)(password123|admin123|12345)'
    }
    
    niveles_riesgo = {
        'sql_injection': 'Alto',
        'xss': 'Alto',
        'path_traversal': 'Medio',
        'command_injection': 'Alto',
        'weak_password': 'Medio'
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            contenido = file.read()
            
            for tipo, patron in patrones.items():
                matches = re.finditer(patron, contenido)
                for match in matches:
                    vulnerabilidades.append(Vulnerabilidad(
                        tipo=tipo.replace('_', ' ').title(),
                        descripcion=f"Encontrado en línea cercana a: '{match.group()}'",
                        nivel_riesgo=niveles_riesgo[tipo],
                        fecha_deteccion=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ))
    
        # Generar estadísticas
        stats = {
            'total': len(vulnerabilidades),
            'por_tipo': {},
            'por_riesgo': {'Alto': 0, 'Medio': 0, 'Bajo': 0}
        }
        
        for vuln in vulnerabilidades:
            if vuln.tipo not in stats['por_tipo']:
                stats['por_tipo'][vuln.tipo] = 0
            stats['por_tipo'][vuln.tipo] += 1
            stats['por_riesgo'][vuln.nivel_riesgo] += 1
            
        return {
            'vulnerabilidades': vulnerabilidades,
            'estadisticas': stats
        }
        
    except Exception as e:
        raise Exception(f"Error al analizar el archivo: {str(e)}")

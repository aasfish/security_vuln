import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def exportar_a_csv(resultados, tipo_reporte):
    """
    Exporta los resultados a un archivo CSV.
    """
    try:
        if tipo_reporte == 'hosts':
            # Preparar datos para el formato de hosts
            datos = []
            for resultado in resultados:
                for ip, host in resultado['hosts_detalle'].items():
                    vulnerabilidades = {
                        'Critical': 0, 'High': 0, 
                        'Medium': 0, 'Low': 0
                    }
                    
                    for vuln in host['vulnerabilidades']:
                        vulnerabilidades[vuln['nivel_amenaza']] += 1
                    
                    datos.append({
                        'Sede': resultado['sede'],
                        'Fecha': resultado['fecha_escaneo'],
                        'IP': ip,
                        'Hostname': host['nombre_host'],
                        'Críticas': vulnerabilidades['Critical'],
                        'Altas': vulnerabilidades['High'],
                        'Medias': vulnerabilidades['Medium'],
                        'Bajas': vulnerabilidades['Low'],
                        'Total': sum(vulnerabilidades.values())
                    })
            
            df = pd.DataFrame(datos)
            
        elif tipo_reporte == 'vulnerabilidades':
            # Preparar datos para el formato de vulnerabilidades
            datos = []
            for vuln in resultados:
                datos.append({
                    'IP': vuln.host.ip,
                    'Hostname': vuln.host.nombre_host,
                    'Nivel': vuln.nivel_amenaza,
                    'CVSS': vuln.cvss,
                    'Puerto': vuln.puerto,
                    'Estado': vuln.estado,
                    'NVT': vuln.nvt,
                    'Resumen': vuln.resumen
                })
            
            df = pd.DataFrame(datos)
        
        output = BytesIO()
        df.to_csv(output, index=False, encoding='utf-8')
        output.seek(0)
        return output

    except Exception as e:
        logger.error(f"Error al exportar a CSV: {str(e)}", exc_info=True)
        raise

def exportar_a_pdf(resultados, tipo_reporte):
    """
    Exporta los resultados a un archivo PDF.
    """
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Título
        title = f"Reporte de {tipo_reporte.title()} - {datetime.now().strftime('%Y-%m-%d')}"
        elements.append(Paragraph(title, styles['Title']))
        elements.append(Paragraph("<br/><br/>", styles['Normal']))

        if tipo_reporte == 'hosts':
            # Preparar datos para la tabla de hosts
            data = [['Sede', 'IP', 'Hostname', 'Críticas', 'Altas', 'Medias', 'Bajas', 'Total']]
            
            for resultado in resultados:
                for ip, host in resultado['hosts_detalle'].items():
                    vulnerabilidades = {
                        'Critical': 0, 'High': 0, 
                        'Medium': 0, 'Low': 0
                    }
                    
                    for vuln in host['vulnerabilidades']:
                        vulnerabilidades[vuln['nivel_amenaza']] += 1
                    
                    data.append([
                        resultado['sede'],
                        ip,
                        host['nombre_host'],
                        vulnerabilidades['Critical'],
                        vulnerabilidades['High'],
                        vulnerabilidades['Medium'],
                        vulnerabilidades['Low'],
                        sum(vulnerabilidades.values())
                    ])

        elif tipo_reporte == 'vulnerabilidades':
            # Preparar datos para la tabla de vulnerabilidades
            data = [['IP', 'Hostname', 'Nivel', 'CVSS', 'Puerto', 'Estado', 'NVT']]
            
            for vuln in resultados:
                data.append([
                    vuln.host.ip,
                    vuln.host.nombre_host,
                    vuln.nivel_amenaza,
                    vuln.cvss,
                    vuln.puerto,
                    vuln.estado,
                    vuln.nvt
                ])

        # Crear tabla
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        return buffer

    except Exception as e:
        logger.error(f"Error al exportar a PDF: {str(e)}", exc_info=True)
        raise

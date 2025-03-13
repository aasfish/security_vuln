function crearGraficos(vulnerabilidadesData, riesgosData) {
    // Gráfico de vulnerabilidades por tipo
    const vulnCtx = document.getElementById('vulnerabilidadesChart').getContext('2d');
    new Chart(vulnCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(vulnerabilidadesData),
            datasets: [{
                label: 'Vulnerabilidades por Tipo',
                data: Object.values(vulnerabilidadesData),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(153, 102, 255, 0.5)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    // Gráfico de distribución por nivel de riesgo
    const riesgosCtx = document.getElementById('riesgosChart').getContext('2d');
    new Chart(riesgosCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(riesgosData),
            datasets: [{
                data: Object.values(riesgosData),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(255, 206, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

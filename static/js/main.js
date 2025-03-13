document.addEventListener('DOMContentLoaded', function() {
    // Validación del tipo de archivo
    const fileInput = document.getElementById('archivo');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file && !file.name.toLowerCase().endsWith('.txt')) {
                alert('Por favor, seleccione un archivo de texto (.txt)');
                e.target.value = '';
            }
        });
    }

    // Inicializar tooltips de Bootstrap
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

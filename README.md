# SECTRACKER-PRO - Sistema de Gestión de Vulnerabilidades

## Instalación Local con Docker

### Requisitos Previos
- Sistema operativo Linux (Ubuntu/Debian recomendado)
- Acceso root o sudo
- Conexión a Internet

### Pasos de Instalación

1. Desinstalar versiones anteriores de Docker:
```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```

2. Actualizar el sistema e instalar dependencias:
```bash
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg
```

3. Añadir el repositorio oficial de Docker:
```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

4. Instalar Docker:
```bash
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

5. Configurar usuario:
```bash
sudo usermod -aG docker $USER
```

6. Clonar el repositorio:
```bash
git clone https://github.com/aasfish/AS.git
cd AS
```

7. Configurar el ambiente:
```bash
cp .env.example .env
```

8. Iniciar la aplicación:
```bash
docker-compose up -d --build
```

### Verificación

Para verificar que todo está funcionando correctamente:

```bash
# Ver el estado de los contenedores
docker-compose ps

# Ver los logs
docker-compose logs
```

La aplicación estará disponible en: http://localhost:5000

## Mantenimiento

### Detener la aplicación
```bash
docker-compose down
```

### Reiniciar la aplicación
```bash
docker-compose restart
```

### Actualizar la aplicación
```bash
git pull
docker-compose down
docker-compose up -d --build
```

### Limpiar completamente (eliminar todos los datos)
```bash
docker-compose down -v
```

## Solución de Problemas

### Error de permisos de Docker
Si ves errores de permisos al ejecutar comandos docker:
1. Asegúrate de haber ejecutado: `sudo usermod -aG docker $USER`
2. Cierra sesión y vuelve a iniciar sesión
3. Verifica con: `docker ps`

### Error de conexión a la base de datos
Si el contenedor web no puede conectarse a la base de datos:
1. Verifica que ambos contenedores estén corriendo: `docker-compose ps`
2. Revisa los logs: `docker-compose logs`
3. Si es necesario, reinicia los contenedores: `docker-compose restart`

## Soporte

Para reportar problemas o sugerir mejoras, por favor crear un issue en el repositorio:
https://github.com/aasfish/AS/issues
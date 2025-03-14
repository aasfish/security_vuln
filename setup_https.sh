#!/bin/bash

# Crear directorio para certificados SSL
mkdir -p certs
cd certs

# Generar certificado SSL autofirmado
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=Security/OU=Development/CN=sectracker.local"

# Establecer permisos correctos
chmod 644 server.crt
chmod 600 server.key
cd ..

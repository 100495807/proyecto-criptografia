# proyecto-criptografia

Proyecto academico de Criptografia aplicado a una pequena plataforma de usuarios, canciones y comentarios. La aplicacion esta construida en Python con interfaz Tkinter, base de datos SQLite y varias primitivas criptograficas para autenticacion, cifrado, certificados y firmas.

## Objetivo

Implementar una aplicacion que combine gestion de usuarios y contenido con mecanismos de seguridad practicos:

- registro e inicio de sesion,
- hashing seguro de contrasenas,
- cifrado y descifrado de datos,
- certificados digitales,
- firma y verificacion de comentarios,
- almacenamiento en SQLite.

## Tecnologias

- Python
- Tkinter
- SQLite
- cryptography
- AES-GCM
- RSA
- PBKDF2-HMAC-SHA256
- Certificados X.509

## Componentes

| Archivo | Descripcion |
| --- | --- |
| `main.py` | Interfaz principal de la aplicacion. |
| `databaseManager.py` | Creacion y acceso a tablas SQLite. |
| `securityManager.py` | Hashing, cifrado, RSA, firmas y certificados. |
| `certificateManager.py` | Gestion de CA raiz, CA subordinadas y certificados de usuario. |
| `usersManager.py` | Registro, login y gestion de usuarios. |
| `songsManager.py` | Gestion de canciones. |
| `commentsManager.py` | Comentarios firmados y verificacion. |
| `validateManager.py` | Validaciones de datos de entrada. |
| `certificados/` | Certificados generados/usados por la aplicacion. |

## Como Ejecutarlo

Instalar dependencias:

```bash
pip install cryptography
```

Ejecutar:

```bash
python main.py
```

## Aprendizajes

- Derivar claves desde contrasenas con PBKDF2 y salt.
- Cifrar datos con AES-GCM y verificar etiquetas de autenticidad.
- Generar pares de claves RSA y firmar contenido con RSA-PSS.
- Crear y validar certificados X.509.
- Integrar seguridad criptografica en una aplicacion con interfaz grafica y base de datos.

## Nota De Seguridad

Este repositorio es academico. Antes de reutilizarlo en un entorno real conviene revisar secretos, credenciales, ficheros generados y configuracion de correo para que no haya datos sensibles versionados.

## Estado

Proyecto academico finalizado. Se conserva como practica aplicada de criptografia, autenticacion y certificados digitales.
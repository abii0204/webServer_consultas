import psycopg2  # Importa la librería psycopg2 para interactuar con PostgreSQL
import paramiko  # Importa la librería paramiko para interactuar con SSH
from sshtunnel import SSHTunnelForwarder  # Importa la clase SSHTunnelForwarder para reenvío de puertos SSH

# Datos de conexión SSH
# ssh_host = 'mvs.sytes.net'  # IP del servidor SSH
# ssh_port = 11150  # Puerto SSH
# ssh_username = 'sshuser'  # Nombre de usuario SSH
# ssh_private_key_path = "C:\\Users\\Abii\\Documents\\accesoRemoto\\accesoServidor\\id_rsa"  # Ruta de la clave privada RSA

# Datos de conexión a la base de datos PostgreSQL
db_host = '127.0.0.1'  # IP del servidor de la base de datos PostgreSQL
db_port = 5432  # Puerto de PostgreSQL
db_username = 'postgres'  # Nombre de usuario de la base de datos PostgreSQL
db_password = '1234'  # Contraseña de la base de datos PostgreSQL
db_name = 'consultasmedicas'  # Nombre de la base de datos PostgreSQL

# Función para establecer la conexión SSH y la conexión a la base de datos PostgreSQL
def get_db_connection():
    # Configurar la conexión SSH
    # ssh_client = paramiko.SSHClient()  # Crea un objeto de cliente SSH
    # ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Configura la política de manejo de claves faltantes
    # ssh_private_key = paramiko.RSAKey.from_private_key_file(ssh_private_key_path)  # Carga la clave privada RSA
    # ssh_client.connect(ssh_host, port=ssh_port, username=ssh_username, pkey=ssh_private_key)  # Realiza la conexión SSH

    # Configurar el reenvío de puertos SSH
    # tunnel = SSHTunnelForwarder(  # Crea un objeto de reenvío de puertos SSH
    #     ssh_address=(ssh_host, ssh_port),  # Dirección del servidor SSH
    #     ssh_username=ssh_username,  # Nombre de usuario SSH
    #     ssh_pkey=ssh_private_key,  # Clave privada RSA
    #     remote_bind_address=(db_host, db_port)  # Dirección y puerto remoto a los que reenviar el tráfico
    # )
    # tunnel.start()  # Inicia el reenvío de puertos SSH

    # Conectar a la base de datos PostgreSQL a través del túnel SSH
    db_connection = psycopg2.connect(  # Establece la conexión a la base de datos PostgreSQL
        user=db_username,  # Nombre de usuario de la base de datos PostgreSQL
        password=db_password,  # Contraseña de la base de datos PostgreSQL
        host=db_host,  # Dirección IP del servidor de la base de datos PostgreSQL
        port=5432, #tunnel.local_bind_port,  # Puerto local al que se ha reenviado el tráfico
        database=db_name,  # Nombre de la base de datos PostgreSQL
        client_encoding="utf8"  # Codificación de caracteres
    )

    return db_connection, None  # Retorna la conexión a la base de datos PostgreSQL, y el tunel SSH
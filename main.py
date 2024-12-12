import ssl

from dotenv import load_dotenv
import os
import jwt
from flask import Flask, render_template, request, make_response, redirect, jsonify

from ddbb import get_db_connection

app = Flask(__name__)

conexion = None
tunnel = None

conexion, tunel = get_db_connection()
@app.route('/read_qr')
def read_qr():
    return render_template('read_qr.html')
@app.route('/qr_ok')
def qr_ok():
    return render_template('qr_ok.html')

@app.route('/qr_fail')
def qr_fail():
    return render_template('qr_fail.html')


@app.route('/qr-data', methods=['POST'])
def qr_data():
    if request.is_json:
        qr_content = request.json.get('qr_data')
        print("Contenido del QR:", qr_content)

        # Responder con JSON indicando éxito y redirigir en el cliente
        return jsonify({"message": "QR recibido", "content": "qr_fail"})

    else:
        return jsonify({"error": "No se recibió JSON válido"}), 400

# Función para generar token
def generate_token(userlogin):
    # Codifica el token JWT con el nombre de usuario y la clave secreta
    token = jwt.encode({'userlogin': userlogin}, os.getenv('SECRET_KEY'), algorithm='HS512')
    return token

# Función para verificar token
def verify_token(token, userlogin):
    try:
        # Verifica la firma del token JWT utilizando la clave secreta
        decoded_token = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS512'])

        # Verificar si el nombre de usuario del token coincide con el usuario proporcionado
        if decoded_token['userlogin'] == userlogin:
            return True
    except jwt.ExpiredSignatureError:
        # Manejar el caso en que el token ha expirado
        return None
    except jwt.InvalidTokenError:
        # Manejar el caso en que el token es inválido
        return None


@app.route('/')
def home():
 return render_template('home.html')

@app.route('/form_login')  # Define la ruta para manejar solicitudes GET en '/form_login'
def login():
    # Renderiza la plantilla HTML llamada 'login_template.html' cuando se accede a la ruta '/form_login'
    return render_template('login_template.html')  # Devuelve la plantilla de login para que se muestre en el navegador

@app.route('/registro')  # Define la ruta para manejar solicitudes GET en '/form_login'
def resgistro():
    # Renderiza la plantilla HTML llamada 'login_template.html' cuando se accede a la ruta '/form_login'
    return render_template('registro_template.html')  # Devuelve la plantilla de login para que se muestre en el navegador


@app.route('/sign_in', methods=['POST'])
def sign_in():
    login = request.form['login']
    passwd = request.form['passwd']

    try:
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        cursor.callproc('login_usuario', (login, passwd))

        # Obtener los resultados (cuenta activa, login exitoso)
        result = cursor.fetchone()

        if result is None:
            # Si no se encuentran resultados (error interno)
            return render_template('login_incorrecto_template.html')

        cuenta_activa, login_exitoso = result[0], result[1]

        if not cuenta_activa:
            # Si la cuenta está desactivada, redirigir a la página de activar cuenta
            return redirect(f'/activar_cuenta?email={login}')

        if login_exitoso:
            # Login exitoso
            token = generate_token(login)
            response = make_response(redirect('/login_ok'))
            response.set_cookie('token', token)
            response.set_cookie('userlogin', login)
            return response
        else:
            # Credenciales incorrectas
            return render_template('login_incorrecto_template.html')

        # Confirmar los cambios realizados por el procedimiento almacenado
        conexion.commit()  # Aquí aseguramos que los cambios se persistan

    except Exception as e:
        print(f"Error al procesar el login: {e}")
        return 'Error al procesar el login.'

    finally:
        cursor.close()

@app.route('/registrarse_in', methods=['POST'])
def registrarse_in():
    # Obtener los datos del formulario
    nombre = request.form['nombre']
    apellidos = request.form['apellidos']
    correo = request.form['correo']
    contrasena = request.form['contrasena']
    telefono = request.form['telefono']
    direccion = request.form['direccion']

    try:
        # Obtener un cursor de la conexión
        cursor = conexion.cursor()

        # Llamar al procedimiento almacenado 'login_usuario'
        cursor.callproc('registrar_usuario', (nombre, apellidos, correo, contrasena, telefono, direccion))
        # Obtener el valor de retorno del procedimiento (booleano)
        result = cursor.fetchone()  # Debería devolver (True,) o (False,)
        conexion.commit()
        if result and result[0]:
            print("Registro exitoso.")

            return render_template('/login_template.html')
        else:
            print("Credenciales incorrectas.")

    except Exception as e:
        print(f"Error al llamar al procedimiento almacenado: {e}")
        return 'Error al verificar las credenciales.'

    finally:
        cursor.close()


# Ejemplo de una ruta protegida
@app.route('/login_ok')
def login_ok():
    # Obtener el token y el nombre de usuario desde las cookies de la solicitud
    token = request.cookies.get('token')         # Obtener el token JWT de la cookie
    userlogin = request.cookies.get('userlogin') # Obtener el nombre de usuario de la cookie

    # Verificar si el token o el nombre de usuario están ausentes
    if not token or not userlogin:
        # Si faltan el token o el nombre de usuario, renderizar una plantilla de error de token
        return render_template('token_fail.html')

    # Verificar la validez del token
    decoded_token = verify_token(token, userlogin)

    # Verificar si el token es válido
    if decoded_token:
        # Si el token es válido, renderizar la plantilla para la ruta protegida
        return render_template('login_ok_template.html')
    else:
        # Si el token no es válido, renderizar una plantilla de error de token
        return render_template('token_fail.html')

@app.route('/activar_cuenta')
def activar_cuenta():
    email = request.args.get('email')  # Recuperar el email desde los parámetros de la URL
    return render_template('activar_cuenta_template.html', email=email)



@app.route('/activar_cuenta_post', methods=['POST'])
def activar_cuenta_post():
    login = request.form.get('login', '').strip()  # Puede ser correo o nombre
    codigo = request.form.get('codigo', '').strip()

    try:
        if not login or not codigo:
            return render_template('cuenta_no_activada.html', error="Usuario o código no proporcionados.")

        try:
            codigo = int(codigo)
        except ValueError:
            return render_template('cuenta_no_activada.html', error="El código debe ser un número válido.")

        cursor = conexion.cursor()

        # Verificar los datos que se envían
        print(f"Enviando a la base de datos -> Login: {login}, Código: {codigo}")

        # Llamar al procedimiento almacenado
        cursor.callproc('activar_cuenta', (login, codigo))
        result = cursor.fetchone()
        conexion.commit()  # Confirmar cambios

        print(f"Resultado de la función almacenada: {result}")

        if result and result[0]:
            # Código correcto
            return render_template('cuenta_activada.html', login=login)
        else:
            # Código incorrecto
            return render_template('cuenta_no_activada.html', login=login, error="El código de activación es incorrecto.")

    except Exception as e:
        print(f"Error al activar la cuenta: {e}")
        return render_template('cuenta_no_activada.html', error=f"Error al procesar la activación: {e}")

    finally:
        if 'cursor' in locals():
            cursor.close()


if __name__ == '__main__':
    conexion, tunel = get_db_connection()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/root/home/certs/cerciapps_sytes_net.pem', '/root/home/certs/erciapps.key')
    app.run(ssl_context=context, host='0.0.0.0', port=5001, debug=True)


    #app.run(host='0.0.0.0', debug=True)
  #  app.run(host='0.0.0.0', port=5000, debug=True)
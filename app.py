import os 
import re
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from decimal import Decimal # IMPORTACIÓN AÑADIDA PARA MANEJAR DINERO

#IMPORTAMOS NUESTRO VALIDADOR DE HASH SEGURO 
from seguridad import generar_hash_seguro, verificar_contraseña

#CARGAMOS LAS VARIABLES DEL ENTORNO DESDE .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_seguro")

#CONFIGURACIÓN Y CONEXIÓN CON SUPABASE (POSTGRESQL)
DATABASE_URL = os.getenv("SUPABASE_DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("⚠️ DATABASE_URL no está configurada en el archivo .env")

#CREAMOS EL MOTOR DE BASE DE DATOS y la FABRICA DE SESIONES
engine = create_engine(DATABASE_URL, pool_size=5, max_overflow=10)
Session = sessionmaker(bind=engine)

#¡REGLA DE CIBERSEGURIDAD! VALIDADORES DE ENTRADA:
def es_email_valido(email: str)-> bool:
    patron = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(patron, email))

#¡ENDPOINT 1: REGISTRO SEGURO (CON TRASACCIÓN ACID)!
@app.route('/api/auth/register', methods=['POST']) # CORREGIDO: BARRAS NORMALES
def registrar_usuario():
    datos = request.get_json() or {}

    email = datos.get('email', "").strip().lower()
    password_plana = datos.get('password', "")
    role = datos.get("role", "client").strip().lower()
    company_name = datos.get("company_name", "").strip()


    #VALIDACIONES DE ENTRADA (INPUT SANITIZATION)
    if not email or not password_plana:
        return jsonify({"error": "Email y contraseña son obligatorios"}), 400
    
    if not es_email_valido(email):
        return jsonify({"error": "Formato de correo electrónico no válido"}), 400

    if len(password_plana) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres"}), 400
    
    if role not in ["client", "enterprise"]:
        return jsonify({"error": "Rol no permitido en la plataforma."}), 400
    

    #INICIAMOS LA SESIÓN DE LA BASE DE DATOS
    session = Session()

    try:
        #VERIFICAMOS SI EL CORREO YA EXISTE (EVITAR DUPLICADOS)
        query_existencia = text("SELECT id FROM users WHERE email = :email")
        existe = session.execute(query_existencia, {"email": email}).fetchone() # CORREGIDO: FALTABA EJECUTAR
        if existe:
            return jsonify({"error": "El correo electrónico ya se encuentra registrado."}), 409
        

        #2. HASH EN LA CONTRASEÑA CON ARGON2ID DE FORMA SEGURA
        password_hash = generar_hash_seguro(password_plana)


#3. TRANSACCIÓN COMPUESTA (SQALCHEMY FIGURA CLAVE)
        #REGISTRAMOS USUARIOS EN LA TABLA 'users'
        query_usuario = text("""
            INSERT INTO users (email, password_hash, role, company_name)
            VALUES (:email, :password_hash, :role, :company_name)
            RETURNING id;
        """)

        # USAMOS .scalar() QUE EXTRAE EL VALOR DIRECTAMENTE DE FORMA SEGURA
        nuevo_user_id = session.execute(query_usuario, {
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "company_name": company_name if role == "enterprise" else None
        }).scalar()

        if not nuevo_user_id:
            raise Exception("Error crítico: La base de datos no devolvió un ID válido.")


        #4. SI EL ROL ES 'client', le abrimos de forma transaccional una cuenta bancaria
        if role == "client":
            #GENERAMOS UN NÚMERO DE CUENTA FICTICIO ALEATORIO DE 10 DÍGITOS
            import random
            numero_cuenta = f"AR{random.randint(100000000, 999999999)}"

            query_cuenta = text("""
                INSERT INTO bank_accounts (user_id, account_number, balance)
                VALUES (:user_id, :account_number, 1000.00);
            """)

            session.execute(query_cuenta, {
                "user_id": nuevo_user_id,
                "account_number": numero_cuenta
            })
        
        #SI LLEGAMOS ACÁ SIN ERRORES, COMMIT DE LA TRANSACCIÓN TOTAL (ACID)
        session.commit()

        return jsonify({
            "mensaje": "Usuario registrado exitosamente", 
            "user_id": str(nuevo_user_id),
            "role": role,
            "cuenta_bancaria_creada": True if role == "client" else False
        }), 201
    
    except Exception as e:
        #SI CUALQUIER OPERACIÓN FALLÓ, DESHACEMOS TODOS LOS CAMBIOS DE LA BASE DE DATOS
        session.rollback()
        #EN PRODUCCIÓN, REGISTRA EL ERROR EN SU SISTEMA INTERNO Y DEVUELVE UN MENSAJE INOFENSIVO 
        print(f"Error interno {e}")
        return jsonify({"error": "Ocurrió un error inesperado al procesar la solicitud."}), 500
    
    finally:
        session.close()

#ENDPOINT 2: LOGIN SEGURO CON VERIFICACIÓN DE HASH
@app.route('/api/auth/login', methods=['POST'])
def login():
    datos = request.get_json() or {}
    email = datos.get('email', "").strip().lower()
    password_plana = datos.get('password', "")

    if not email or not password_plana:
        return jsonify({"error": "Se requiere credenciales completas"}), 400
    
    session = Session()
    try:
        query = text("SELECT id, password_hash, role, company_name FROM users WHERE email = :email")
        usuario = session.execute(query, {"email": email}).fetchone()

        if usuario:
            user_id, hash_guardado, role, company_name = usuario

            #VERIFICAMOS CON LA LIBRERIA ARGON2
            if verificar_contraseña(hash_guardado, password_plana):
                return jsonify({
                    "mensaje": "Autenticación exitosa",
                    "user_id": str(user_id),
                    "role": role,
                    "company_name": company_name
                }), 200
            
        #POR CIBERSEGURIDAD, NUNCA LE DIGAS AL HACKER SI EL CORREO O LA CONTRASEÑA ESTABAN MAL.
        #MANTÉN LA RESPUESTA AMBIGUA: "CREDENCIALES INVALIDAS"
        return jsonify({"error": "Credenciales inválidas o inexistentes."}), 401
    
    except Exception as e:
        print(f"Error Login: {e}")
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        session.close()


#ENDPOINT 3: TRANSFERENCIA BANCARIA ENTRE CUENTAS (ACID MÁS FOR UPDATE)
@app.route('/api/banking/transfer', methods=['POST'])
def transferir_fondos():
    datos = request.get_json() or {}

    sender_id = datos.get('sender_user_id')
    receiver_account_number = datos.get('receiver_account_number', "").strip()
    amount_str = datos.get('amount')
    descripcion = datos.get('description', 'Transferencia enviada')

    #1. VALIDACIÓN DE ENTRADA
    if not sender_id or not receiver_account_number or not amount_str:
        return jsonify({"error": "Faltan datos obligatorios."}), 400
    
    try:
        amount = Decimal(str(amount_str))
        if amount <= Decimal('0.00'):
            return jsonify({"error": "El monto debe ser mayor a cero."}), 400
    except Exception:
        return jsonify({"error": "Formato de monto inválido."}), 400
    
    session = Session()

    try:
        #2. OBTENEMOS Y BLOQUEAMOS LA CUENTA DEL EMISOR
        query_sender = text("""
            SELECT id, balance, account_number
            FROM bank_accounts
            WHERE user_id = :user_id
            FOR UPDATE; -- 🛡️ BLOQUEO EXCLUSIVO HASTA EL COMMIT
        """)
        sender = session.execute(query_sender, {"user_id": sender_id}).fetchone()

        if not sender:
            return jsonify({"error": "Cuenta del emisor no encontrada."}), 404
        
        sender_account_id, sender_balance, sender_account_number = sender
        
        #EVITA AUTO-TRANSFERENCIAS Y SALDOS NEGATIVOS
        if sender_account_number == receiver_account_number:
            return jsonify({"error": "No puedes transferir fondos a tu propia cuenta."}), 400
            
        if sender_balance < amount:
            return jsonify({"error": "Fondos insuficientes."}), 400

        #3. OBTENEMOS Y BLOQUEAMOS LA CUENTA DEL RECEPTOR
        query_receiver = text("""
            SELECT id 
            FROM bank_accounts 
            WHERE account_number = :account_number 
            FOR UPDATE;
        """)
        receiver = session.execute(query_receiver, {"account_number": receiver_account_number}).fetchone()
        
        if not receiver:
            return jsonify({"error": "Cuenta de destino no encontrada."}), 404
            
        receiver_account_id = receiver[0]

        #4. EJECUTAMOS LOS MOVIMIENTOS MATEMÁTICOS DE FORMA SEGURA
        query_update_sender = text("UPDATE bank_accounts SET balance = balance - :amount WHERE id = :id")
        session.execute(query_update_sender, {"amount": amount, "id": sender_account_id})

        query_update_receiver = text("UPDATE bank_accounts SET balance = balance + :amount WHERE id = :id")
        session.execute(query_update_receiver, {"amount": amount, "id": receiver_account_id})

        #5. REGISTRAMOS LA TRANSACCIÓN EN LA TABLA INMUTABLE DE AUDITORÍA
        query_audit = text("""
            INSERT INTO bank_transactions (sender_account_id, receiver_account_id, amount, transaction_type, description)
            VALUES (:sender, :receiver, :amount, 'transfer', :desc)
        """)
        session.execute(query_audit, {
            "sender": sender_account_id,
            "receiver": receiver_account_id,
            "amount": amount,
            "desc": descripcion
        })

        #SI TODO SALIÓ BIEN, GUARDAMOS LOS CAMBIOS
        session.commit()
        
        
        return jsonify({
            "mensaje": "Transferencia exitosa", 
            "monto": str(amount),
            "destino": receiver_account_number
        }), 200

    except Exception as e:
        session.rollback()
        print(f"Error interno {e}")
        return jsonify({"error": "Ocurrió un error inesperado al procesar la solicitud."}), 500
    finally:
        session.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
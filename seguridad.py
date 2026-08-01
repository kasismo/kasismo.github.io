from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

#Configuración con parámetros robustos recomendados (OWASP)
#Consume aprox 64MB de RAM y 3 pasadas por cálculo, algo inofensivo para tu servidor,
#pero letal para un ataque de fuerza bruta masivo en paralelo.
ph = PasswordHasher(
    time_cost=3, # Número de iteraciones (pasadas) de hashing
    memory_cost=65536, # 64 MB requeridos por cálculo 
    parallelism=4, # Hilos de procesamiento ocupados
)

def generar_hash_seguro(password_plana: str) -> str:
    """
    Toma la contraseña escrita por el usuario en el frontend, 
    le genera una 'sal' (salt) única aleatoria de forma automática y la hashéa.
    """
    if not password_plana or len(password_plana.strip())<8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    
    #Argon2id maneja el salado por debajo y vuelve un string legible por la BD
    return ph.hash(password_plana.strip())

def verificar_contraseña(hash_guardado: str, password_plana: str) -> bool:
    """
    Compara de forma segura (mitigando ataques de temporización/timing attacks)
    si la contraseña ingresada coincide con el hash almacenado en Supabase.
    """
    try:
        #ph.verify() analiza los párametros dentro del hash guardado y los valida
        return ph.verify(hash_guardado.strip(), password_plana.strip())
    except (VerifyMismatchError, VerificationError):
        return False
    

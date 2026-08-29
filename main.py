from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional, List
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt 
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import google.generativeai as genai
import json

# --- 1. CONFIGURACIÓN ---
load_dotenv()

# Configurar la API de Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Seguridad: Leemos la clave del entorno. Si no existe, usa la insegura por defecto (solo para local).
SECRET_KEY = os.getenv("SECRET_KEY", "secreto_por_defecto_inseguro")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30000 

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# 👇 LÓGICA HÍBRIDA DE BASE DE DATOS (LA MAGIA 🎩)
# 1. Primero intentamos buscar la URL completa (Esto es lo que usa Render/Neon)
DATABASE_URL = os.getenv("DATABASE_URL")

# 2. Si está vacía (significa que estás en tu PC), la construimos por partes como antes
if not DATABASE_URL:
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "admin")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "klist_db")
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# 🛠️ CORRECCIÓN DE COMPATIBILIDAD
# Neon devuelve "postgres://", pero SQLAlchemy prefiere "postgresql://"
# Este código lo arregla automáticamente al vuelo.
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Creamos la conexión con la URL final (sea la de tu PC o la de Neon)
engine = create_engine(DATABASE_URL)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. MODELOS DE DATOS (CORREGIDOS 🛠️) ---

class Usuario(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    nombre: str
    password_hash: str

class Serie(SQLModel, table=True):
    # 👇 Configuración para que acepte alias tanto al recibir como al enviar
    class Config:
        populate_by_name = True

    id: Optional[int] = Field(default=None, primary_key=True)
    usuario_id: Optional[int] = Field(default=None, foreign_key="usuario.id")
    tmdb_id: int
    titulo: str
    
    # 🛠️ TRADUCTOR ACTIVADO:
    # DB espera "imagenUrl", pero aceptamos "imagen_url" de Flutter
    imagenUrl: str = Field(alias="imagen_url") 
    
    estado: str
    calificacion: int
    comentario: str
    plataforma: str
    
    # 🛠️ TRADUCTOR ACTIVADO:
    anioLanzamiento: int = Field(alias="anio_lanzamiento")
    
    activa: bool = Field(default=True)
    episodios_vistos: int = Field(default=0)
    total_episodios: int = Field(default=0)
    tipo: str = Field(default="tv")

class ActorFavorito(SQLModel, table=True):
    class Config:
        populate_by_name = True

    id: Optional[int] = Field(default=None, primary_key=True)
    usuario_id: Optional[int] = Field(default=None, foreign_key="usuario.id")
    tmdb_id: int
    nombre: str
    
    # 🛠️ TRADUCTOR ACTIVADO:
    fotoUrl: str = Field(alias="foto_url")

# Modelos auxiliares (Pydantic)
class UsuarioRegistro(BaseModel):
    email: str
    nombre: str
    password: str

class UsuarioLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    usuario_nombre: str
    usuario_id: int
    
class UsuarioUpdate(BaseModel):
    nombre: str

# Nuevo modelo Pydantic para estructurar la respuesta de la IA
class Recomendacion(BaseModel):
    titulo: str
    razon: str

# --- 3. FUNCIONES DE SEGURIDAD ---

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    with Session(engine) as session:
        user = session.exec(select(Usuario).where(Usuario.email == email)).first()
        if user is None:
            raise credentials_exception
        return user

@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# --- 4. RUTAS ---

@app.post("/registro", status_code=201)
def registrar_usuario(usuario: UsuarioRegistro):
    with Session(engine) as session:
        if session.exec(select(Usuario).where(Usuario.email == usuario.email)).first():
            raise HTTPException(status_code=400, detail="Email ya registrado")
        
        nuevo_usuario = Usuario(email=usuario.email, nombre=usuario.nombre, password_hash=get_password_hash(usuario.password))
        session.add(nuevo_usuario)
        session.commit()
        return {"mensaje": "Usuario creado"}

@app.post("/login", response_model=Token)
def login(datos: UsuarioLogin):
    with Session(engine) as session:
        user = session.exec(select(Usuario).where(Usuario.email == datos.email)).first()
        if not user or not verify_password(datos.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        access_token = create_access_token(data={"sub": user.email})
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "usuario_nombre": user.nombre,
            "usuario_id": user.id
        }

# --- LOGIN GOOGLE ---
CLIENT_IDS_PERMITIDOS = [
    GOOGLE_CLIENT_ID, 
    "86335933030-kk244oldjrclj7mlsl02uuf1jnoi6en3.apps.googleusercontent.com"
]

@app.post("/login/google")
def login_google(data: dict):
    token_google = data.get("token")
    try:
        response = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={token_google}")
        if response.status_code != 200: raise ValueError("Google rechazó el token")
            
        google_data = response.json()
        audience_recibida = google_data['aud']
        
        if audience_recibida not in CLIENT_IDS_PERMITIDOS:
            print(f"❌ ID desconocido: {audience_recibida}")
            raise ValueError(f"Token no autorizado")

        email = google_data['email']
        nombre = google_data.get('email', email.split('@')[0])
        
        with Session(engine) as session:
            usuario = session.exec(select(Usuario).where(Usuario.email == email)).first()
            if not usuario:
                usuario = Usuario(email=email, nombre=nombre, password_hash="GOOGLE_LOGIN")
                session.add(usuario)
                session.commit()
                session.refresh(usuario)
            
            access_token = create_access_token(data={"sub": usuario.email})
            return {
                "access_token": access_token, 
                "token_type": "bearer",
                "usuario_id": usuario.id,
                "usuario_nombre": usuario.nombre
            }
    except Exception as e:
        print(f"Error Google: {e}")
        raise HTTPException(status_code=500, detail="Error interno")

# --- RUTAS PROTEGIDAS ---

@app.get("/series", response_model=List[Serie])
def obtener_series(current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        return session.exec(select(Serie).where(Serie.usuario_id == current_user.id).where(Serie.activa == True)).all()

@app.post("/series", response_model=Serie)
def crear_serie(serie: Serie, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        statement = select(Serie).where(Serie.usuario_id == current_user.id).where(Serie.tmdb_id == serie.tmdb_id)
        resultado = session.exec(statement).first()
        
        if resultado:
            if not resultado.activa:
                resultado.activa = True
                session.add(resultado)
                session.commit()
                session.refresh(resultado)
                return resultado
            else:
                raise HTTPException(status_code=400, detail="Ya tienes esta serie")

        serie.usuario_id = current_user.id
        session.add(serie)
        session.commit()
        session.refresh(serie)
        return serie

@app.put("/series/{serie_id}")
def actualizar_serie(serie_id: int, serie_actualizada: Serie, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        serie_db = session.exec(select(Serie).where(Serie.id == serie_id).where(Serie.usuario_id == current_user.id)).first()
        if not serie_db: raise HTTPException(status_code=404, detail="No encontrada")
        
        # Actualizamos campo por campo (El alias maneja la traducción automática)
        serie_db.estado = serie_actualizada.estado
        serie_db.calificacion = serie_actualizada.calificacion
        serie_db.comentario = serie_actualizada.comentario
        serie_db.episodios_vistos = serie_actualizada.episodios_vistos
        serie_db.total_episodios = serie_actualizada.total_episodios
        serie_db.plataforma = serie_actualizada.plataforma
        serie_db.titulo = serie_actualizada.titulo
        
        session.add(serie_db)
        session.commit()
        session.refresh(serie_db)
        return serie_db

@app.delete("/series/{serie_id}")
def borrar_serie(serie_id: int, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        serie = session.exec(select(Serie).where(Serie.id == serie_id).where(Serie.usuario_id == current_user.id)).first()
        if not serie: raise HTTPException(status_code=404, detail="No encontrada")
        serie.activa = False
        session.add(serie)
        session.commit()
        return {"mensaje": "Borrada"}

@app.put("/usuario/me", response_model=Usuario)
def actualizar_perfil(datos: UsuarioUpdate, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        user = session.get(Usuario, current_user.id)
        if not user: raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.nombre = datos.nombre
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

# --- ACTORES ---
@app.post("/actores", response_model=ActorFavorito)
def guardar_actor(actor: ActorFavorito, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        if session.exec(select(ActorFavorito).where(ActorFavorito.usuario_id == current_user.id).where(ActorFavorito.tmdb_id == actor.tmdb_id)).first():
             raise HTTPException(400, "Ya es favorito")
        
        actor.usuario_id = current_user.id
        session.add(actor)
        session.commit()
        session.refresh(actor)
        return actor

@app.get("/actores", response_model=List[ActorFavorito])
def obtener_actores(current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        return session.exec(select(ActorFavorito).where(ActorFavorito.usuario_id == current_user.id)).all()

@app.delete("/actores/tmdb/{tmdb_id}")
def borrar_actor_por_tmdb(tmdb_id: int, current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        a = session.exec(select(ActorFavorito).where(ActorFavorito.usuario_id == current_user.id).where(ActorFavorito.tmdb_id == tmdb_id)).first()
        if not a: raise HTTPException(404, "No encontrado")
        session.delete(a)
        session.commit()
        return {"mensaje": "Eliminado"}

@app.get("/recomendaciones", response_model=List[Recomendacion])
def obtener_recomendaciones_ia(current_user: Usuario = Depends(get_current_user)):
    with Session(engine) as session:
        # 1. Obtenemos las series del usuario que estén activas
        series_db = session.exec(select(Serie).where(Serie.usuario_id == current_user.id).where(Serie.activa == True)).all()
        
        if not series_db:
             raise HTTPException(status_code=400, detail="Necesitas agregar algunas series primero para que la IA te conozca.")

        # 2. Extraemos solo los nombres. 
        # Si el usuario tiene guardadas obras como "Shopping King Louie", "My First First Love" o "So Not Worth It", 
        # esta lista se llenará con esos títulos exactos para enviarlos de contexto.
        nombres_series = [serie.titulo for serie in series_db]
        series_texto = ", ".join(nombres_series)

        # 3. El "Prompt Engineering" (Las instrucciones para la IA)
        prompt = f"""
        Actúa como un experto recomendador de series y doramas. 
        Un usuario ha visto y le gustan las siguientes series: {series_texto}.
        
        Basado estrictamente en esos gustos, recomiéndale 3 series nuevas que NO estén en esa lista.
        Tu respuesta DEBE ser ÚNICAMENTE un arreglo JSON válido con esta estructura exacta:
        [
            {{"titulo": "Nombre de la Serie", "razon": "Breve explicación de por qué le gustará"}},
            ...
        ]
        No incluyas texto adicional, ni saludos, ni formato Markdown (```json). Solo el arreglo puro.
        """

        try:
            # 4. Llamamos a Gemini
            modelo = genai.GenerativeModel('gemini-2.5-flash')
            respuesta = modelo.generate_content(prompt)
            
            # 5. Limpiamos la respuesta (por si la IA mete formato Markdown por error) y la convertimos a JSON
            texto_json = respuesta.text.replace("```json", "").replace("```", "").strip()
            recomendaciones = json.loads(texto_json)
            
            return recomendaciones
            
        except Exception as e:
            print(f"Error con la IA: {e}")
            raise HTTPException(status_code=500, detail="La IA está descansando, intenta en un momento.")
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import mysql.connector
from mysql.connector import Error
from models import *

from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta

SALT = b'\xe0\xfd\xdb4\x07<\xb5\xcd\x97\xa1]\x94yo>\x07~\x13\xc0\xeb\x13^\x1f$ \xf1<Xx"\x19\x0f'
SECRET_KEY = "89a571ae0f0895c88b639ad25c2abdb74716cbc2e92ebde082635ba0f76dace2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# engine = create_engine('mssql+pyodbc://ben2:P1neappleRunn3rd@143.198.112.73:3306/test')


    
    # def out_val(self):
    #     return {'id': self.id, 'name': self.name}

def create_connection(host, user, password, database, port='3306'):
    connection = None
    try:
        connection = mysql.connector.connect(host=host, user=user, passwd=password, port=port, database=database)
        print('success')
    except Error as e:
        print(f"The error '{e}' occured")

    return connection
        

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(plain_password):
    return pwd_context.hash(plain_password)

# @app.get('/login')
def get_user(username):
    # username = 'babin101'
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'journal')
    query = 'SELECT * FROM journal.users WHERE username="' + username + '"'
    print(query)
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    data = [User(username=r[1], email=r[3], password=r[2]) for r in rows]

    # if username in db:
    if len(data) > 0:
        user_dict = data[0]
        return user_dict
    
    return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/')
async def root():
    return {'message': 'Hello World'}

@app.get('/test_get')
async def test_get():
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'journal')
    query = 'SELECT * FROM test.test_table'
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    data = [TestModel(r[0], r[1]) for r in rows]

    # print(result)
    return data

@app.get('/b/{bubble_id}')
async def get_posts(bubble_id):
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'journal')
    query = 'SELECT id, name FROM bubbles WHERE id = %s' % bubble_id
    query2 = 'SELECT id, body FROM posts WHERE bubble_id = %s' % bubble_id
    cursor = connection.cursor()
    cursor.execute(query)
    retreive_bubble = cursor.fetchall()

    bubble = Bubble(retreive_bubble[0][0], retreive_bubble[0][1])

    cursor.execute(query2)
    retreive_posts = cursor.fetchall()

    data = [bubble.add_post(Post(r[0], r[1])) for r in retreive_posts]

    return bubble

@app.get('/test')
async def test(token: str = Depends(oauth2_scheme)):
    return 'test'

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# @app.get('/login')
# async def login():
#     # result = 
#     pass_hash = hashlib.scrypt(b'test', salt=SALT, n=2**14, r=8, p=1)
#     print(pass_hash)
#     return pass_hash.hex()

# def get_token(token):
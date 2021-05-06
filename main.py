from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
from mysql.connector import Error
from models import *

from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta

from pypika import Query, Table, Field

import boto3

import uuid

SALT = b'\xe0\xfd\xdb4\x07<\xb5\xcd\x97\xa1]\x94yo>\x07~\x13\xc0\xeb\x13^\x1f$ \xf1<Xx"\x19\x0f'
SECRET_KEY = "89a571ae0f0895c88b639ad25c2abdb74716cbc2e92ebde082635ba0f76dace2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 100

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

origins = [
    "http://localhost:3000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(plain_password):
    return pwd_context.hash(plain_password)

# @app.get('/login')
def get_user(username):
    # username = 'babin101'
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
    # query = 'SELECT * FROM "grading.users" WHERE username="' + username + '"'
    user_table = Table('users')
    query = str(Query.from_(user_table).select('*').where(user_table.username == username))
    print(query)
    # return False
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    data = [User(id=r[0], username=r[1], email=r[3], password=r[2]) for r in rows]

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
    
    print(expire)
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

# app logic

# Verifies if a logged in user is the creator of a class
def verify_class_user(connection, current_user, indv_class_id):
    try:
        tbl = Table('classes')
        query = str(Query.from_(tbl).select('*').where(tbl.id == indv_class_id))
        print(query)
        cursor = connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        if int(rows[0][2]) == current_user.id:
            return True
        else:
            return False
    except Error as e:
        print(e)
        raise HTTPException(status_code=500)

# Verifies if a logged in student is in a particular class
def verify_class_student(connection, current_user, indv_class_id):
    try:
        tbl = Table('students')
        query = str(Query.from_(tbl).select('*').where(tbl.class_id == indv_class_id))
        print(query)
        cursor = connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        if len(rows) > 0 and int(rows[0][1]) == current_user.id:
            return True
        else:
            return False
    except Error as e:
        print(e)
        raise HTTPException(status_code=500)

#endpoints

# @app.post("/new/class")
# async def add_class_endpoint(new_class: IndvClass, current_user: User = Depends((get_current_user))):
    
#     return 'query'

@app.get("/class/{class_id}")
async def get_class_assignments(class_id: int, current_user: User = Depends(get_current_user)):
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
    tbl = Table('assignments')
    query = str(Query.from_(tbl).select('*').where(tbl.class_id == class_id))
    print(query)
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    assignments = [Assignment(id=r[0], name=r[1], class_id=r[2], num_uploads=r[3]) for r in rows]
    return assignments

@app.get("/assignments/{assignment_id}")
async def get_assignment_uploads(assignment_id: int, current_user: User = Depends(get_current_user)):
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
    tbl = Table('uploads')
    tbl_users = Table('users')
    query = str(Query.from_(tbl).select('*').where(tbl.assignment_id == assignment_id).join(tbl_users).on(tbl.user_id == tbl_users.id))
    print(query)
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    uploads = [IndvUpload(id=r[0], assignment_id=r[1], link=r[2], user_id=r[3], user_name=r[5]) for r in rows]
    # print(rows)
    return uploads

@app.get('/uploads/{upload_id}')
async def get_upload_information(upload_id: int, current_user: User = Depends(get_current_user)):
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
    tbl_uploads = Table('uploads')
    tbl_grades = Table('grades')
    query_upload = str(Query.from_(tbl_uploads).select('*').where(tbl_uploads.id == upload_id))
    query_grades = str(Query.from_(tbl_grades).select('*').where(tbl_grades.upload_id == upload_id))
    cursor = connection.cursor()
    cursor.execute(query_upload)
    response1 = cursor.fetchall()[0]
    upload_key = 'uploads/' + str(response1[2])

    s3_session = boto3.session.Session()
    client = s3_session.client('s3', region_name='nyc3', endpoint_url='https://nyc3.digitaloceanspaces.com', aws_access_key_id='NBBNIPXWULH7MATJ7XJI', aws_secret_access_key='vt2XSjao45I+f8U/uKvw1Hr5SVyKZFW5esSoKid6x/s')
    temp_link = client.generate_presigned_url(ClientMethod='get_object', Params={'Bucket': '426gradeapp', 'Key': upload_key}, ExpiresIn=60)

    upload_obj = IndvUpload(id=response1[0], assignment_id=response1[1], link=temp_link, user_id=response1[3])

    # going to verify that user is a part of this class
    tbl_assignments = Table('assignments')
    query_assignment = str(Query.from_(tbl_assignments).select('*').where(tbl_assignments.id == upload_obj.assignment_id))
    cursor.execute(query_assignment)
    response2 = cursor.fetchall()[0]
    assignment_class_id = response2[2]
    if verify_class_student(connection, current_user, assignment_class_id):
        cursor.execute(query_grades)
        grades_arr = [IndvGrade(id=r[0], upload_id=r[1], overall_grade=r[2], selected_rubric_items=r[3]) for r in cursor.fetchall()]
        return UploadResponse(upload_info=upload_obj, grades=grades_arr)
    else:
        raise HTTPException(401)

@app.post("/new/upload")
async def add_upload_for_assignment(new_upload: UploadFile = File(...), assignment_id: int = Form(...), current_user: User = Depends(get_current_user)):
    try:
        connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
        tbl = Table('assignments')
        query = str(Query.from_(tbl).select('*').where(tbl.id == assignment_id))
        print(query)
        cursor = connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        print(rows)
        
        if len(rows) > 0 and verify_class_student(connection, current_user, rows[0][2]):
            s3_session = boto3.session.Session()
            client = s3_session.client('s3', region_name='nyc3', endpoint_url='https://nyc3.digitaloceanspaces.com', aws_access_key_id='NBBNIPXWULH7MATJ7XJI', aws_secret_access_key='vt2XSjao45I+f8U/uKvw1Hr5SVyKZFW5esSoKid6x/s')
            og_file_name = new_upload.filename.split('.')
            file_name = str(uuid.uuid4()) + '.' + str(og_file_name[1])
            resp = client.put_object(Body=new_upload.file, Bucket='426gradeapp', Key='uploads/' + file_name)

            completed_upload = IndvUpload(assignment_id=assignment_id, link=file_name, user_id=current_user.id)

            print(completed_upload)

            uploads_tbl = Table('uploads')
            upload_query = str(Query.into(uploads_tbl).columns(uploads_tbl.assignment_id, uploads_tbl.link, uploads_tbl.user_id).insert(assignment_id, completed_upload.link, completed_upload.user_id))
            increase_count_query = str(Query.update(tbl).set(tbl.num_uploads, tbl.num_uploads + 1).where(tbl.id == assignment_id))
            print(increase_count_query)
            cursor.execute(upload_query)
            cursor.execute(increase_count_query)
            connection.commit()
            # print(new_upload)
            connection.close()
            return True
        else:
            connection.close()
            raise HTTPException(status_code=401)
    except Error as e:
        print(e)
        raise HTTPException(status_code=500)

@app.post("/new/assignment")
async def add_assignment_endpoint(new_assignment: Assignment, current_user: User = Depends((get_current_user))):
    try:
        connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
        if verify_class_user(connection, current_user, new_assignment.class_id):
            tbl = Table('assignments')
            query = str(Query.into(tbl).columns(tbl.name, tbl.class_id, tbl.num_uploads).insert(new_assignment.name, new_assignment.class_id, 0))
            print(query)
            cursor = connection.cursor()
            cursor.execute(query)
            connection.commit()
            connection.close()
            return new_assignment
        else:
            connection.close()
            raise HTTPException(status_code=401)
    except Error as e:
        return e
    

@app.post("/new/class")
async def add_class_endpoint(new_class: IndvClass, current_user: User = Depends((get_current_user))):
    new_class.user = current_user.id
    connection = create_connection('143.198.112.73', 'ben3', 'P1neappleRunn3rd', 'grading')
    classes_table = Table('classes')
    query = str(Query.into(classes_table).columns(classes_table.name, classes_table.user).insert(new_class.name, new_class.user))
    print(query)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    connection.close()
    return True

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
    print(access_token_expires)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "exp": access_token_expires}

@app.get('/')
async def root():
    return {'message': 'Hello World'}

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
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta

class TestModel:
    def __init__(self, id, name):
        self.id = id
        self.name = name

class Bubble:
    def __init__(self, id, name):
        self.id = id
        self.name = name
        self.posts = []
    
    def add_post(self, post):
        self.posts.append(post)

class Post:
    def __init__(self, id, body, bubble_id=0):
        self.id = id
        self.body = body

class User(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    exp: timedelta


class TokenData(BaseModel):
    username: Optional[str] = None

class IndvClass(BaseModel):
    id: Optional[int]
    name: str
    user: Optional[int]

class Assignment(BaseModel):
    id: Optional[int]
    name: str
    class_id: int
    num_uploads: Optional[int]
    rubric: Optional[str]

class IndvUpload(BaseModel):
    id: Optional[int]
    assignment_id: int
    link: str
    user_id: int
    user_name: Optional[str]

class IndvGrade(BaseModel):
    id: Optional[int]
    upload_id: int
    overall_grade: int
    selected_rubric_items: Optional[str]

class UploadResponse(BaseModel):
    upload_info: IndvUpload
    grades: List[IndvGrade]

# class FormUpload(BaseModel):
#     assignment_id: int
#     user_id: Optional[int]
#     file: 

# class UserInDB(User):
#     hashed_password: str
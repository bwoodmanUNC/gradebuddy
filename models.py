from pydantic import BaseModel
from typing import Optional

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
    username: str
    email: Optional[str] = None
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

# class UserInDB(User):
#     hashed_password: str
from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4

db = SQLAlchemy()

def get_uuid() :
    return uuid4().hex

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, default=get_uuid)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
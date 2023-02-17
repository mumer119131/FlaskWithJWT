from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

#load the .env file
load_dotenv()


# Created the flask app
app = Flask(__name__)





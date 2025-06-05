

# ===== Standard Library Imports =====
import os
import csv
import io
import json
import logging
import mimetypes
import random
import re
import socket
import string
import sys
import uuid
import secrets
import traceback
import shutil
import platform
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict

# ===== Load Environment Variables Early =====
from dotenv import load_dotenv
load_dotenv()

# ===== MongoDB Configuration =====
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/eduresourcehub')

# ===== Third-Party Imports =====
from bleach import clean
from markdown import markdown
from markupsafe import Markup

from flask import (
    Flask, abort, current_app, flash, jsonify, redirect, render_template,
    request, send_from_directory, session, url_for, make_response
)

from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)

from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_wtf.file import FileAllowed, FileField

from wtforms import (
    BooleanField, DateTimeField, FloatField, IntegerField,
    PasswordField, SelectField, StringField, SubmitField, TextAreaField
)

from wtforms.validators import (
    DataRequired, Email, NumberRange, Optional, ValidationError
)

from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import ClientDisconnected

from bson import ObjectId
from bson.errors import InvalidId
from bson.json_util import dumps
from pymongo.errors import ConnectionFailure, OperationFailure, PyMongoError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
# ===== Configure Logging =====
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
utc = timezone.utc

# ===== Custom JSON Encoder =====
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

# ===== Markdown to HTML Filter =====
def markdown_to_html(markdown_text):
    if not markdown_text:
        return ""
    return Markup(markdown(markdown_text))

# ===== Initialize Flask App =====
app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
app.config["MONGO_URI"] = MONGODB_URI
app.config["MONGO_CONNECT"] = False
app.config["MONGO_SERVER_SELECTION_TIMEOUT_MS"] = 5000

# Enable/Disable TLS based on environment
if "localhost" in MONGODB_URI or "127.0.0.1" in MONGODB_URI:
    app.config["MONGO_TLS"] = False
else:
    app.config["MONGO_TLS"] = True
    app.config["MONGO_TLS_ALLOW_INVALID_CERTIFICATES"] = True
#
app.start_time = time.time()
# ===== Test MongoDB Connection =====
try:
    mongo = PyMongo(app)
    mongo.cx.server_info()
    logger.info("✅ Successfully connected to MongoDB")
except Exception as e:
    logger.error(f"❌ Could not connect to MongoDB: {e}")
    print("Please check your connection string and network connectivity")
    sys.exit(1)


# ===== App Configuration =====
app.json_encoder = JSONEncoder
app.jinja_env.filters['markdown'] = markdown_to_html
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

app.config.update({
    'WTF_CSRF_ENABLED': True,
    'WTF_CSRF_SECRET_KEY': os.getenv('CSRF_SECRET_KEY', 'another-secret-key'),
    'UPLOAD_FOLDER':  os.path.join('static', 'uploads'),
    'ALLOWED_EXTENSIONS': {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'mp4', 'mov', 'avi'},
    'ALLOWED_AVATAR_EXTENSIONS': {'png', 'jpg', 'jpeg', 'gif'},
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,
    'AVATAR_FOLDER': os.path.join('static', 'images'),
    
})
# ===== Jitsi Configuration =====
app.config['JITSI_DOMAIN'] = os.getenv('JITSI_DOMAIN', 'meet.jit.si')
app.config['JITSI_OPTIONS'] = {
    'roomName': lambda: f'EduMeet-{secrets.token_hex(4)}',
    'width': '100%',
    'height': '100%',
    'parentNode': '#jitsi-container',
    'configOverwrite': {
        'startWithAudioMuted': True,
        'startWithVideoMuted': False,
        'enableWelcomePage': False
    },
    'interfaceConfigOverwrite': {
        'SHOW_JITSI_WATERMARK': False,
        'SHOW_WATERMARK_FOR_GUESTS': False
    }
}
# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['AVATAR_FOLDER'], exist_ok=True)

# ===== Flask Extensions =====
csrf = CSRFProtect(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    manage_session=False
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ===== User Class and Loader =====
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data['role']
        self.data = user_data

    def is_authenticated(self):
        return True

    def is_active(self):
        return self.data.get('is_active', True)

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
        return None
    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error loading user: {str(e)}")
        return None

# ===== Validators and Utility =====
def validate_email(form, field):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, field.data):
        raise ValidationError('Invalid email address')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ===== Constants =====
MEETING_EXPIRY_HOURS = 2
MEETING_ROOM_PREFIX = "edu-meet-"
MAX_MESSAGE_LENGTH = 1000
DEFAULT_AVATAR = 'images/default-avatar.png'
DEFAULT_AVATAR_STUDENT = 'images/default-avatar1.png'

# ===== Forms =====
class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class ResourceSearchForm(FlaskForm):
    submit = SubmitField('Submit')  # A simple form with a submit button

class AdminUserEditForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), validate_email])
    role = SelectField('Role', choices=[('student', 'Student'), ('educator', 'Educator'), ('admin', 'Admin')])
    is_active = BooleanField('Active')
    bio = TextAreaField('Bio')
    specialization = StringField('Specialization')
    profile_picture = FileField('Profile Picture', validators=[DataRequired()])  # Added field
    submit = SubmitField('Save Changes')

def validate_scheduled_time(self, field):
    user_time = field.data.replace(tzinfo=utc)
    if user_time < datetime.now(utc) + timedelta(minutes=15):
        raise ValidationError('Meeting must be scheduled at least 15 minutes in the future.')

class PaymentForm(FlaskForm):
    card_number = StringField('Card Number', validators=[DataRequired()])
    card_name = StringField('Cardholder Name', validators=[DataRequired()])
    expiry_date = StringField('Expiry Date (MM/YY)', validators=[DataRequired()])
    cvv = StringField('CVV', validators=[DataRequired()])
    submit = SubmitField('Pay Now')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')


# Update the ResourceForm class to ensure all fields are properly initialized
class ResourceForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    type = SelectField('Type', choices=[('free', 'Free'), ('paid', 'Paid')], validators=[DataRequired()])
    price = FloatField('Price', validators=[Optional()])
    file = FileField('Resource File', validators=[FileAllowed(app.config['ALLOWED_EXTENSIONS'])])
    thumbnail = FileField('Thumbnail Image', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!'),
        Optional()
    ])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Changes')

class SettingsForm(FlaskForm):
    site_name = StringField('Site Name', validators=[DataRequired()])
    site_description = StringField('Site Description', validators=[DataRequired()])
    enable_registration = BooleanField('Enable Registration')
    default_user_role = SelectField('Default Role', choices=[('student', 'Student'), ('educator', 'Educator')])
    resource_approval_required = BooleanField('Require Resource Approval')
    max_upload_size = IntegerField('Max Upload Size (MB)', validators=[NumberRange(min=1, max=100)])
    submit = SubmitField('Save Settings')    

class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    scheduled_time = DateTimeField('Scheduled Time', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    duration = IntegerField('Duration (minutes)', validators=[DataRequired(), NumberRange(min=15, max=240)])
    requires_approval = BooleanField('Require approval to join', default=False)
    is_private = BooleanField('Private Meeting (only invited users can join)', default=False)
    enable_chat = BooleanField('Enable meeting chat', default=True)
    enable_notes = BooleanField('Enable shared notes', default=True)
    submit = SubmitField('Create Meeting')

class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Bio')
    location = StringField('Location')
    education = StringField('Education')
    experience = StringField('Experience')
    website = StringField('Website')
    twitter = StringField('Twitter')
    linkedin = StringField('LinkedIn')
    github = StringField('GitHub')
    specialization = StringField('Specialization')
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Only image files (jpg, jpeg, png) are allowed')
    ])
    submit = SubmitField('Update Profile')


# Database collections
db = mongo.db
users = db.users
resources = db.resources
chats = db.chats
payments = db.payments
notifications = db.notifications
purchases = db.purchases
resource_comments = db.resource_comments
ratings = db.ratings
saved_resources = db.saved_resources
meetings = db.meetings
meeting_requests = db.meeting_requests

# Create indexes
chats.create_index([('participants', 1)])

notifications.create_index([('recipient_id', 1)])
notifications.create_index([('created_at', -1)])

resources.create_index([('educator_id', 1)])
resources.create_index([('upload_date', -1)])



# Helper Functions
def validate_object_id(id_str):
    """Validate if a string is a valid ObjectId"""
    try:
        return ObjectId(id_str)
    except Exception:
        raise BadRequest("Invalid ID format")

def sanitize_message_content(content):
    """Sanitize message content to prevent XSS"""
    return clean(content, tags=[], strip=True)

def format_conversation(conv, current_user_id):
    """Format conversation data for response"""
    formatted = {
        'chat_id': str(conv['_id']),
        'user_id': str(conv.get('user_id', '')) if 'user_id' in conv else None,
        'educator_id': str(conv.get('educator_id', '')) if 'educator_id' in conv else None,
        'name': conv.get('name', ''),
        'username': conv.get('username', ''),
        'avatar': conv.get('avatar', DEFAULT_AVATAR if conv.get('role') == 'educator' else DEFAULT_AVATAR_STUDENT),
        'unread_count': conv.get('unread_count', 0),
        'updated_at': conv.get('updated_at', datetime.now(timezone.utc)).isoformat(),
        'last_message': {
            'content': '',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender_id': ''
        }
    }
    
    if 'last_message' in conv and conv['last_message']:
        formatted['last_message'] = {
            'content': conv['last_message'].get('content', ''),
            'timestamp': conv['last_message'].get('timestamp', datetime.now(timezone.utc)).isoformat(),
            'sender_id': str(conv['last_message'].get('sender_id', ''))
        }
    
    return formatted

def create_new_conversation_entry(recipient_id, chat_id, current_user):
    """Create a new conversation entry for the list"""
    recipient = users.find_one({'_id': ObjectId(recipient_id)})
    if not recipient:
        return None
    
    return {
        'chat_id': chat_id,
        'user_id': str(recipient_id) if current_user.role == 'educator' else None,
        'educator_id': None if current_user.role == 'educator' else str(recipient_id),
        'name': recipient.get('name', recipient['username']),
        'username': recipient['username'],
        'avatar': recipient.get('avatar', DEFAULT_AVATAR if recipient.get('role') == 'educator' else DEFAULT_AVATAR_STUDENT),
        'last_message': {
            'content': '',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender_id': ''
        },
        'unread_count': 0
    }

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        try:
            # Get file extension
            ext = file.filename.rsplit('.', 1)[1].lower()
            # Generate unique filename
            filename = f"{uuid.uuid4().hex}.{ext}"
            # Secure the filename
            secure_name = secure_filename(filename)
            # Full path where file will be saved
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            # Save the file
            file.save(filepath)

            # Return relative path (without 'static/' prefix)
            return f"uploads/{secure_name}"
        except Exception as e:
            logger.error(f"Error saving file: {str(e)}")
            return None
    return None
#
def get_user_by_id(user_id):
    """Helper function to get user data by ID"""
    try:
        user_data = users.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
        return None
    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error getting user by ID: {str(e)}")
        return None

def calculate_storage_usage():
    """Calculate storage usage for different types of files"""
    storage_info = {
        'resources': 0,
        'avatars': 0,
        'thumbnails': 0,
        'total': 0,
        'used': 0
    }
    
    try:
        # Calculate resources storage
        resources_dir = os.path.join(app.config['UPLOAD_FOLDER'])
        if os.path.exists(resources_dir):
            storage_info['resources'] = round(sum(
                os.path.getsize(os.path.join(resources_dir, f)) 
                for f in os.listdir(resources_dir) 
                if os.path.isfile(os.path.join(resources_dir, f))
            ) / (1024 * 1024), 2)  # Convert to MB

        # Calculate avatars storage
        avatars_dir = os.path.join(app.config['AVATAR_FOLDER'])
        if os.path.exists(avatars_dir):
            storage_info['avatars'] = round(sum(
                os.path.getsize(os.path.join(avatars_dir, f)) 
                for f in os.listdir(avatars_dir) 
                if os.path.isfile(os.path.join(avatars_dir, f))
            ) / (1024 * 1024), 2)

        # Calculate thumbnails storage (assuming thumbnails are in uploads folder)
        thumbnails = resources.distinct('thumbnail')
        thumbnail_files = [t for t in thumbnails if t and not t.startswith('http')]
        storage_info['thumbnails'] = round(sum(
            os.path.getsize(os.path.join(app.static_folder, t)) 
            for t in thumbnail_files 
            if os.path.exists(os.path.join(app.static_folder, t))
        ) / (1024 * 1024), 2)

        # Calculate totals
        storage_info['used'] = storage_info['resources'] + storage_info['avatars'] + storage_info['thumbnails']
        
        # Get total disk space (this may not work on all systems)
        try:
            total, used, free = shutil.disk_usage("/")
            storage_info['total'] = round(total / (1024 * 1024), 2)  # Convert to MB
        except:
            storage_info['total'] = storage_info['used'] * 2  # Fallback if can't get disk info

    except Exception as e:
        logger.error(f"Error calculating storage usage: {str(e)}")
    
    return storage_info        
#
def check_missing_files():
    with app.app_context():
        try:
            all_resources = resources.find({}, {'file_url': 1})

            for resource in all_resources:
                if not resource.get('file_url'):
                    logger.warning(f"Resource {resource['_id']} has no file_url")
                    continue

                file_url = resource['file_url']
                if not (file_url.startswith('http://') or file_url.startswith('https://')):
                    if not file_url.startswith('uploads/'):
                        file_url = f"uploads/{file_url}"

                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(file_url))
                    if not os.path.exists(file_path):
                        logger.warning(f"File missing for resource {resource['_id']}: {file_path}")
                        resources.update_one(
                            {'_id': resource['_id']},
                            {'$set': {'is_active': False}}
                        )
        except Exception as e:
            logger.error(f"Error in file check task: {str(e)}")

# 🔧 Initialize and start the scheduler only once
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_missing_files,
    trigger=IntervalTrigger(days=1),
    id='check_missing_files',
    name='Disable resources with missing local files',
    replace_existing=True
)
scheduler.start()

# 🧹 Ensure scheduler shuts down cleanly on exit
atexit.register(lambda: scheduler.shutdown(wait=False))


#
def get_current_educator():
    if current_user.is_authenticated and current_user.role == 'educator':
        return users.find_one({'_id': ObjectId(current_user.id)})
    return None
#
def make_aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def ensure_timezone_aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def datetimeformat(value, format='%H:%M'):
    """Custom datetime format filter for Jinja2"""
    if value is None:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime(format)

app.jinja_env.filters['datetimeformat'] = datetimeformat    

def ensure_timezone_aware(dt):
    """Ensure a datetime object is timezone aware (UTC if not specified)"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def educator_required(f=None):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if not (current_user.is_authenticated and current_user.role == 'educator'):
                flash('Please login as an educator to access this page', 'danger')
                return redirect(url_for('login'))
            return func(*args, **kwargs)
        return wrapped_function
    
    if f is None:
        return decorator
    return decorator(f)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('You need to be an admin to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_file_icon(filename):
    if not filename:
        return 'fa-file'
    
    ext = filename.split('.')[-1].lower()
    
    if ext in ['pdf']:
        return 'fa-file-pdf'
    elif ext in ['doc', 'docx']:
        return 'fa-file-word'
    elif ext in ['xls', 'xlsx']:
        return 'fa-file-excel'
    elif ext in ['ppt', 'pptx']:
        return 'fa-file-powerpoint'
    elif ext in ['jpg', 'jpeg', 'png', 'gif']:
        return 'fa-file-image'
    elif ext in ['mp4', 'mov', 'avi']:
        return 'fa-file-video'
    elif ext in ['zip', 'rar', '7z']:
        return 'fa-file-archive'
    elif ext in ['txt', 'md']:
        return 'fa-file-alt'
    else:
        return 'fa-file'

def has_purchased(user_id, resource_id):
    """Check if a user has purchased a resource"""
    try:
        if not user_id:
            return False
            
        # Check if user is admin or resource owner
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if resource:
            if str(user_id) == str(resource['educator_id']):
                return True
                
        user = users.find_one({'_id': ObjectId(user_id)})
        if user and user.get('role') == 'admin':
            return True
            
        return purchases.find_one({
            'user_id': ObjectId(user_id),
            'resource_id': ObjectId(resource_id),
            'status': 'completed'
        }) is not None
    except Exception as e:
        logger.error(f"Error checking purchase: {str(e)}")
        return False
    
def is_authenticated():
    return current_user.is_authenticated

def is_educator():
    return is_authenticated() and current_user.role == 'educator'

def is_admin():
    return is_authenticated() and current_user.role == 'admin'

def create_default_admin():
    admin_username = 'admin'
    admin_password = 'admin123'
    
    if users.count_documents({'username': admin_username, 'role': 'admin'}) == 0:
        admin_data = {
            'username': admin_username,
            'password': generate_password_hash(admin_password),
            'role': 'admin',
            'name': 'Admin User',
            'email': 'admin@example.com',
            'created_at': datetime.now(timezone.utc),
            'is_active': True,
            'avatar': DEFAULT_AVATAR
        }
        users.insert_one(admin_data)
        logger.info(f"✅ Admin user created - Username: {admin_username}, Password: {admin_password}")

create_default_admin()

# Utility function to fetch the resource
def get_resource(resource_id):
    resource = resources.find_one({'_id': ObjectId(resource_id)})
    if resource is None:
        return None
    # Ensure 'rating_count' exists
    if 'rating_count' not in resource:
        resource['rating_count'] = 0
    return resource
    
def get_user_avatar(user_data):
    """Helper function to get correct avatar path"""
    if not user_data:
        return url_for('static', filename=f'images/{DEFAULT_AVATAR}')
    
    avatar = user_data.get('avatar')
    
    # Handle uploaded avatars
    if avatar and avatar.startswith('uploads/'):
        return url_for('static', filename=avatar)
    
    # Handle default avatars
    if not avatar or not os.path.exists(os.path.join(app.static_folder, 'images', avatar)):
        avatar = DEFAULT_AVATAR if user_data.get('role') == 'educator' else DEFAULT_AVATAR_STUDENT
    
    return url_for('static', filename=f'images/{avatar}')
    
@app.context_processor
def utility_processor():
    def get_unread_count(user_id, sender_id=None):
        if not current_user.is_authenticated:
            return 0
        try:
            query = {
                'recipient_id': user_id,
                'read': False,
                'type': 'message'
            }
            if sender_id:
                query['sender_id'] = sender_id

            return notifications.count_documents(query)
        except PyMongoError:
            return 0

    return dict(
        is_authenticated=is_authenticated,
        is_educator=is_educator,
        is_admin=is_admin,
        get_file_icon=get_file_icon,
        get_unread_count=get_unread_count,
        has_purchased=has_purchased,
        get_user_avatar=get_user_avatar
    )
@app.context_processor
def inject_chat_conversations():
    if current_user.is_authenticated:
        return {
            'chat_conversations': get_chat_conversations(current_user.id)
        }
    return {}

# Error handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': False, 'message': 'The form has expired. Please refresh the page and try again.'}), 400
    flash('The form has expired. Please try again.', 'danger')
    return redirect(request.referrer or url_for('index')), 400

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash('File size exceeds maximum allowed (16MB)', 'danger')
    return redirect(request.referrer or url_for('index')), 413

@app.errorhandler(404)
def page_not_found(e):
    context = {
        'current_year': datetime.now().year,
        'now': datetime.now(),
        'default_date': datetime.now()
    }
    return render_template('404.html', **context), 404

@app.errorhandler(500)
def internal_server_error(e):
    context = {
        'current_year': datetime.now().year,
        'now': datetime.now(),
        'default_date': datetime.now()
    }
    return render_template('500.html', **context), 500

@app.template_filter('timesince')
def timesince(dt):
    """Custom filter to display time since a datetime"""
    now = datetime.now(timezone.utc)
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    
    periods = (
        (diff.days // 365, "year", "years"),
        (diff.days // 30, "month", "months"),
        (diff.days // 7, "week", "weeks"),
        (diff.days, "day", "days"),
        (diff.seconds // 3600, "hour", "hours"),
        (diff.seconds // 60, "minute", "minutes"),
        (diff.seconds, "second", "seconds"),
    )
    
    for period, singular, plural in periods:
        if period:
            return f"{period} {singular if period == 1 else plural} ago"
    return "just now"

@app.route('/')
def index():
    try:
        recent_resources = list(resources.find().sort('upload_date', -1).limit(12))
        popular_resources = list(resources.find().sort('downloads', -1).limit(6))
        featured_educators = list(users.aggregate([
            {'$match': {'role': 'educator'}},
            {'$sort': {'resources_count': -1}},
            {'$limit': 4}
        ]))
        categories = resources.distinct('category')

        context = {
            'recent_resources': recent_resources,
            'popular_resources': popular_resources,
            'featured_educators': featured_educators,
            'categories': categories,
            'current_year': datetime.now().year,
            'now': datetime.now(),
            'default_date': datetime.now()
        }

        return render_template('index.html', **context)
                              
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        context = {
            'recent_resources': [],
            'popular_resources': [],
            'featured_educators': [],
            'categories': [],
            'current_year': datetime.now().year,
            'now': datetime.now(),
            'default_date': datetime.now()
        }
        return render_template('index.html', **context)
                              

from flask import render_template, request, url_for, flash
from bson.objectid import ObjectId
from pymongo.errors import PyMongoError
import logging

logger = logging.getLogger(__name__)


@app.route('/browse')
def browse_resources():
    try:
        category = request.args.get('category', '')
        resource_type = request.args.get('type', 'all')
        sort_by = request.args.get('sort', 'recent')
        search_query = request.args.get('q', '').strip()  # New search query parameter

        query = {}
        if category:
            query['category'] = category
        if resource_type != 'all':
            query['type'] = resource_type
        
        # Add text search if query exists
        if search_query:
            query['$text'] = {'$search': search_query}
            # Create text index if it doesn't exist
            try:
                resources.create_index([('title', 'text'), ('description', 'text'), ('category', 'text')])
            except:
                pass  # Index already exists

        sort_option = [('upload_date', -1)]
        if sort_by == 'popular':
            sort_option = [('downloads', -1)]
        elif sort_by == 'rating':
            sort_option = [('rating', -1)]
        elif search_query:  # If searching, sort by relevance
            sort_option = [('score', {'$meta': 'textScore'})]

        categories = resources.distinct('category')
        page = int(request.args.get('page', 1))
        per_page = 12
        skip = (page - 1) * per_page

        # Include score if searching
        projection = {}
        if search_query:
            projection['score'] = {'$meta': 'textScore'}

        total_resources = resources.count_documents(query)
        resources_list = list(
            resources.find(query, projection)
                     .sort(sort_option)
                     .skip(skip)
                     .limit(per_page)
        )

        educator_ids = list(set(str(r.get('educator_id')) for r in resources_list if r.get('educator_id')))
        educators_cursor = users.find({'_id': {'$in': [ObjectId(eid) for eid in educator_ids if ObjectId.is_valid(eid)]}})
        educators = {
            str(u['_id']): {
                'username': u.get('username'),
                'avatar': u.get('avatar'),
                'role': u.get('role', 'educator')
            }
            for u in educators_cursor
        }

        for r in resources_list:
            r['educator_id'] = str(r.get('educator_id'))

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_resources,
            'pages': (total_resources + per_page - 1) // per_page
        }

        return render_template('browse.html',
                               resources=resources_list,
                               educators=educators,
                               categories=categories,
                               current_category=category,
                               current_type=resource_type,
                               current_sort=sort_by,
                               search_query=search_query,  # Pass search query to template
                               pagination=pagination)

    except (ConnectionAbortedError, BrokenPipeError, socket.error):
        logger.warning("Client disconnected during browse request")
        return '', 499
    except PyMongoError as e:
        logger.error(f"Error browsing resources: {str(e)}")
        flash('Error loading resources', 'danger')
        return render_template('browse.html',
                               resources=[],
                               categories=[],
                               pagination={'page': 1, 'per_page': 12, 'total': 0, 'pages': 0})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('index'))
    
    form = FlaskForm()
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                flash('Both username and password are required', 'danger')
                return redirect(url_for('login'))
            
            user_data = users.find_one({'username': username})
            
            if user_data and check_password_hash(user_data['password'], password):
                user = User(user_data)
                login_user(user)
                
                session['user_id'] = str(user_data['_id'])
                session['username'] = user_data['username']
                session['role'] = user_data['role']
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login'))
        except PyMongoError as e:
            logger.error(f"Database error during login: {str(e)}")
            flash('Database error during login', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role')
            name = request.form.get('name')
            email = request.form.get('email')
            
            if not all([username, password, confirm_password, role, name, email]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))
            
            if users.find_one({'username': username}):
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))
            
            hashed_password = generate_password_hash(password)
            
            user_data = {
                'username': username,
                'password': hashed_password,
                'role': role,
                'name': name,
                'email': email,
                'created_at': datetime.now(timezone.utc),
                'resources_count': 0,
                'premium_resources_count': 0,
                'free_resources_count': 0,
                'is_active': True,
                'avatar': DEFAULT_AVATAR if role == 'educator' else DEFAULT_AVATAR_STUDENT
            }
            
            if role == 'educator':
                user_data.update({
                    'bio': '',
                    'specialization': '',
                    'rating': 0,
                    'meeting_key': str(uuid.uuid4())
                })
            
            if 'avatar' in request.files:
                avatar_file = request.files['avatar']
                if avatar_file.filename != '':
                    avatar_url = save_uploaded_file(avatar_file)
                    if avatar_url:
                        user_data['avatar'] = avatar_url
            
            users.insert_one(user_data)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        except PyMongoError as e:
            logger.error(f"Database error during registration: {str(e)}")
            flash('Database error during registration', 'danger')
    
    form = FlaskForm()
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    flash('You have been logged out', 'info')
    return response

@app.route('/profile/<username>')
@login_required
def profile(username):
    try:
        user_data = users.find_one({'username': username})
        if not user_data:
            abort(404)

        is_own_profile = str(current_user.id) == str(user_data['_id'])

        context = {
            'user': user_data,
            'is_own_profile': is_own_profile,
            'followers': list(users.find({
                '_id': {'$in': [ObjectId(fid) for fid in user_data.get('followers', [])]}
            })),
            'following': list(users.find({
                '_id': {'$in': [ObjectId(fid) for fid in user_data.get('following', [])]}
            })),
            'chat_conversations': get_chat_conversations(current_user.id)
        }

        context['unread_messages'] = sum(1 for convo in context['chat_conversations'] if convo.get('unread_count', 0) > 0)

        if user_data.get('role') == 'educator':
            # Educator profile
            now = datetime.now(timezone.utc)
            all_meetings = list(meetings.find({'host_id': str(user_data['_id'])}).sort('scheduled_time', -1))
            educator_meetings = defaultdict(list)

            for meeting in all_meetings:
                meeting['is_participant'] = (
                    str(current_user.id) == str(meeting.get('host_id')) or
                    str(current_user.id) in meeting.get('participants', [])
                )
                scheduled_time = meeting.get('scheduled_time')
                if scheduled_time and scheduled_time.tzinfo is None:
                    scheduled_time = scheduled_time.replace(tzinfo=timezone.utc)

                if not scheduled_time:
                    meeting_status = 'unscheduled'
                elif meeting.get('status') == 'ended' or scheduled_time < now - timedelta(hours=MEETING_EXPIRY_HOURS):
                    meeting_status = 'past'
                elif meeting.get('status') == 'in_progress':
                    meeting_status = 'in_progress'
                else:
                    meeting_status = 'upcoming'

                educator_meetings[meeting_status].append(meeting)

            user_resources = list(resources.find({
                'educator_id': str(user_data['_id']),
                'is_active': True
            }).sort('upload_date', -1).limit(6))

            earnings_data = list(payments.aggregate([
                {'$match': {'educator_id': str(user_data['_id'])}},
                {'$group': {
                    '_id': None,
                    'total_earnings': {'$sum': '$amount'},
                    'total_sales': {'$sum': 1}
                }}
            ]))

            context.update({
                'resources': user_resources,
                'educator_meetings': educator_meetings,
                'pending_requests': list(meeting_requests.find({
                    'meeting_id': {'$in': [m['meeting_id'] for m in all_meetings]},
                    'status': 'pending'
                }).limit(5)),
                'total_earnings': earnings_data[0]['total_earnings'] if earnings_data else 0,
                'total_sales': earnings_data[0]['total_sales'] if earnings_data else 0
            })

        else:
            # Student profile
            purchased_resources = []
            if is_own_profile:
                purchased_resources = list(purchases.aggregate([
                    {'$match': {
                        '$or': [
                            {'user_id': ObjectId(current_user.id)},
                            {'user_id': str(current_user.id)}
                        ],
                        'status': 'completed'
                    }},
                    {'$lookup': {
                        'from': 'resources',
                        'localField': 'resource_id',
                        'foreignField': '_id',
                        'as': 'resource'
                    }},
                    {'$unwind': '$resource'},
                    {'$lookup': {
                        'from': 'users',
                        'localField': 'resource.educator_id',
                        'foreignField': '_id',
                        'as': 'educator'
                    }},
                    {'$unwind': '$educator'},
                    {'$sort': {'purchase_date': -1}},
                    {'$project': {
                        'resource._id': 1,
                        'resource.title': 1,
                        'resource.description': 1,
                        'resource.category': 1,
                        'resource.type': 1,
                        'resource.price': 1,
                        'resource.thumbnail': 1,
                        'resource.downloads': 1,
                        'resource.upload_date': 1,
                        'educator.username': 1,
                        'educator.avatar': 1,
                        'purchase_date': 1
                    }}
                ]))

                saved_resources_list = list(saved_resources.aggregate([
                    {'$match': {'user_id': ObjectId(current_user.id)}},
                    {'$lookup': {
                        'from': 'resources',
                        'localField': 'resource_id',
                        'foreignField': '_id',
                        'as': 'resource'
                    }},
                    {'$unwind': '$resource'},
                    {'$sort': {'saved_at': -1}},
                    {'$limit': 6}
                ]))

                recent_resources = list(resources.aggregate([
                    {'$match': {
                        '_id': {'$in': [ObjectId(rid) for rid in user_data.get('recent_views', [])]}
                    }},
                    {'$sort': {'last_viewed': -1}},
                    {'$limit': 6}
                ]))

                following_educators = list(users.find({
                    '_id': {'$in': [ObjectId(eid) for eid in user_data.get('following', [])]},
                    'role': 'educator'
                }).limit(4))

                context.update({
                    'purchased_resources': purchased_resources,
                    'saved_resources': saved_resources_list,
                    'recent_resources': recent_resources,
                    'following_educators': following_educators,
                    'saved_count': len(saved_resources_list),
                    'meeting_requests': list(meeting_requests.find({
                        'user_id': str(current_user.id)
                    }).sort('requested_at', -1).limit(5))
                })
            else:
                # Viewing another user's student profile – don't show purchased resources
                context['purchased_resources'] = []

        return render_template('profile.html', **context)

    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}", exc_info=True)
        flash('Error loading profile', 'danger')
        return redirect(url_for('index'))


@app.route('/meeting/request/<request_id>/<action>', methods=['POST'])
@login_required
@educator_required
def handle_meeting_request(request_id, action):
    try:
        if action not in ['approved', 'rejected']:
            abort(400)
            
        request = meeting_requests.find_one({'_id': ObjectId(request_id)})
        if not request:
            return jsonify({'success': False, 'message': 'Request not found'}), 404
            
        meeting = meetings.find_one({'meeting_id': request['meeting_id'], 'host_id': current_user.id})
        if not meeting:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            
        meeting_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': action, 'processed_at': datetime.now(timezone.utc)}}
        )
        
        if action == 'approved':
            meetings.update_one(
                {'meeting_id': request['meeting_id']},
                {'$addToSet': {'participants': request['user_id']}}
            )
            
            # Notify user
            notifications.insert_one({
                'recipient_id': request['user_id'],
                'sender_id': current_user.id,
                'sender_username': current_user.username,
                'message': f"Your request to join '{meeting['title']}' has been approved",
                'type': 'meeting_request',
                'related_meeting': request['meeting_id'],
                'read': False,
                'created_at': datetime.now(timezone.utc)
            })
            
            socketio.emit('meeting_request_approved', {
                'meeting_id': request['meeting_id'],
                'host_id': current_user.id,
                'host_username': current_user.username
            }, room=f"user_{request['user_id']}")
        
        return jsonify({'success': True, 'message': f'Request {action}'})
        
    except Exception as e:
        logger.error(f"Error processing meeting request: {str(e)}")
        return jsonify({'success': False, 'message': 'Error processing request'}), 500



@app.route('/profile/')
@login_required
def my_profile():
    return redirect(url_for('profile', username=current_user.username))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_data = users.find_one({'_id': ObjectId(current_user.id)})
    if not user_data:
        flash('User not found', 'danger')
        return redirect(url_for('index'))

    form = ProfileForm(obj=user_data)

    if form.validate_on_submit():
        try:
            update_data = {
                'name': form.name.data,
                'email': form.email.data,
                'bio': form.bio.data,
                'location': form.location.data,
                'education': form.education.data,
                'experience': form.experience.data,
                'website': form.website.data,
                'twitter': form.twitter.data,
                'linkedin': form.linkedin.data,
                'github': form.github.data
            }

            if current_user.role == 'educator':
                update_data['specialization'] = form.specialization.data

            # Handle profile picture upload
            if form.profile_picture.data:
                picture = form.profile_picture.data
                filename = secure_filename(picture.filename)

                if filename != '' and allowed_file(filename):
                    # Delete old profile picture if it's not the default
                    old_avatar = user_data.get('avatar')
                    if old_avatar and not old_avatar.startswith('uploads/default-avatar'):
                        old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(old_avatar))
                        if os.path.exists(old_pic_path):
                            try:
                                os.remove(old_pic_path)
                            except Exception as e:
                                logger.error(f"Error deleting old profile picture: {str(e)}")

                    # Save new profile picture
                    new_filename = f"{current_user.id}_{filename}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    picture.save(save_path)

                    update_data['avatar'] = f"uploads/{new_filename}"
                else:
                    flash('Invalid file type for profile picture', 'danger')
                    return redirect(url_for('edit_profile'))

            users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': update_data}
            )

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile', username=current_user.username))

        except PyMongoError as e:
            logger.error(f"Error updating profile: {str(e)}")
            flash('Error updating profile', 'danger')

    return render_template('edit_profile.html', form=form, user=user_data)

@app.route('/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['avatar']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        # Delete old avatar if it exists and is not default
        user_data = users.find_one({'_id': ObjectId(current_user.id)})
        if user_data and 'avatar' in user_data and user_data['avatar'] and \
           not user_data['avatar'].startswith('images/default-avatar'):
            try:
                old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user_data['avatar'])
                if os.path.exists(old_avatar_path):
                    os.remove(old_avatar_path)
            except Exception as e:
                logger.error(f"Error deleting old avatar: {str(e)}")

        filename = secure_filename(f"{current_user.id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Update user's avatar in database
        avatar_url = f"uploads/{filename}"
        users.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'avatar': avatar_url}})
        
        return jsonify({'success': True, 'avatar': avatar_url})
    
    return jsonify({'success': False, 'message': 'Invalid file type'}), 400

@app.route('/follow/<educator_id>', methods=['POST'])
@login_required
def follow_educator(educator_id):
    try:
        # Validate educator exists and is actually an educator
        educator = users.find_one({
            '_id': ObjectId(educator_id),
            'role': 'educator'
        })
        if not educator:
            return jsonify({'success': False, 'message': 'Educator not found'}), 404
        
        # Check if already following
        if educator_id in current_user.data.get('following', []):
            return jsonify({'success': False, 'message': 'Already following this educator'}), 400
        
        # Update both user's following and educator's followers
        users.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$addToSet': {'following': educator_id}}
        )
        
        users.update_one(
            {'_id': ObjectId(educator_id)},
            {'$addToSet': {'followers': current_user.id}}
        )
        
        # Create notification
        notification_data = {
            'recipient_id': educator_id,
            'sender_id': current_user.id,
            'sender_username': current_user.username,
            'message': f"{current_user.username} started following you",
            'type': 'follow',
            'read': False,
            'created_at': datetime.now(timezone.utc)
        }
        notifications.insert_one(notification_data)
        
        return jsonify({
            'success': True,
            'message': 'Successfully followed educator',
            'follower_count': len(educator.get('followers', [])) + 1
        })
        
    except Exception as e:
        logger.error(f"Error following educator: {str(e)}")
        return jsonify({'success': False, 'message': 'Error following educator'}), 500

@app.route('/unfollow/<educator_id>', methods=['POST'])
@login_required
def unfollow_educator(educator_id):
    try:
        # Validate educator exists
        educator = users.find_one({'_id': ObjectId(educator_id)})
        if not educator:
            return jsonify({'success': False, 'message': 'Educator not found'}), 404
        
        # Check if actually following
        if educator_id not in current_user.data.get('following', []):
            return jsonify({'success': False, 'message': 'Not following this educator'}), 400
        
        # Update both user's following and educator's followers
        users.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$pull': {'following': educator_id}}
        )
        
        users.update_one(
            {'_id': ObjectId(educator_id)},
            {'$pull': {'followers': current_user.id}}
        )
        
        return jsonify({
            'success': True,
            'message': 'Successfully unfollowed educator',
            'follower_count': len(educator.get('followers', [])) - 1
        })
        
    except Exception as e:
        logger.error(f"Error unfollowing educator: {str(e)}")
        return jsonify({'success': False, 'message': 'Error unfollowing educator'}), 500

@app.route('/follower-count/<educator_id>', methods=['GET'])
def get_follower_count(educator_id):
    """Get follower count for an educator"""
    try:
        educator = users.find_one({'_id': ObjectId(educator_id)})
        if not educator:
            return jsonify({'success': False, 'message': 'Educator not found'}), 404
        
        return jsonify({
            'success': True,
            'count': len(educator.get('followers', []))
        })
        
    except Exception as e:
        logger.error(f"Error getting follower count: {str(e)}")
        return jsonify({'success': False, 'message': 'Error getting follower count'}), 500

@app.route('/is-following/<educator_id>', methods=['GET'])
@login_required
def is_following(educator_id):
    """Check if current user is following an educator"""
    try:
        if educator_id in current_user.data.get('following', []):
            return jsonify({'success': True, 'is_following': True})
        return jsonify({'success': True, 'is_following': False})
        
    except Exception as e:
        logger.error(f"Error checking follow status: {str(e)}")
        return jsonify({'success': False, 'message': 'Error checking follow status'}), 500

def get_following_educators(user_id):
    """Get list of educators a user is following"""
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return []
        
        following_ids = user.get('following', [])
        if not following_ids:
            return []
            
        educators = users.find({
            '_id': {'$in': [ObjectId(id) for id in following_ids]},
            'role': 'educator'
        })
        
        return [{
            'id': str(e['_id']),
            'username': e['username'],
            'name': e.get('name', ''),
            'avatar': e.get('avatar', DEFAULT_AVATAR),
            'specialization': e.get('specialization', '')
        } for e in educators]
        
    except Exception as e:
        logger.error(f"Error getting following educators: {str(e)}")
        return []

def get_followers(educator_id):
    """Get list of followers for an educator"""
    try:
        educator = users.find_one({'_id': ObjectId(educator_id)})
        if not educator:
            return []
        
        follower_ids = educator.get('followers', [])
        if not follower_ids:
            return []
            
        followers = users.find({
            '_id': {'$in': [ObjectId(id) for id in follower_ids]}
        })
        
        return [{
            'id': str(f['_id']),
            'username': f['username'],
            'name': f.get('name', ''),
            'avatar': f.get('avatar', DEFAULT_AVATAR if f.get('role') == 'educator' else DEFAULT_AVATAR_STUDENT)
        } for f in followers]
        
    except Exception as e:
        logger.error(f"Error getting followers: {str(e)}")
        return []

        
    
@app.route('/resource/<resource_id>/comment', methods=['POST'])
@login_required
def add_comment(resource_id):
    try:
        content = request.form.get('content', '').strip()
        if not content:
            return jsonify({'success': False, 'message': 'Comment cannot be empty'}), 400

        # Check if user has access to comment
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify({'success': False, 'message': 'Resource not found'}), 404

        has_access = False
        if resource['type'] == 'free':
            has_access = True
        else:
            if str(current_user.id) == str(resource['educator_id']) or current_user.role == 'admin':
                has_access = True
            else:
                has_access = purchases.find_one({
                    'user_id': ObjectId(current_user.id),
                    'resource_id': ObjectId(resource_id),
                    'status': 'completed'
                }) is not None

        if not has_access:
            return jsonify({'success': False, 'message': 'You need to purchase this resource to comment'}), 403

        # Determine avatar with fallback
        avatar = current_user.data.get('avatar')
        if not avatar:
            avatar = DEFAULT_AVATAR if current_user.role == 'educator' else DEFAULT_AVATAR_STUDENT

        # Create new comment
        comment_data = {
            'resource_id': ObjectId(resource_id),
            'user_id': ObjectId(current_user.id),
            'content': content,
            'timestamp': datetime.now(timezone.utc),
            'username': current_user.username,
            'avatar': avatar,
            'role': current_user.role
        }

        comment_id = resource_comments.insert_one(comment_data).inserted_id

        # Update resource comment count
        resources.update_one(
            {'_id': ObjectId(resource_id)},
            {'$inc': {'comments_count': 1}}
        )

        return jsonify({
            'success': True,
            'message': 'Comment added',
            'comment': {
                'id': str(comment_id),
                'user_id': str(current_user.id),
                'username': current_user.username,
                'avatar': avatar,
                'content': content,
                'timestamp': comment_data['timestamp'].isoformat(),
                'role': current_user.role
            }
        })

    except Exception as e:
        logger.error(f"Error adding comment: {str(e)}")
        return jsonify({'success': False, 'message': 'Error adding comment'}), 500


@app.route('/resource/<resource_id>/rate', methods=['POST'])
@login_required
def rate_resource(resource_id):
    try:
        # Get rating from request
        rating = int(request.form.get('rating'))
        if rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400

        # Get the resource
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify({'success': False, 'message': 'Resource not found'}), 404

        # Check if user has access to rate
        has_access = False
        if resource['type'] == 'free':
            has_access = True
        else:
            # Check if purchased or is owner/admin
            if str(current_user.id) == str(resource['educator_id']):
                has_access = True
            elif current_user.role == 'admin':
                has_access = True
            else:
                has_access = purchases.find_one({
                    'user_id': ObjectId(current_user.id),
                    'resource_id': ObjectId(resource_id),
                    'status': 'completed'
                }) is not None

        if not has_access:
            return jsonify({'success': False, 'message': 'You need to purchase this resource to rate it'}), 403

        # Update or create rating
        ratings.update_one(
            {
                'user_id': ObjectId(current_user.id),
                'resource_id': ObjectId(resource_id)
            },
            {
                '$set': {
                    'rating': rating,
                    'rated_at': datetime.now(timezone.utc)
                }
            },
            upsert=True
        )

        # Recalculate average rating
        pipeline = [
            {'$match': {'resource_id': ObjectId(resource_id)}},
            {'$group': {
                '_id': '$resource_id',
                'avg_rating': {'$avg': '$rating'},
                'count': {'$sum': 1}
            }}
        ]
        result = list(ratings.aggregate(pipeline))
        
        if result:
            avg_rating = round(result[0]['avg_rating'], 1)
            rating_count = result[0]['count']
            resources.update_one(
                {'_id': ObjectId(resource_id)},
                {'$set': {
                    'rating': avg_rating,
                    'rating_count': rating_count
                }}
            )
        else:
            avg_rating = 0
            rating_count = 0

        return jsonify({
            'success': True,
            'message': 'Rating submitted',
            'avg_rating': avg_rating,
            'rating_count': rating_count
        })

    except Exception as e:
        logger.error(f"Error rating resource: {str(e)}")
        return jsonify({'success': False, 'message': 'Error submitting rating'}), 500
    
@app.route('/resource/comment/<comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    try:
        comment = resource_comments.find_one({'_id': ObjectId(comment_id)})
        if not comment:
            flash('Comment not found', 'danger')
            return redirect(request.referrer or url_for('index'))
            
        # Verify user owns the comment or is admin/educator
        resource = resources.find_one({'_id': ObjectId(comment['resource_id'])})
        can_delete = (
    str(current_user.id) == str(comment['user_id']) or
    current_user.role == 'admin' or
    (current_user.role == 'educator' and 
     str(current_user.id) == str(resource['educator_id']))
)
        
        if not can_delete:
            flash('You are not authorized to delete this comment', 'danger')
            return redirect(request.referrer or url_for('index'))
            
        # Soft delete the comment
        resource_comments.update_one(
            {'_id': ObjectId(comment_id)},
            {'$set': {
                'is_deleted': True,
                'content': '[deleted]',
                'deleted_at': datetime.now(timezone.utc)
            }}
        )
        
        # Update resource comment count
        resources.update_one(
            {'_id': ObjectId(comment['resource_id'])},
            {'$inc': {'comments_count': -1}}
        )
        
        flash('Comment deleted successfully', 'success')
        return redirect(request.referrer or url_for('index'))
        
    except Exception as e:
        logger.error(f"Error deleting comment: {str(e)}")
        flash('Error deleting comment', 'danger')
        return redirect(request.referrer or url_for('index'))

        # Add these routes to your app.py


@app.route('/resource/<resource_id>/save', methods=['POST'])
@login_required
def save_resource(resource_id):
    """Save resource to user's library"""
    try:
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            return jsonify({'success': False, 'message': 'Resource not found'}), 404

        # Check if user has access to save
        has_access = resource.get('type') == 'free' or \
                   purchases.find_one({
                       'user_id': ObjectId(current_user.id),
                       'resource_id': ObjectId(resource_id),
                       'status': 'completed'
                   })

        if not has_access:
            return jsonify({'success': False, 'message': 'You need to purchase this resource to save it'}), 403

        # Check if already saved
        existing = db.saved_resources.find_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id)
        })

        if existing:
            return jsonify({'success': False, 'message': 'Resource already saved'}), 400

        db.saved_resources.insert_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id),
            'saved_at': datetime.now(timezone.utc)
        })

        return jsonify({'success': True, 'message': 'Resource saved to your library'})

    except Exception as e:
        logger.error(f"Error saving resource: {str(e)}")
        return jsonify({'success': False, 'message': 'Error saving resource'}), 500

@app.route('/resource/<resource_id>/unsave', methods=['POST'])
@login_required
def unsave_resource(resource_id):
    """Remove resource from user's library"""
    try:
        result = db.saved_resources.delete_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id)
        })

        if result.deleted_count > 0:
            return jsonify({'success': True, 'message': 'Resource removed from your library'})
        else:
            return jsonify({'success': False, 'message': 'Resource not found in your library'}), 404

    except Exception as e:
        logger.error(f"Error unsaving resource: {str(e)}")
        return jsonify({'success': False, 'message': 'Error removing resource'}), 500
    
@app.route('/resource/<resource_id>/is-saved')
@login_required
def is_resource_saved(resource_id):
    """Check if a resource is saved by the current user"""
    try:
        is_saved = saved_resources.find_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id)
        }) is not None
        return jsonify(is_saved)
    except Exception as e:
        logger.error(f"Error checking saved status: {str(e)}")
        return jsonify(False)

@app.route('/resource/<resource_id>/comments')
def get_resource_comments(resource_id):
    try:
        comments = list(resource_comments.aggregate([
            {'$match': {'resource_id': ObjectId(resource_id)}},
            {'$lookup': {
                'from': 'users',
                'localField': 'user_id',
                'foreignField': '_id',
                'as': 'user'
            }},
            {'$unwind': '$user'},
            {'$sort': {'timestamp': -1}},
            {'$project': {
                '_id': {'$toString': '$_id'},
                'content': 1,
                'timestamp': 1,
                'user._id': {'$toString': '$user._id'},
                'user.username': 1,
                'user.avatar': {
                    '$cond': [
                        {'$eq': ['$user.avatar', None]},
                        None,
                        {
                            '$cond': [
                                {'$or': [
                                    {'$eq': [{'$indexOfCP': ['$user.avatar', 'http']}, 0]},
                                    {'$eq': [{'$indexOfCP': ['$user.avatar', '/static']}, 0]}
                                ]},
                                '$user.avatar',
                                {'$concat': ['/static/', '$user.avatar']}
                            ]
                        }
                    ]
                },
                'user.role': 1
            }}
        ]))

        return jsonify(comments)

    except Exception as e:
        logger.error(f"Error getting comments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/resource/<resource_id>/ratings')
def get_resource_ratings(resource_id):
    """Get ratings for a specific resource."""
    try:
        ratings_list = list(ratings.aggregate([
            {'$match': {'resource_id': ObjectId(resource_id)}},
            {'$lookup': {
                'from': 'users',
                'localField': 'user_id',
                'foreignField': '_id',
                'as': 'user'
            }},
            {'$unwind': '$user'},
            {'$sort': {'rated_at': -1}},
            {'$project': {
                '_id': 1,
                'rating': 1,
                'rated_at': 1,
                'user._id': 1,
                'user.username': 1,
                'user.avatar': 1,
                'user.role': 1
            }}
        ]))

        result = [{
            'id': str(r['_id']),
            'rating': r['rating'],
            'rated_at': r['rated_at'].isoformat(),
            'user': {
                'id': str(r['user']['_id']),
                'username': r['user']['username'],
                'avatar': r['user'].get('avatar') or (
                    DEFAULT_AVATAR if r['user'].get('role') == 'educator' else DEFAULT_AVATAR_STUDENT
                )
            }
        } for r in ratings_list]

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error getting ratings: {str(e)}")
        return jsonify({'error': 'Error getting ratings'}), 500


@app.route('/library')
@login_required
def library():
    """View user's saved resources library"""
    try:
        # Get saved resources with resource details
        saved_resources = list(db.saved_resources.aggregate([
            {'$match': {'user_id': ObjectId(current_user.id)}},
            {'$lookup': {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }},
            {'$unwind': '$resource'},
            {'$lookup': {
                'from': 'users',
                'localField': 'resource.educator_id',
                'foreignField': '_id',
                'as': 'educator'
            }},
            {'$unwind': '$educator'},
            {'$sort': {'saved_at': -1}},
            {'$project': {
                'resource._id': 1,
                'resource.title': 1,
                'resource.description': 1,
                'resource.category': 1,
                'resource.type': 1,
                'resource.price': 1,
                'resource.thumbnail': 1,
                'resource.downloads': 1,
                'resource.upload_date': 1,
                'educator.username': 1,
                'educator.avatar': 1,
                'saved_at': 1
            }}
        ]))

        return render_template('library.html', 
                            saved_resources=saved_resources,
                            current_user=current_user)
    except PyMongoError as e:
        logger.error(f"Error loading library: {str(e)}")
        flash('Error loading your library', 'danger')
        return redirect(url_for('index'))
    
@app.route('/upload', methods=['GET', 'POST'])
@login_required
@educator_required
def upload_resource():
    form = ResourceForm()
    
    if form.validate_on_submit():
        try:
            # Handle file upload
            if not form.file.data or form.file.data.filename == '':
                flash('Resource file is required', 'danger')
                return redirect(url_for('upload_resource'))
                
            # Save resource file
            file_url = save_uploaded_file(form.file.data)
            if not file_url:
                flash('Error saving resource file', 'danger')
                return redirect(url_for('upload_resource'))

            # Handle thumbnail upload (optional)
            thumbnail_url = None
            if form.thumbnail.data and form.thumbnail.data.filename != '':
                thumbnail_url = save_uploaded_file(form.thumbnail.data)

            # Create resource data
            resource_data = {
                'title': form.title.data,
                'description': form.description.data,
                'category': form.category.data,
                'type': form.type.data,
                'price': float(form.price.data) if form.type.data == 'paid' else 0,
                'educator_id': current_user.id,
                'educator_username': current_user.username,
                'upload_date': datetime.now(timezone.utc),
                'downloads': 0,
                'rating': 0,
                'rating_count': 0,
                'comments_count': 0,
                'file_url': file_url,
                'thumbnail': thumbnail_url,
                'is_active': True
            }

            # Insert resource
            resource_id = resources.insert_one(resource_data).inserted_id

            # Update educator stats
            update_data = {'$inc': {'resources_count': 1}}
            if form.type.data == 'paid':
                update_data['$inc']['premium_resources_count'] = 1
            else:
                update_data['$inc']['free_resources_count'] = 1

            users.update_one({'_id': ObjectId(current_user.id)}, update_data)

            flash('Resource uploaded successfully!', 'success')
            return redirect(url_for('view_resource', resource_id=resource_id))

        except Exception as e:
            logger.error(f"Error uploading resource: {str(e)}")
            flash(f'Error uploading resource: {str(e)}', 'danger')
            return redirect(url_for('upload_resource'))

    return render_template('upload.html', form=form)

@app.route('/resource/<resource_id>')
@login_required
def view_resource(resource_id):
    try:
        # Fetch the resource by its ObjectId
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('index'))

        # Ensure rating fields exist and have default values
        if 'rating' not in resource:
            resource['rating'] = 0
        if 'rating_count' not in resource:
            resource['rating_count'] = 0

        # Fetch educator details
        educator = users.find_one({'_id': ObjectId(resource['educator_id'])})
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('index'))

        # Check if the resource has been purchased or if user is admin or owner
        purchased = False
        is_admin_or_owner = False
        
        if current_user.is_authenticated:
            purchased = purchases.find_one({
                'user_id': ObjectId(current_user.id),
                'resource_id': ObjectId(resource_id),
                'status': 'completed'
            }) is not None
            
            # Check if user is admin or the resource owner
            is_admin_or_owner = current_user.role == 'admin' or str(current_user.id) == str(resource['educator_id'])

        # Determine access based on resource type, purchase status, or user role
        has_access = resource['type'] == 'free' or purchased or is_admin_or_owner

        # Get comments and rating if access is granted
        comments = []
        user_rating = None
        if has_access:
            comments = list(resource_comments.find({'resource_id': ObjectId(resource_id)}).sort('timestamp', -1))
            if current_user.is_authenticated:
                user_rating = ratings.find_one({
                    'user_id': ObjectId(current_user.id),
                    'resource_id': ObjectId(resource_id)
                })

        # Get related resources
        related_resources = list(resources.find({
            'educator_id': resource['educator_id'],
            '_id': {'$ne': ObjectId(resource_id)}
        }).limit(3))

        # Render the resource page template with all the context variables
        return render_template('resource.html',
                           resource=resource,
                           educator=educator,
                           has_access=has_access,
                           purchased=purchased,
                           is_admin_or_owner=is_admin_or_owner,
                           comments=comments,
                           user_rating=user_rating,
                           related_resources=related_resources)

    except Exception as e:
        logger.error(f"Error viewing resource: {str(e)}")
        flash('Error loading resource', 'danger')
        return redirect(url_for('index'))
    
@app.route('/resource/<resource_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_resource(resource_id):
    try:
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('index'))

        # Check if current user is owner or admin
        if str(current_user.id) != str(resource['educator_id']) and current_user.role != 'admin':
            flash('You are not authorized to edit this resource', 'danger')
            return redirect(url_for('view_resource', resource_id=resource_id))

        form = ResourceForm(obj=resource)

        if form.validate_on_submit():
            update_data = {
                'title': form.title.data,
                'description': form.description.data,
                'category': form.category.data,
                'type': form.type.data,
                'price': form.price.data if form.type.data == 'paid' else 0,
                'is_active': form.is_active.data,
                'updated_at': datetime.now(timezone.utc)
            }

            # Handle file update - make sure we don't remove the file_url
            if form.file.data:
                file_url = save_uploaded_file(form.file.data)
                if file_url:
                    update_data['file_url'] = file_url
                else:
                    flash('File upload failed, keeping existing file.', 'warning')

            # Handle thumbnail upload (this is the key fix)
            if form.thumbnail.data:
                thumbnail_file = form.thumbnail.data
                if thumbnail_file.filename != '':
                    # Delete old thumbnail if it exists and isn't default
                    old_thumbnail = resource.get('thumbnail')
                    if old_thumbnail and not old_thumbnail.startswith('images/default'):
                        try:
                            old_path = os.path.join(app.static_folder, old_thumbnail)
                            if os.path.exists(old_path):
                                os.remove(old_path)
                        except Exception as e:
                            logger.error(f"Error deleting old thumbnail: {str(e)}")

                    # Save new thumbnail
                    thumbnail_url = save_uploaded_file(thumbnail_file)
                    if thumbnail_url:
                        update_data['thumbnail'] = thumbnail_url

            # Update resource in database
            resources.update_one(
                {'_id': ObjectId(resource_id)},
                {'$set': update_data}
            )

            flash('Resource updated successfully!', 'success')
            return redirect(url_for('view_resource', resource_id=resource_id))

        return render_template('edit_resource.html', form=form, resource=resource)

    except Exception as e:
        logger.error(f"Error editing resource: {str(e)}")
        flash('Error editing resource', 'danger')
        return redirect(url_for('index'))

@app.route('/resource/<resource_id>/delete', methods=['POST'])
@login_required
@educator_required
def delete_resource(resource_id):
    try:
        resource = resources.find_one({
            '_id': ObjectId(resource_id),
            'educator_id': current_user.id
        })
        if not resource:
            flash('Resource not found or unauthorized', 'danger')
            return redirect(url_for('index'))

        # Soft delete by marking as inactive
        resources.update_one(
            {'_id': ObjectId(resource_id)},
            {'$set': {'is_active': False}}
        )

        flash('Resource has been deactivated', 'success')
        return redirect(url_for('profile', username=current_user.username))

    except Exception as e:
        logger.error(f"Error deleting resource: {str(e)}")
        flash('Error deleting resource', 'danger')
        return redirect(url_for('index'))

@app.route('/resource/<resource_id>/preview')
def preview_resource(resource_id):
    """Preview a resource (shows limited info for paid resources)"""
    try:
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('index'))

        educator = users.find_one({'_id': ObjectId(resource['educator_id'])})
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('index'))

        # For paid resources, show limited preview to non-purchasers
        preview_content = resource.get('description', '')
        if resource['type'] == 'paid' and current_user.is_authenticated:
            # Check if user has purchased
            purchased = purchases.find_one({
                'user_id': ObjectId(current_user.id),
                'resource_id': ObjectId(resource_id),
                'status': 'completed'
            })
            if not purchased and str(current_user.id) != str(resource['educator_id']) and current_user.role != 'admin':
                preview_content = ' '.join(preview_content.split()[:50]) + '...'

        return render_template('resource_preview.html',
            resource=resource,
            educator=educator,
            preview_content=preview_content,
            is_authenticated=current_user.is_authenticated
        )

    except Exception as e:
        logger.error(f"Error viewing resource preview: {str(e)}")
        flash('Error loading resource', 'danger')
        return redirect(url_for('index'))
    
@app.route('/meetings/create', methods=['GET', 'POST'])
@login_required
@educator_required
def create_meeting():
    form = MeetingForm()
    
    if form.validate_on_submit():
        try:
            # Generate unique meeting ID
            meeting_id = f"EDU-{secrets.token_hex(4).upper()}"
            
            # Convert scheduled_time to UTC if it exists
            scheduled_time = None
            if form.scheduled_time.data:
                scheduled_time = form.scheduled_time.data.replace(tzinfo=timezone.utc)
                if scheduled_time < datetime.now(timezone.utc) + timedelta(minutes=15):
                    flash('Meeting must be scheduled at least 15 minutes in the future', 'danger')
                    return redirect(url_for('create_meeting'))
            
            # Create meeting data
            meeting_data = {
                'meeting_id': meeting_id,
                'title': form.title.data,
                'description': form.description.data,
                'host_id': current_user.id,
                'host_username': current_user.username,
                'scheduled_time': scheduled_time,
                'duration': form.duration.data,
                'requires_approval': form.requires_approval.data,
                'is_private': form.is_private.data,
                'enable_chat': form.enable_chat.data,
                'enable_notes': form.enable_notes.data,
                'created_at': datetime.now(timezone.utc),
                'status': 'scheduled' if scheduled_time else 'ready',
                'participants': [],
                'is_active': True,
                'jitsi_room': f"EduMeet-{secrets.token_hex(4)}",
                'invited_users': []
            }
            
            # Insert meeting
            meetings.insert_one(meeting_data)
            
            flash('Meeting created successfully!', 'success')
            return redirect(url_for('view_meeting', meeting_id=meeting_id))
            
        except Exception as e:
            logger.error(f"Error creating meeting: {str(e)}")
            flash('Error creating meeting', 'danger')
    
    # For GET requests, set default duration to 60 minutes
    form.duration.data = form.duration.data or 60
    return render_template('create_meeting.html', form=form)


@app.route('/meeting/<meeting_id>')
@login_required
def view_meeting(meeting_id):
    try:
        meeting = meetings.find_one({'meeting_id': meeting_id})
        if not meeting:
            flash('Meeting not found', 'danger')
            return redirect(url_for('index'))
            
        # Check if user can access this meeting
        if meeting.get('is_private') and str(current_user.id) != meeting['host_id']:
            if str(current_user.id) not in meeting.get('invited_users', []):
                flash('This is a private meeting and you are not invited', 'danger')
                return redirect(url_for('index'))
        
        # Check if meeting requires approval
        if meeting.get('requires_approval') and str(current_user.id) != meeting['host_id']:
            if str(current_user.id) not in meeting.get('participants', []):
                # Check if request already exists
                existing_request = meeting_requests.find_one({
                    'meeting_id': meeting_id,
                    'user_id': str(current_user.id),
                    'status': 'pending'
                })
                if not existing_request:
                    # Get host details for the template
                    host = users.find_one({'_id': ObjectId(meeting['host_id'])})
                    if not host:
                        flash('Meeting host not found', 'danger')
                        return redirect(url_for('index'))
                        
                    meeting['host_username'] = host['username']
                    return render_template('meeting_request.html', meeting=meeting)
        
        # Get host details
        host = users.find_one({'_id': ObjectId(meeting['host_id'])})
        if not host:
            flash('Meeting host not found', 'danger')
            return redirect(url_for('index'))
            
        # Check if meeting is active
        now = datetime.now(timezone.utc)
        if meeting.get('status') == 'ended':
            flash('This meeting has ended', 'info')
            return redirect(url_for('index'))
            
        # Check scheduled time
        if meeting.get('scheduled_time') and meeting['scheduled_time'] > now:
            if str(current_user.id) != meeting['host_id']:
                flash('Meeting has not started yet', 'info')
                return redirect(url_for('index'))
        
        # Add participant if not already added
        if str(current_user.id) != meeting['host_id']:
            meetings.update_one(
                {'meeting_id': meeting_id},
                {'$addToSet': {'participants': str(current_user.id)}}
            )
        
        return render_template('meeting_room.html',
                            meeting=meeting,
                            host=host,
                            current_user=current_user,
                            jitsi_domain=app.config['JITSI_DOMAIN'],
                            jitsi_room=meeting['jitsi_room'])
    
    except Exception as e:
        logger.error(f"Error viewing meeting: {str(e)}", exc_info=True)
        flash('Error loading meeting', 'danger')
        return redirect(url_for('index'))

@app.route('/meeting/<meeting_id>/request_join', methods=['POST'])
@login_required
def request_join_meeting(meeting_id):
    try:
        meeting = meetings.find_one({'meeting_id': meeting_id})
        if not meeting:
            flash('Meeting not found', 'danger')
            return redirect(url_for('index'))
            
        # Check if already a participant
        if str(current_user.id) in meeting.get('participants', []):
            flash('You are already a participant in this meeting', 'info')
            return redirect(url_for('view_meeting', meeting_id=meeting_id))
            
        # Check if request already exists
        existing_request = meeting_requests.find_one({
            'meeting_id': meeting_id,
            'user_id': str(current_user.id),
            'status': 'pending'
        })
        if existing_request:
            flash('You already have a pending request for this meeting', 'info')
            return redirect(url_for('view_meeting', meeting_id=meeting_id))
            
        # Create meeting request
        request_data = {
            'meeting_id': meeting_id,
            'user_id': str(current_user.id),
            'username': current_user.username,
            'status': 'pending',
            'requested_at': datetime.now(timezone.utc),
            'message': request.form.get('message', '')
        }
        
        meeting_requests.insert_one(request_data)
        
        # Create notification for host
        notification_data = {
            'recipient_id': meeting['host_id'],
            'sender_id': str(current_user.id),
            'sender_username': current_user.username,
            'message': f"{current_user.username} wants to join your meeting: {meeting['title']}",
            'type': 'meeting_request',
            'related_meeting': meeting_id,
            'read': False,
            'created_at': datetime.now(timezone.utc)
        }
        notifications.insert_one(notification_data)
        
        # Notify host via Socket.IO
        socketio.emit('new_meeting_request', {
            'meeting_id': meeting_id,
            'user_id': str(current_user.id),
            'username': current_user.username,
            'message': request.form.get('message', '')
        }, room=f"user_{meeting['host_id']}")
        
        flash('you joined the meeting', 'success')
        return redirect(url_for('view_meeting', meeting_id=meeting_id))
        
    except Exception as e:
        logger.error(f"Error sending join request: {str(e)}")
        flash('Error sending request', 'danger')
        return redirect(url_for('view_meeting', meeting_id=meeting_id))

@app.route('/meeting/<meeting_id>/end', methods=['POST'])
@login_required
@educator_required
def end_meeting(meeting_id):
    try:
        # Verify the current user is the host
        meeting = meetings.find_one({
            'meeting_id': meeting_id,
            'host_id': current_user.id
        })
        if not meeting:
            return jsonify({'success': False, 'message': 'Meeting not found or unauthorized'}), 404
            
        # Update meeting status
        meetings.update_one(
            {'meeting_id': meeting_id},
            {'$set': {
                'status': 'ended',
                'ended_at': datetime.now(timezone.utc),
                'is_active': False
            }}
        )
        
        # Notify participants
        socketio.emit('meeting_ended', {
            'message': 'Host has ended the meeting',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"meeting_{meeting_id}")
        
        return jsonify({'success': True, 'message': 'Meeting ended'})
        
    except Exception as e:
        logger.error(f"Error ending meeting: {str(e)}")
        return jsonify({'success': False, 'message': 'Error ending meeting'}), 500



@app.route('/meeting/<meeting_id>/cancel', methods=['POST'])
@login_required
@educator_required
def cancel_meeting(meeting_id):
    try:
        meeting = meetings.find_one({
            'meeting_id': meeting_id,
            'host_id': current_user.id
        })
        if not meeting:
            return jsonify({'success': False, 'message': 'Meeting not found or unauthorized'}), 404
            
        meetings.update_one(
            {'meeting_id': meeting_id},
            {'$set': {
                'status': 'cancelled',
                'is_active': False,
                'cancelled_at': datetime.now(timezone.utc)
            }}
        )
        
        # Notify participants
        socketio.emit('meeting_cancelled', {
            'meeting_id': meeting_id,
            'message': 'Meeting has been cancelled by the host'
        }, room=f"meeting_{meeting_id}")
        
        return jsonify({'success': True, 'message': 'Meeting cancelled'})
        
    except Exception as e:
        logger.error(f"Error cancelling meeting: {str(e)}")
        return jsonify({'success': False, 'message': 'Error cancelling meeting'}), 500        


@app.route('/meeting/<meeting_id>/approve/<user_id>', methods=['POST'])
@login_required
@educator_required
def approve_meeting_request(meeting_id, user_id):
    try:
        # Verify the current user is the host
        meeting = meetings.find_one({
            'meeting_id': meeting_id,
            'host_id': current_user.id
        })
        if not meeting:
            return jsonify({'success': False, 'message': 'Meeting not found or unauthorized'}), 404
            
        # Update the request status
        meeting_requests.update_one(
            {'meeting_id': meeting_id, 'user_id': user_id},
            {'$set': {'status': 'approved', 'processed_at': datetime.now(timezone.utc)}}
        )
        
        # Add user to meeting participants
        meetings.update_one(
            {'meeting_id': meeting_id},
            {'$addToSet': {'participants': user_id}}
        )
        
        # Notify the user
        notifications.insert_one({
            'recipient_id': user_id,
            'sender_id': current_user.id,
            'sender_username': current_user.username,
            'message': f"Your request to join '{meeting['title']}' has been approved",
            'type': 'meeting_request',
            'related_meeting': meeting_id,
            'read': False,
            'created_at': datetime.now(timezone.utc)
        })
        
        socketio.emit('meeting_request_approved', {
            'meeting_id': meeting_id,
            'host_id': current_user.id,
            'host_username': current_user.username
        }, room=f"user_{user_id}")
        
        return jsonify({'success': True, 'message': 'Request approved'})
        
    except Exception as e:
        logger.error(f"Error approving meeting request: {str(e)}")
        return jsonify({'success': False, 'message': 'Error approving request'}), 500

@app.route('/payment/<resource_id>', methods=['GET', 'POST'])
@login_required
def payment_page(resource_id):
    try:
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource or resource['type'] != 'paid':
            flash('Invalid resource', 'danger')
            return redirect(url_for('index'))
        
        # Check if the user has already purchased this resource
        existing_purchase = purchases.find_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id),
            'status': 'completed'
        })
        
        if existing_purchase:
            flash('You have already purchased this resource', 'info')
            return redirect(url_for('view_resource', resource_id=resource_id))
        
        form = PaymentForm()

        if request.method == 'POST':
            payment_data = {
                'user_id': ObjectId(current_user.id),
                'resource_id': ObjectId(resource_id),
                'educator_id': ObjectId(resource['educator_id']),
                'amount': resource['price'],
                'payment_method': 'credit_card',
                'payment_date': datetime.now(timezone.utc),
                'status': 'completed',
                'transaction_id': str(uuid.uuid4()),
                'card_last4': request.form.get('card_number')[-4:],
                'card_brand': 'VISA'
            }
            payment_id = str(payments.insert_one(payment_data).inserted_id)

            purchase_data = {
                'user_id': ObjectId(current_user.id),
                'resource_id': ObjectId(resource_id),
                'payment_id': payment_id,
                'purchase_date': datetime.now(timezone.utc),
                'status': 'completed'
            }
            purchases.insert_one(purchase_data)

            users.update_one(
                {'_id': ObjectId(resource['educator_id'])},
                {'$inc': {'earnings': resource['price']}}
            )

            notification_data = {
                'recipient_id': resource['educator_id'],
                'sender_id': ObjectId(current_user.id),
                'sender_username': current_user.username,
                'message': f"{current_user.username} purchased your resource: {resource['title']}",
                'type': 'purchase',
                'related_resource': resource_id,
                'read': False,
                'created_at': datetime.now(timezone.utc)
            }
            notifications.insert_one(notification_data)

            flash('Payment successful! You can now access the resource.', 'success')
            return redirect(url_for('view_resource', resource_id=resource_id))

        educator = users.find_one({'_id': ObjectId(resource['educator_id'])})

        return render_template('payment.html',
                           resource=resource,
                           form=form,
                           price=resource['price'],
                           educator=educator)
    except Exception as e:
        logger.error(f"Error processing payment: {str(e)}")
        flash('Error processing payment', 'danger')
        return redirect(url_for('view_resource', resource_id=resource_id))
    
@app.route('/download/<resource_id>')
@login_required
def download_resource(resource_id):
    try:
        # Validate ObjectId
        try:
            resource_obj_id = ObjectId(resource_id)
        except InvalidId:
            logger.error(f"Invalid resource ID format: {resource_id}")
            flash('Invalid resource ID.', 'danger')
            return redirect(url_for('index'))

        # Fetch resource with projection to only get needed fields
        resource = resources.find_one(
            {'_id': resource_obj_id},
            {
                'file_url': 1,
                'educator_id': 1,
                'type': 1,
                'title': 1
            }
        )
        
        if not resource:
            logger.error(f"Resource not found: {resource_id}")
            flash('Resource not found', 'danger')
            return redirect(url_for('index'))
            
        # Check if file_url exists and is not empty
        if not resource.get('file_url'):
            logger.error(f"Resource has no file URL: {resource_id}")
            flash('This resource is not available for download. Please contact the educator.', 'danger')
            return redirect(url_for('view_resource', resource_id=resource_id))

        # Check access permissions
        has_access = False
        if resource.get('type', 'free') == 'free':
            has_access = True
        else:
            if current_user.is_authenticated:
                # Check if user is owner or admin
                if str(current_user.id) == str(resource.get('educator_id')):
                    has_access = True
                elif current_user.role == 'admin':
                    has_access = True
                else:
                    # Check purchase record
                    purchase = purchases.find_one({
                        'user_id': ObjectId(current_user.id),
                        'resource_id': resource_obj_id,
                        'status': 'completed'
                    })
                    if purchase:
                        has_access = True

        if not has_access:
            flash('You need to purchase this resource before downloading', 'danger')
            return redirect(url_for('view_resource', resource_id=resource_id))

        # Construct file path - handle both full URLs and relative paths
        file_url = resource['file_url']
        
        # If it's a full URL (starts with http), redirect to it
        if file_url.startswith('http://') or file_url.startswith('https://'):
            return redirect(file_url)
            
        # Handle relative paths
        if not file_url.startswith('uploads/'):
            file_url = f"uploads/{file_url}"
            
        filename = os.path.basename(file_url)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Verify file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found at path: {file_path}")
            flash('File not found on server. The educator may need to re-upload this resource.', 'danger')
            return redirect(url_for('view_resource', resource_id=resource_id))

        # Update download count
        resources.update_one(
            {'_id': resource_obj_id},
            {'$inc': {'downloads': 1}}
        )

        # Create download filename
        file_ext = os.path.splitext(filename)[1]
        download_name = f"{secure_filename(resource.get('title', 'resource'))}{file_ext}"

        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True,
            download_name=download_name
        )

    except Exception as e:
        logger.error(f"Error processing download: {str(e)}", exc_info=True)
        flash('Error processing download', 'danger')
        return redirect(url_for('view_resource', resource_id=resource_id))

# Add this route to help debug purchase records
@app.route('/debug/purchase/<resource_id>')
@login_required
def debug_purchase(resource_id):
    try:
        purchase = purchases.find_one({
            'user_id': ObjectId(current_user.id),
            'resource_id': ObjectId(resource_id)
        })
        
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        
        return jsonify({
            'has_purchase': purchase is not None,
            'purchase_status': purchase.get('status') if purchase else None,
            'resource_exists': resource is not None,
            'resource_type': resource.get('type') if resource else None,
            'is_owner': str(current_user.id) == str(resource.get('educator_id')) if resource else False,
            'is_admin': current_user.role == 'admin'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500        

    
@app.route('/search')
def search():
    try:
        query = request.args.get('q', '')
        category = request.args.get('category', '')
        
        search_filter = {}
        if query:
            search_filter['$or'] = [
                {'title': {'$regex': query, '$options': 'i'}},
                {'description': {'$regex': query, '$options': 'i'}},
                {'category': {'$regex': query, '$options': 'i'}}
            ]
        if category:
            search_filter['category'] = category
        
        results = list(resources.find(search_filter).sort('upload_date', -1)) if search_filter else []
        return render_template('search_results.html',
                            results=results,
                            query=query,
                            category=category)
    except PyMongoError as e:
        logger.error(f"Error performing search: {str(e)}")
        flash('Error performing search', 'danger')
        return render_template('search_results.html', results=[], query=query, category=category)
          

@app.route('/educators')
def browse_educators():
    try:
        # Get filter parameters
        search_query = request.args.get('q', '')
        specialization = request.args.get('specialization', '')
        
        # Build query
        query = {'role': 'educator'}
        if search_query:
            query['$or'] = [
                {'name': {'$regex': search_query, '$options': 'i'}},
                {'specialization': {'$regex': search_query, '$options': 'i'}},
                {'bio': {'$regex': search_query, '$options': 'i'}}
            ]
        if specialization:
            query['specialization'] = specialization
        
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = 12
        skip = (page - 1) * per_page
        
        # Get educators
        educators = list(users.find(query)
                        .sort('resources_count', -1)
                        .skip(skip)
                        .limit(per_page))
        
        # Get total count for pagination
        total_educators = users.count_documents(query)
        
        # Get unique specializations for filter dropdown
        specializations = users.distinct('specialization', {'role': 'educator'})
        specializations = [s for s in specializations if s]  # Remove None values
        
        # Get popular categories and their counts
        categories = resources.aggregate([
            {'$group': {
                '_id': '$category',
                'count': {'$sum': 1}
            }},
            {'$sort': {'count': -1}}
        ])
        
        # Convert to dictionary for easy access in template
        resources_count = {category['_id']: category['count'] for category in categories}
        
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_educators,
            'pages': (total_educators + per_page - 1) // per_page
        }
        
        return render_template('educators.html',
                            educators=educators,
                            specializations=specializations,
                            resources_count=resources_count,
                            pagination=pagination)
        
    except PyMongoError as e:
        logger.error(f"Error loading educators: {str(e)}")
        flash('Error loading educators', 'danger')
        return redirect(url_for('index'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check admin credentials from database
        admin_user = users.find_one({'username': username, 'role': 'admin'})
        
        if admin_user and check_password_hash(admin_user['password'], password):
            user = User(admin_user)
            login_user(user)
            
            # Set session variables
            session['user_id'] = str(admin_user['_id'])
            session['username'] = admin_user['username']
            session['role'] = admin_user['role']
            session['is_admin'] = True
            
            flash('Logged in successfully as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
    
    return render_template('admin/login.html', form=form)

@app.route('/admin/logout')
@admin_required
def admin_logout():
    logout_user()
    session.pop('is_admin', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Calculate statistics
        total_users = users.count_documents({})
        total_educators = users.count_documents({'role': 'educator'})
        total_resources = resources.count_documents({})
        total_premium = resources.count_documents({'type': 'paid'})
        total_free = resources.count_documents({'type': 'free'})
        total_revenue = sum(p['amount'] for p in payments.find())

        stats = {
            'total_users': total_users,
            'total_educators': total_educators,
            'total_resources': total_resources,
            'total_premium': total_premium,
            'total_free': total_free,
            'total_revenue': total_revenue
        }

        return render_template('admin/dashboard.html', stats=stats)
    except PyMongoError as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('index'))
    
@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        skip = (page - 1) * per_page
        
        users_list = list(users.find().skip(skip).limit(per_page))
        total_users = users.count_documents({})
        
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_users,
            'pages': (total_users + per_page - 1) // per_page
        }
        
        return render_template('admin/users.html', 
                            users=users_list,
                            pagination=pagination)
    except PyMongoError as e:
        logger.error(f"Error loading users: {str(e)}")
        flash('Error loading users', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<user_id>')
@admin_required
def admin_view_user(user_id):
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
            
        # Get user's resources
        user_resources = list(resources.find({'educator_id': str(user['_id'])}))
        
        # Get user's payments if they're an educator
        earnings = 0
        if user['role'] == 'educator':
            earnings = payments.aggregate([
                {'$match': {'educator_id': str(user['_id'])}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
            ])
            earnings = list(earnings)
            earnings = earnings[0]['total'] if earnings else 0
        
        return render_template('admin/view_user.html',
                            user=user,
                            resources=user_resources,
                            earnings=earnings)
    except PyMongoError as e:
        logger.error(f"Error viewing user: {str(e)}")
        flash('Error viewing user', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/admin/user/<user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        form = AdminUserEditForm(obj=user)
        
        if form.validate_on_submit():
            update_data = {
                'name': form.name.data,
                'email': form.email.data,
                'role': form.role.data,
                'is_active': form.is_active.data,
                'bio': form.bio.data,
                'specialization': form.specialization.data
            }
            
            # Handle profile picture upload
            if form.profile_picture.data:
                picture = form.profile_picture.data
                filename = secure_filename(picture.filename)

                if filename != '' and allowed_file(filename):
                    # Delete old profile picture if it's not the default
                    old_avatar = user.get('avatar')
                    if old_avatar and not old_avatar.startswith('uploads/default-avatar'):
                        old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(old_avatar))
                        if os.path.exists(old_pic_path):
                            try:
                                os.remove(old_pic_path)
                            except Exception as e:
                                logger.error(f"Error deleting old profile picture: {str(e)}")

                    # Save new profile picture
                    new_filename = f"{user_id}_{filename}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    picture.save(save_path)

                    update_data['avatar'] = f"uploads/{new_filename}"
                else:
                    flash('Invalid file type for profile picture', 'danger')
                    return redirect(url_for('admin_edit_user', user_id=user_id))
            
            users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
            flash('User updated successfully', 'success')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        return render_template('admin/edit_user.html', form=form, user=user)
    
    except PyMongoError as e:
        logger.error(f"Error editing user: {str(e)}")
        flash('Error updating user', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/admin/educator/<educator_id>/earnings')
@admin_required
def admin_educator_earnings(educator_id):
    try:
        # Get educator info
        educator = users.find_one({'_id': ObjectId(educator_id), 'role': 'educator'})
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('admin_users'))

        # Get all payments to this educator
        payments_list = list(payments.find({'educator_id': educator_id}))

        # Get all resources by this educator
        educator_resources = list(resources.find({'educator_id': educator_id}))

        # Create a dictionary of resource details
        resources_dict = {str(r['_id']): r for r in educator_resources}

        # Calculate statistics
        total_earnings = sum(p['amount'] for p in payments_list)
        total_purchases = len(payments_list)

        # Get top purchased resources
        top_resources = list(resources.aggregate([
            {'$match': {'educator_id': educator_id}},
            {'$lookup': {
                'from': 'purchases',
                'localField': '_id',
                'foreignField': 'resource_id',
                'as': 'purchases'
            }},
            {'$addFields': {
                'purchase_count': {'$size': '$purchases'}
            }},
            {'$sort': {'purchase_count': -1}},
            {'$limit': 5}
        ]))

        # Get recent purchases
        recent_purchases = list(payments.aggregate([
            {'$match': {'educator_id': educator_id}},
            {'$sort': {'payment_date': -1}},
            {'$limit': 10},
            {'$lookup': {
                'from': 'users',
                'localField': 'user_id',
                'foreignField': '_id',
                'as': 'buyer'
            }},
            {'$unwind': '$buyer'},
            {'$lookup': {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }},
            {'$unwind': '$resource'},
            {'$project': {
                'amount': 1,
                'payment_date': 1,
                'buyer.username': 1,
                'buyer.name': 1,
                'resource.title': 1
            }}
        ]))

        return render_template(
            'admin/educator_earnings.html',
            educator=educator,
            payments=payments_list,
            resources=resources_dict,
            total_earnings=total_earnings,
            total_purchases=total_purchases,
            top_resources=top_resources,
            recent_purchases=recent_purchases
        )

    except PyMongoError as e:
        logger.error(f"Error loading educator earnings: {str(e)}")
        flash('Error loading payment details', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/educator/<educator_id>/export')
@admin_required
def export_educator_earnings(educator_id):
    try:
        # Verify educator exists
        educator = users.find_one({'_id': ObjectId(educator_id), 'role': 'educator'})
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('admin_users'))
            
        # Get all payments
        payments_list = list(payments.find({'educator_id': educator_id}))
        
        # Create CSV data
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Transaction ID', 'Date', 'Buyer ID', 'Buyer Username', 
            'Buyer Name', 'Resource ID', 'Resource Title', 'Amount'
        ])
        
        # Write rows
        for payment in payments_list:
            buyer = users.find_one({'_id': ObjectId(payment['user_id'])})
            resource = resources.find_one({'_id': ObjectId(payment['resource_id'])})
            
            writer.writerow([
                payment['transaction_id'],
                payment['payment_date'].isoformat(),
                payment['user_id'],
                buyer['username'] if buyer else 'N/A',
                buyer.get('name', '') if buyer else 'N/A',
                payment['resource_id'],
                resource['title'] if resource else 'Deleted Resource',
                payment['amount']
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = f'attachment; filename={educator["username"]}_earnings.csv'
        response.headers['Content-type'] = 'text/csv'
        return response
        
    except Exception as e:
        logger.error(f"Error exporting earnings: {str(e)}")
        flash('Error exporting earnings data', 'danger')
        return redirect(url_for('admin_educator_earnings', educator_id=educator_id))

@app.route('/admin/educator/<educator_id>/monthly')
@admin_required
def educator_monthly_earnings(educator_id):
    try:
        educator = users.find_one({'_id': ObjectId(educator_id), 'role': 'educator'})
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('admin_users'))
            
        # Get monthly earnings breakdown
        monthly_data = list(payments.aggregate([
            {'$match': {'educator_id': educator_id}},
            {'$group': {
                '_id': {
                    'year': {'$year': '$payment_date'},
                    'month': {'$month': '$payment_date'}
                },
                'total': {'$sum': '$amount'},
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id.year': 1, '_id.month': 1}}
        ]))
        
        # Format for chart
        labels = []
        earnings = []
        purchases = []
        
        for month in monthly_data:
            month_name = datetime(month['_id']['year'], month['_id']['month'], 1).strftime('%b %Y')
            labels.append(month_name)
            earnings.append(month['total'])
            purchases.append(month['count'])
        
        return render_template('admin/educator_monthly.html',
                            educator=educator,
                            labels=labels,
                            earnings=earnings,
                            purchases=purchases)
    except PyMongoError as e:
        logger.error(f"Error loading monthly earnings: {str(e)}")
        flash('Error loading monthly data', 'danger')
        return redirect(url_for('admin_educator_earnings', educator_id=educator_id))

@app.route('/admin/user/<user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    try:
        # Don't allow deleting yourself
        if str(current_user.id) == user_id:
            flash('You cannot delete your own account', 'danger')
            return redirect(url_for('admin_users'))
        
        result = users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count > 0:
            # Clean up related data
            resources.delete_many({'educator_id': user_id})
            chats.delete_many({'$or': [{'user_id': user_id}, {'educator_id': user_id}]})
            payments.delete_many({'user_id': user_id})
            
            flash('User deleted successfully', 'success')
        else:
            flash('User not found', 'danger')
    except PyMongoError as e:
        logger.error(f"Error deleting user: {str(e)}")
        flash('Error deleting user', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/resources', methods=['GET', 'POST'])
@admin_required
def admin_resources():
    form = ResourceSearchForm()  # Initialize the form here

    # Handle form submission if needed
    if form.validate_on_submit():
        # Process the form data (e.g., search query)
        pass

    # Pagination logic
    page = max(int(request.args.get('page', 1)), 1)
    per_page = 20
    skip = (page - 1) * per_page

    # Fetch resources and educators
    resources_list = list(resources.find().skip(skip).limit(per_page))
    total_resources = resources.count_documents({})
    educator_ids = [str(r['educator_id']) for r in resources_list]
    educators = {
        str(u['_id']): u['username']
        for u in users.find({'_id': {'$in': [ObjectId(id) for id in educator_ids]}})
    }

    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total_resources,
        'pages': (total_resources + per_page - 1) // per_page
    }

    return render_template(
        'admin/resources.html',
        form=form,  # Pass the form here
        resources=resources_list,
        educators=educators,
        pagination=pagination
    )


@app.route('/admin/resource/<resource_id>')
@admin_required
def admin_view_resource(resource_id):
    try:
        # Retrieve the resource
        resource = get_resource(resource_id)
        
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('admin_resources'))
        
        # Retrieve the educator and purchase count
        educator = users.find_one({'_id': ObjectId(resource['educator_id'])})
        purchases_count = purchases.count_documents({'resource_id': resource_id, 'status': 'completed'})
        
        # Pass the resource to the template
        return render_template('admin/view_resource.html',
                               resource=resource,
                               educator=educator,
                               purchases_count=purchases_count)
    except PyMongoError as e:
        logger.error(f"Error viewing resource {resource_id}: {str(e)}")
        flash('Error viewing resource', 'danger')
        return redirect(url_for('admin_resources'))

@app.route('/admin/resource/<resource_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_resource(resource_id):
    try:
        # Retrieve the resource
        resource = get_resource(resource_id)
        
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('admin_resources'))
        
        # Toggle the resource status (active/inactive)
        new_status = not resource.get('is_active', False)
        
        # Update the resource's status in the database
        resources.update_one(
            {'_id': ObjectId(resource_id)},
            {'$set': {'is_active': new_status}}
        )

        flash('Resource status updated successfully!', 'success')
        return redirect(url_for('admin_view_resource', resource_id=resource_id))

    except Exception as e:
        logger.error(f"Error toggling resource {resource_id}: {str(e)}")
        flash('Error toggling resource', 'danger')
        return redirect(url_for('admin_resources'))


@app.route('/admin/resource/<resource_id>/replace-file', methods=['POST'])
@admin_required
def admin_replace_file(resource_id):
    try:
        # Retrieve the resource by its ID
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('admin_resources'))
        
        # Handle file replacement logic
        if 'file' in request.files:
            new_file = request.files['file']
            # Replace or handle the new file here (e.g., save it, update database, etc.)
            filename = secure_filename(new_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            new_file.save(file_path)

            # Update the resource's file path or filename in the database
            resources.update_one(
                {'_id': ObjectId(resource_id)},
                {'$set': {'filename': filename}}
            )

            flash('Resource file replaced successfully', 'success')
            return redirect(url_for('admin_view_resource', resource_id=resource_id))
        else:
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_view_resource', resource_id=resource_id))
        
    except Exception as e:
        logger.error(f"Error replacing file for resource {resource_id}: {str(e)}")
        flash('Error replacing file', 'danger')
        return redirect(url_for('admin_resources'))

# Update the edit_resource route
@app.route('/admin/resource/<resource_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_resource(resource_id):
    try:
        resource = resources.find_one({'_id': ObjectId(resource_id)})
        if not resource:
            flash('Resource not found', 'danger')
            return redirect(url_for('admin_resources'))

        # Initialize form with resource data
        form = ResourceForm(obj=resource)
        
        # Set default values if not in resource
        if 'type' not in resource:
            form.type.data = 'free'
        if 'price' not in resource:
            form.price.data = 0.0
        if 'is_active' not in resource:
            form.is_active.data = True

        if form.validate_on_submit():
            update_data = {
                'title': form.title.data,
                'description': form.description.data,
                'category': form.category.data,
                'type': form.type.data,
                'price': float(form.price.data) if form.type.data == 'paid' else 0,
                'is_active': form.is_active.data,
                'updated_at': datetime.now(timezone.utc)
            }

            # Handle file upload
            if form.file.data:
                file_url = save_uploaded_file(form.file.data)
                if file_url:
                    update_data['file_url'] = file_url

            # Handle thumbnail upload
            if form.thumbnail.data:
                thumbnail_url = save_uploaded_file(form.thumbnail.data)
                if thumbnail_url:
                    update_data['thumbnail'] = thumbnail_url

            # Update resource
            resources.update_one(
                {'_id': ObjectId(resource_id)},
                {'$set': update_data}
            )

            flash('Resource updated successfully!', 'success')
            return redirect(url_for('admin_view_resource', resource_id=resource_id))

        return render_template('admin/edit_resource.html',
                            form=form,
                            resource=resource)

    except Exception as e:
        logger.error(f"Error editing resource: {str(e)}")
        flash('Error editing resource', 'danger')
        return redirect(url_for('admin_resources'))

@app.route('/admin/resource/<resource_id>/delete', methods=['POST'])
@admin_required
def admin_delete_resource(resource_id):
    try:
        result = resources.delete_one({'_id': ObjectId(resource_id)})
        if result.deleted_count > 0:
            # Clean up related purchases
            purchases.delete_many({'resource_id': resource_id})
            flash('Resource deleted successfully', 'success')
        else:
            flash('Resource not found', 'danger')
    except PyMongoError as e:
        logger.error(f"Error deleting resource: {str(e)}")
        flash('Error deleting resource', 'danger')
    return redirect(url_for('admin_resources'))

@app.route('/admin/resources/add', methods=['GET', 'POST'])
@admin_required
def admin_add_resource():
    form = ResourceForm()
    
    if form.validate_on_submit():
        new_resource = {
            'title': form.title.data,
            'description': form.description.data,
            'category': form.category.data,
            'type': form.type.data,
            'price': form.price.data,
            'is_active': form.is_active.data,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Handle file upload
        if form.file.data:
            filename = secure_filename(form.file.data.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.file.data.save(file_path)
            new_resource['filename'] = filename
        
        # Insert into database
        resources.insert_one(new_resource)
        flash('Resource added successfully!', 'success')
        return redirect(url_for('admin_resources'))
    
    return render_template('admin/add_resource.html', form=form)

@app.route('/admin/user/<user_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
            
        # Generate a reset token (you'll need to implement this)
        reset_token = secrets.token_urlsafe(32)
        
        # Store the token with expiration (1 hour)
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'reset_token': reset_token,
                'reset_token_expires': datetime.now(timezone.utc) + timedelta(hours=1)
            }}
        )
        
        # In a real app, you would send an email here with the reset link
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        
        flash(f'Password reset link generated: {reset_link}', 'success')
        return redirect(url_for('admin_edit_user', user_id=user_id))
        
    except Exception as e:
        logger.error(f"Error generating reset token: {str(e)}")
        flash('Error generating password reset', 'danger')
        return redirect(url_for('admin_edit_user', user_id=user_id))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    form = ResetPasswordForm()
    
    # Verify token
    user = users.find_one({
        'reset_token': token,
        'reset_token_expires': {'$gt': datetime.now(timezone.utc)}
    })
    
    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('login'))
        
    if form.validate_on_submit():
        # Update password
        users.update_one(
            {'_id': user['_id']},
            {'$set': {
                'password': generate_password_hash(form.password.data),
                'reset_token': None,
                'reset_token_expires': None
            }}
        )
        
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
        
    return render_template('auth/reset_password.html', form=form, token=token)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    form = AdminUserForm()  # Assuming you have this form class
    
    if form.validate_on_submit():
        new_user = {
            'name': form.name.data,
            'email': form.email.data,
            'password': generate_password_hash(form.password.data),
            'role': form.role.data,
            'is_active': form.is_active.data,
            'created_at': datetime.utcnow(),
            'bio': form.bio.data,
            'specialization': form.specialization.data
        }
        
        # Insert into database
        users.insert_one(new_user)
        flash('User added successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/add_user.html', form=form)

@app.route('/admin/payments')
@admin_required
def admin_payments():
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        skip = (page - 1) * per_page

        # Fetch paginated payments
        payments_list = list(payments.find().sort('payment_date', -1).skip(skip).limit(per_page))
        total_payments = payments.count_documents({})

        # Collect all related IDs
        user_ids = [p['user_id'] for p in payments_list]
        educator_ids = [p['educator_id'] for p in payments_list]
        resource_ids = [p['resource_id'] for p in payments_list]

        # Map user and educator IDs to usernames
        users_map = {
            str(u['_id']): u['username']
            for u in users.find({'_id': {'$in': [ObjectId(id) for id in user_ids]}})
        }

        educators_map = {
            str(u['_id']): u['username']
            for u in users.find({'_id': {'$in': [ObjectId(id) for id in educator_ids]}})
        }

        # Map resource IDs to titles
        resources_map = {
            str(r['_id']): r['title']
            for r in resources.find({'_id': {'$in': [ObjectId(id) for id in resource_ids]}})
        }

        # Create pagination data
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_payments,
            'pages': (total_payments + per_page - 1) // per_page
        }

        # Educator names list for labels
        educator_names = list(educators_map.values())

        # Aggregate earnings per educator (by username)
        educator_earnings_map = {}
        for p in payments_list:
            eid = str(p['educator_id'])
            name = educators_map.get(eid, 'Unknown')
            educator_earnings_map[name] = educator_earnings_map.get(name, 0) + p.get('amount', 0)

        return render_template(
            'admin/payments.html',
            payments=payments_list,
            users=users_map,
            educators=educators_map,
            resources=resources_map,
            pagination=pagination,
            educator_names=educator_names,
            educator_earnings=educator_earnings_map  # ✅ Safe to use with `|tojson` in template
        )

    except PyMongoError as e:
        logger.error(f"Error loading payments: {str(e)}")
        flash('Error loading payments', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear-cache', methods=['POST'])
@admin_required
def admin_clear_cache():
    # Your cache clearing logic here
    flash('Cache cleared successfully.', 'success')
    return redirect(url_for('admin_settings'))
@app.route('/admin/rebuild-indexes', methods=['POST'])
@admin_required
def admin_rebuild_indexes():
    """Rebuild database indexes (admin only)"""
    try:
        # Rebuild indexes for all collections
        collections = {
            'users': users,
            'resources': resources,
            'chats': chats,
            'payments': payments,
            'notifications': notifications,
            'purchases': purchases,
            'resource_comments': resource_comments,
            'ratings': ratings,
            'saved_resources': saved_resources,
            'meetings': meetings,
            'meeting_requests': meeting_requests
        }
        
        results = {}
        for name, collection in collections.items():
            try:
                collection.drop_indexes()
                collection.create_indexes()
                results[name] = 'success'
            except Exception as e:
                results[name] = str(e)
        
        flash('Indexes rebuilt successfully', 'success')
        return redirect(url_for('admin_settings'))
        
    except Exception as e:
        logger.error(f"Error rebuilding indexes: {str(e)}")
        flash('Error rebuilding indexes', 'danger')
        return redirect(url_for('admin_settings'))    

@app.route('/admin/backup', methods=['POST'])
@admin_required
def admin_backup_database():
    # Simulated backup logic
    backup_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_file = f"backup_{backup_time}.zip"
    
    # (You'd actually run database dump logic here)
    # For now just simulate
    print(f"[Backup] Simulated DB backup saved to: {backup_file}")

    flash(f"Backup created successfully: {backup_file}", "success")
    return redirect(url_for('admin_settings'))


@app.route('/admin/meetings')
@admin_required
def admin_meetings():
    """Admin view of meetings with filters and creator stats"""
    try:
        status = request.args.get('status', 'upcoming')

        query = {}
        now = datetime.now(timezone.utc)

        # Status filtering
        if status == 'upcoming':
            query['scheduled_time'] = {'$gt': now}
            query['status'] = {'$ne': 'cancelled'}
        elif status == 'past':
            query['scheduled_time'] = {'$lt': now}
            query['status'] = {'$ne': 'cancelled'}
        elif status == 'cancelled':
            query['status'] = 'cancelled'

        # Get meetings list
        meetings_list = list(meetings.find(query).sort('scheduled_time', -1))

        # Get educator usernames
        educator_ids = list({m['educator_id'] for m in meetings_list if 'educator_id' in m})
        educators = {
            str(u['_id']): u.get('name', u['username'])
            for u in users.find({'_id': {'$in': [ObjectId(eid) for eid in educator_ids]}})
            if u.get('username')  # Filter out educators with no username
        }

        # Count how many meetings were created by each user
        creator_stats = list(meetings.aggregate([{
            "$group": {
                "_id": "$educator_id",
                "count": {"$sum": 1}
            }
        }]))

        # Prepare stats to send to template
        meeting_creators = [{
            'user_id': str(stat['_id']),
            'username': educators.get(str(stat['_id']), 'Unknown'),
            'count': stat['count']
        } for stat in creator_stats]

        # Calculate host counts
        host_counts = {}
        for meeting in meetings_list:
            host_id = meeting.get('educator_id')
            if host_id:
                host_counts[host_id] = host_counts.get(host_id, 0) + 1

        # Prepare the labels for the chart (host names)
        host_names = [educators.get(str(host_id), 'Unknown') for host_id in host_counts.keys()]

        # Clean data
        host_names = [name for name in host_names if name]
        host_counts = {k: v for k, v in host_counts.items() if v}

        return render_template(
            'admin/meetings.html',
            meetings=meetings_list,
            educators=educators,
            current_status=status,
            meeting_creators=meeting_creators,
            host_names=host_names,
            host_counts=host_counts
        )

    except PyMongoError as e:
        logger.error(f"Error loading meetings: {str(e)}")
        flash('Error loading meetings', 'danger')
        return redirect(url_for('admin_dashboard'))



@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    try:
        settings_collection = db.settings
        current_settings = settings_collection.find_one({'_id': 'global_settings'}) or {}

        form = SettingsForm(data=current_settings)

        if form.validate_on_submit():
            new_settings = {
                'site_name': form.site_name.data,
                'site_description': form.site_description.data,
                'enable_registration': form.enable_registration.data,
                'default_user_role': form.default_user_role.data,
                'resource_approval_required': form.resource_approval_required.data,
                'max_upload_size': form.max_upload_size.data
            }

            settings_collection.update_one(
                {'_id': 'global_settings'},
                {'$set': new_settings},
                upsert=True
            )

            flash('Settings updated successfully', 'success')
            return redirect(url_for('admin_settings'))

        # Add system information to the template context
        import platform
        import flask
        import time
        
        storage_usage = calculate_storage_usage()
        
        return render_template('admin/settings.html', 
                            form=form, 
                            settings=current_settings,
                            storage_usage=storage_usage,
                            server_info=platform.platform(),
                            python_version=platform.python_version(),
                            flask_version=flask.__version__,
                            uptime=time.strftime("%H:%M:%S", time.gmtime(time.time() - app.start_time)))

    except PyMongoError as e:
        logger.error(f"Error loading/saving settings: {str(e)}")
        flash('Error processing settings', 'danger')
        return redirect(url_for('admin_dashboard'))
# Chat routes
@app.route('/chat/<educator_id>')
@login_required
def chat(educator_id):
    """Start or continue a chat conversation with an educator"""
    try:
        # Verify the educator exists
        educator = users.find_one({
            '_id': ObjectId(educator_id),
            'role': 'educator'
        })
        if not educator:
            flash('Educator not found', 'danger')
            return redirect(url_for('index'))
        
        # Check if a chat already exists between these users
        existing_chat = chats.find_one({
            '$or': [
                {'user_id': current_user.id, 'educator_id': educator_id},
                {'user_id': educator_id, 'educator_id': current_user.id}
            ]
        })
        
        if existing_chat:
            chat_id = str(existing_chat['_id'])
            return redirect(url_for('view_chat', chat_id=chat_id))
        
        # Create a new chat
        chat_data = {
            'user_id': current_user.id,
            'educator_id': educator_id,
            'created_at': datetime.now(timezone.utc),
            'messages': [],
            'user_unread': 0,
            'educator_unread': 0
        }
        chat_id = str(chats.insert_one(chat_data).inserted_id)
        return redirect(url_for('view_chat', chat_id=chat_id))
    
    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error starting chat: {str(e)}")
        flash('Error starting chat conversation', 'danger')
        return redirect(url_for('index'))

@app.route('/chat/conversation/<chat_id>')
@login_required
def view_chat(chat_id):
    """View a chat conversation"""
    try:
        chat = chats.find_one({'_id': ObjectId(chat_id)})
        if not chat:
            flash('Chat not found', 'danger')
            return redirect(url_for('index'))
        
        # Verify the current user is part of this chat
        if current_user.id not in [chat['user_id'], chat['educator_id']]:
            flash('You are not authorized to view this chat', 'danger')
            return redirect(url_for('index'))
        
        # Mark messages as read for the current user
        update_field = 'user_unread' if current_user.id == chat['user_id'] else 'educator_unread'
        chats.update_one(
            {'_id': ObjectId(chat_id)},
            {'$set': {update_field: 0}}
        )
        
        # Get the other participant's details
        other_user_id = chat['educator_id'] if current_user.id == chat['user_id'] else chat['user_id']
        other_user = users.find_one({'_id': ObjectId(other_user_id)})
        
        return render_template('chat.html',
                            chat=chat,
                            other_user=other_user,
                            current_user_id=current_user.id)
    
    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error viewing chat: {str(e)}")
        flash('Error loading chat', 'danger')
        return redirect(url_for('index'))
        
@app.route('/api/chat/<chat_id>/messages')
@login_required
def get_chat_messages(chat_id):
    """Get messages for a chat (API endpoint)"""
    try:
        chat = chats.find_one({'_id': ObjectId(chat_id)})
        if not chat or current_user.id not in [chat['user_id'], chat['educator_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Safely get messages with default values for missing fields
        messages = []
        for m in chat.get('messages', []):
            messages.append({
                'id': str(m.get('_id', '')),
                'sender_id': m.get('sender_id', ''),
                'content': m.get('content', '[Message not available]'),
                'timestamp': m.get('timestamp', datetime.now(timezone.utc)).isoformat(),
                'read': m.get('read', False)
            })
            
        
        return jsonify(messages)
    
    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error getting chat messages: {str(e)}")
        return jsonify({'error': 'Database error'}), 500   

@app.route('/api/chat/<chat_id>/send', methods=['POST'])
@login_required
def send_chat_message(chat_id):
    """Send a message in a chat (API endpoint)"""
    try:
        data = request.get_json()
        message_content = data.get('message', '').strip()

        if not message_content:
            return jsonify({'error': 'Message cannot be empty'}), 400

        chat = chats.find_one({'_id': ObjectId(chat_id)})
        if not chat or current_user.id not in [chat['user_id'], chat['educator_id']]:
            return jsonify({'error': 'Unauthorized'}), 403

        # Create and sanitize new message
        new_message = {
            '_id': ObjectId(),
            'sender_id': current_user.id,
            'content': sanitize_message_content(message_content),
            'timestamp': datetime.now(timezone.utc),
            'read': False
        }

        # Update chat document
        chats.update_one(
            {'_id': ObjectId(chat_id)},
            {
                '$push': {'messages': new_message},
                '$inc': {
                    'user_unread': 1 if current_user.id == chat['educator_id'] else 0,
                    'educator_unread': 1 if current_user.id == chat['user_id'] else 0
                },
                '$set': {'last_updated': datetime.now(timezone.utc)}
            }
        )

        # Emit to Socket.IO rooms
        try:
            recipient_id = chat['educator_id'] if current_user.id == chat['user_id'] else chat['user_id']

            # Emit new message (for live chat UI updates)
            socketio.emit('new_message', {
                'chat_id': chat_id,
                'sender_id': current_user.id,
                'content': new_message['content'],
                'timestamp': new_message['timestamp'].isoformat()
            }, room=f"user_{recipient_id}")

            # Emit separate notification (for alerts, badge counters, etc.)
            socketio.emit('new_message_notification', {
                'recipient_id': recipient_id,
                'chat_id': chat_id,
                'sender_id': current_user.id,
                'sender_name': current_user.username,
                'message': message_content[:50] + '...' if len(message_content) > 50 else message_content
            }, room=f"user_{recipient_id}")

        except Exception as e:
            logger.warning(f"SocketIO emit failed: {str(e)}")

        return jsonify({
            'success': True,
            'message': {
                'id': str(new_message['_id']),
                'sender_id': new_message['sender_id'],
                'content': new_message['content'],
                'timestamp': new_message['timestamp'].isoformat(),
                'read': new_message['read']
            }
        })

    except (PyMongoError, InvalidId) as e:
        logger.error(f"Error sending chat message: {str(e)}")
        return jsonify({'error': 'Database error'}), 500


def get_chat_conversations(user_id):
    """Get all chat conversations for a user with last message and unread count"""
    try:
        # Get conversations where user is either the student or educator
        conversations = list(chats.aggregate([
            {'$match': {
                '$or': [
                    {'user_id': user_id},
                    {'educator_id': user_id}
                ]
            }},
            {'$lookup': {
                'from': 'users',
                'let': {'other_user_id': {
                    '$cond': [
                        {'$eq': ['$user_id', user_id]},
                        '$educator_id',
                        '$user_id'
                    ]
                }},
                'pipeline': [
                    {'$match': {
                        '$expr': {'$eq': ['$_id', {'$toObjectId': '$$other_user_id'}]}
                    }},
                    {'$project': {
                        'username': 1,
                        'name': 1,
                        'avatar': 1,
                        'role': 1
                    }}
                ],
                'as': 'other_user'
            }},
            {'$unwind': '$other_user'},
            {'$project': {
                'chat_id': {'$toString': '$_id'},
                'other_user': 1,
                'last_message': {'$arrayElemAt': ['$messages', -1]},
                'unread_count': {
                    '$cond': [
                        {'$eq': ['$user_id', user_id]},
                        '$user_unread',
                        '$educator_unread'
                    ]
                },
                'updated_at': {
                    '$cond': [
                        {'$gt': [{'$size': '$messages'}, 0]},
                        {'$arrayElemAt': ['$messages.timestamp', -1]},
                        '$created_at'
                    ]
                }
            }},
            {'$sort': {'updated_at': -1}}
        ]))

        # Format the conversations consistently
        formatted = []
        for conv in conversations:
            # Handle case where there are no messages yet
            last_msg = conv.get('last_message', {})
            
            formatted.append({
                'chat_id': conv['chat_id'],
                'name': conv['other_user'].get('name', conv['other_user']['username']),
                'username': conv['other_user']['username'],
                'avatar': conv['other_user'].get('avatar', 
                    DEFAULT_AVATAR if conv['other_user'].get('role') == 'educator' else DEFAULT_AVATAR_STUDENT),
                'unread_count': conv.get('unread_count', 0),
                'last_message': {
                    'content': last_msg.get('content', 'No messages yet'),
                    'timestamp': last_msg.get('timestamp', conv['updated_at']),
                    'sender_id': last_msg.get('sender_id', '')
                }
            })
        
        return formatted

    except Exception as e:
        logger.error(f"Error getting chat conversations: {str(e)}")
        return []

@app.route('/api/chats/conversations')
@login_required
def get_user_conversations():
    """Get all conversations for the current user"""
    try:
        conversations = get_chat_conversations(current_user.id)
        return jsonify([{
            'chat_id': conv['chat_id'],
            'name': conv['name'],
            'username': conv['username'],
            'avatar': conv['avatar'],
            'unread_count': conv['unread_count'],
            'last_message': {
                'content': conv['last_message']['content'],
                'timestamp': conv['last_message']['timestamp'].isoformat() if isinstance(conv['last_message']['timestamp'], datetime) else conv['last_message']['timestamp'],
                'sender_id': conv['last_message']['sender_id']
            }
        } for conv in conversations])
    except Exception as e:
        logger.error(f"Error getting conversations: {str(e)}")
        return jsonify({'error': 'Error getting conversations'}), 500

@app.route('/messages')
@login_required
def chat_list():
    """Render a full-page message inbox (not JSON)"""
    conversations = get_chat_conversations(current_user.id)
    return render_template("chat_list.html", conversations=conversations)


@app.route('/api/profile/purchased-resources')
@login_required
def get_purchased_resources():
    try:
        # Get purchased resources for current user
        purchased_resources = list(purchases.aggregate([
            {'$match': {
                'user_id': ObjectId(current_user.id),
                'status': 'completed'
            }},
            {'$lookup': {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }},
            {'$unwind': '$resource'},
            {'$lookup': {
                'from': 'users',
                'localField': 'resource.educator_id',
                'foreignField': '_id',
                'as': 'educator'
            }},
            {'$unwind': '$educator'},
            {'$sort': {'purchase_date': -1}},
            {'$project': {
                '_id': {'$toString': '$resource._id'},
                'title': '$resource.title',
                'description': '$resource.description',
                'category': '$resource.category',
                'type': '$resource.type',
                'price': '$resource.price',
                'thumbnail': {
                    '$cond': {
                        'if': {'$and': [
                            {'$ne': ['$resource.thumbnail', None]},
                            {'$ne': ['$resource.thumbnail', '']}
                        ]},
                        'then': '$resource.thumbnail',
                        'else': None
                    }
                },
                'downloads': '$resource.downloads',
                'purchase_date': {
                    '$dateToString': {
                        'format': '%Y-%m-%d',
                        'date': '$purchase_date'
                    }
                },
                'educator_name': '$educator.name',
                'educator_username': '$educator.username'
            }}
        ]))

        return jsonify({
            'success': True,
            'resources': purchased_resources
        })
    except Exception as e:
        logger.error(f"Error getting purchased resources: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error loading purchased resources'
        }), 500

@app.route('/api/chats/unread_count')
@login_required
def get_unread_count():
    try:
        count = 0
        conversations = get_chat_conversations(current_user.id)
        for conv in conversations:
            count += conv.get('unread_count', 0)
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        logger.error(f"Error getting unread count: {str(e)}")
        return jsonify({'success': False, 'count': 0})        


@app.route('/api/chats/start', methods=['POST'])
@login_required
def start_chat():
    """Start a new chat conversation"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'error': 'Recipient ID required'}), 400
        
        # Check if recipient exists
        recipient = users.find_one({'_id': ObjectId(recipient_id)})
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Check if conversation already exists
        existing_chat = chats.find_one({
            'participants': {
                '$all': [current_user.id, recipient_id],
                '$size': 2
            }
        })
        
        if existing_chat:
            return jsonify({
                'success': True,
                'chat_id': str(existing_chat['_id']),
                'exists': True
            })
        
        # Create new chat
        chat_data = {
            'participants': [current_user.id, recipient_id],
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc),
            'messages': [],
            'unread_counts': {
                current_user.id: 0,
                recipient_id: 0
            }
        }
        
        result = chats.insert_one(chat_data)
        chat_id = str(result.inserted_id)
        
        # Format the new conversation for response
        new_conversation = create_new_conversation_entry(recipient_id, chat_id, current_user)
        
        return jsonify({
            'success': True,
            'chat_id': chat_id,
            'conversation': new_conversation,
            'exists': False
        })
        
    except Exception as e:
        logger.error(f"Error starting chat: {str(e)}")
        return jsonify({'error': 'Error starting chat'}), 500

@app.route('/notifications')
@login_required
def user_notifications():
    """View user notifications"""
    try:
        notifications = list(db.notifications.find(
            {'recipient_id': current_user.id}
        ).sort('created_at', -1).limit(50))

        # Mark notifications as read when viewing them
        db.notifications.update_many(
            {'recipient_id': current_user.id, 'read': False},
            {'$set': {'read': True}}
        )

        return render_template('notifications.html', notifications=notifications)
    except PyMongoError as e:
        logger.error(f"Error loading notifications: {str(e)}")
        flash('Error loading notifications', 'danger')
        return redirect(url_for('index'))

@app.route('/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        result = db.notifications.update_one(
            {'_id': ObjectId(notification_id), 'recipient_id': current_user.id},
            {'$set': {'read': True}}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Notification not found'}), 404
    except PyMongoError as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        db.notifications.update_many(
            {'recipient_id': current_user.id, 'read': False},
            {'$set': {'read': True}}
        )
        return jsonify({'success': True})
    except PyMongoError as e:
        logger.error(f"Error marking all notifications as read: {str(e)}")
        return jsonify({'success': False, 'message': 'Database error'}), 500

# Updated Socket.IO event handlers with integrated meeting logic
sid_to_meeting = {}  # Global dictionary to track sid to meeting_id

#
@socketio.on('connect')
def handle_connect(auth):
    sid = request.sid  # explicitly get the current Socket.IO session ID
    if current_user.is_authenticated:
        user_room = f"user_{current_user.id}"
        join_room(user_room, sid=sid)

        if current_user.role == 'educator':
            educator_room = f"educator_{current_user.id}"
            join_room(educator_room, sid=sid)

        logger.info(f"User {current_user.username} connected and joined rooms: {user_room}" +
                    (f", {educator_room}" if current_user.role == 'educator' else ""))
    else:
        logger.warning("Unauthenticated user tried to connect")


@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    if chat_id and current_user.is_authenticated:
        chat = chats.find_one({
            '_id': ObjectId(chat_id),
            '$or': [
                {'user_id': current_user.id},
                {'educator_id': current_user.id}
            ]
        })
        if chat:
            join_room(f"chat_{chat_id}")
            logger.info(f"User {current_user.id} joined chat {chat_id}")

@socketio.on('new_message')
def handle_new_message(data):
    chat_id = data.get('chat_id')
    if not chat_id:
        return
    
    # Get the chat to identify participants
    chat = chats.find_one({'_id': ObjectId(chat_id)})
    if not chat:
        return
    
    # Emit to both participants to update their UI
    emit('refresh_messages', {'chat_id': chat_id}, room=f"user_{chat['user_id']}")
    emit('refresh_messages', {'chat_id': chat_id}, room=f"user_{chat['educator_id']}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    if current_user.is_authenticated:
        join_room(f"user_{current_user.id}")
        logger.info(f"User {current_user.username} joined their room")

@socketio.on('new_message_notification')
def handle_new_message_notification(data):
    recipient_id = data.get('recipient_id')
    if recipient_id:
        emit('new_message', {
            'chat_id': data.get('chat_id'),
            'sender_id': data.get('sender_id'),
            'sender_name': data.get('sender_name'),
            'message': data.get('message')
        }, room=f"user_{recipient_id}")    

@socketio.on('mark_read')
def handle_mark_read(data):
    chat_id = data.get('chat_id')
    message_id = data.get('message_id')
    if not chat_id or not message_id or not current_user.is_authenticated:
        return
    try:
        chats.update_one(
            {'_id': ObjectId(chat_id), 'messages._id': ObjectId(message_id)},
            {'$set': {'messages.$.read': True}}
        )
        chat = chats.find_one({'_id': ObjectId(chat_id)})
        if chat:
            if current_user.id == chat['user_id']:
                chats.update_one({'_id': ObjectId(chat_id)}, {'$set': {'user_unread': 0}})
            elif current_user.id == chat['educator_id']:
                chats.update_one({'_id': ObjectId(chat_id)}, {'$set': {'educator_unread': 0}})
    except Exception as e:
        logger.error(f"Error marking message as read: {str(e)}")



@socketio.on('join_meeting_room')
def handle_join_meeting_room(data):
    meeting_id = data.get('meeting_id')
    user_id = data.get('user_id')
    username = data.get('username')
    role = data.get('role')
    
    if not all([meeting_id, user_id, username, role]):
        return
    
    # Verify meeting exists and is active
    meeting = meetings.find_one({'meeting_id': meeting_id, 'is_active': True})
    if not meeting:
        emit('meeting_not_found', {'message': 'Meeting not found or has ended'})
        return
    
    # Join the meeting room
    join_room(f"meeting_{meeting_id}")
    sid_to_meeting[request.sid] = meeting_id
    
    # Notify others about the new participant
    participant_data = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    emit('participant_joined', participant_data, room=f"meeting_{meeting_id}")
    
    # Update meeting participants list
    if user_id not in meeting.get('participants', []):
        meetings.update_one(
            {'meeting_id': meeting_id},
            {'$addToSet': {'participants': user_id}}
        )

@socketio.on('leave_meeting_room')
def handle_leave_meeting_room(data):
    meeting_id = data.get('meeting_id')
    user_id = data.get('user_id')
    username = data.get('username')
    
    if meeting_id and user_id and username:
        leave_room(f"meeting_{meeting_id}")
        
        # Notify others about participant leaving
        emit('participant_left', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"meeting_{meeting_id}")
        
        # Remove from sid_to_meeting mapping
        sid_to_meeting.pop(request.sid, None)

@socketio.on('meeting_message')
def handle_meeting_message(data):
    meeting_id = data.get('meeting_id')
    message = data.get('message')
    csrf_token = data.get('csrf_token')
    
    if not all([meeting_id, message, csrf_token]):
        return
    
    # Verify CSRF token
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return
    
    if current_user.is_authenticated:
        emit('meeting_message', {
            'user_id': current_user.id,
            'username': current_user.username,
            'message': sanitize_message_content(message),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"meeting_{meeting_id}")

@socketio.on('end_meeting')
def handle_end_meeting(data):
    meeting_id = data.get('meeting_id')
    csrf_token = data.get('csrf_token')
    
    if not all([meeting_id, csrf_token]):
        return
    
    # Verify CSRF token
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return
    
    # Verify user is the host
    meeting = meetings.find_one({
        'meeting_id': meeting_id,
        'host_id': current_user.id
    })
    if not meeting:
        return
    
    # Update meeting status
    meetings.update_one(
        {'meeting_id': meeting_id},
        {'$set': {
            'status': 'ended',
            'ended_at': datetime.now(timezone.utc),
            'is_active': False
        }}
    )
    
    # Notify all participants
    emit('meeting_ended', {
        'message': 'Host has ended the meeting',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=f"meeting_{meeting_id}")

@socketio.on('lock_meeting')
def handle_lock_meeting(data):
    meeting_id = data.get('meeting_id')
    locked = data.get('locked')
    csrf_token = data.get('csrf_token')
    
    if not all([meeting_id, locked is not None, csrf_token]):
        return
    
    # Verify CSRF token
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return
    
    # Verify user is the host
    meeting = meetings.find_one({
        'meeting_id': meeting_id,
        'host_id': current_user.id
    })
    if not meeting:
        return
    
    # Update meeting locked status
    meetings.update_one(
        {'meeting_id': meeting_id},
        {'$set': {'is_locked': locked}}
    )
    
    # Notify all participants
    emit('meeting_locked', {
        'locked': locked,
        'message': 'Meeting has been locked by the host' if locked else 'Meeting has been unlocked'
    }, room=f"meeting_{meeting_id}")

@socketio.on('remove_participant')
def handle_remove_participant(data):
    meeting_id = data.get('meeting_id')
    user_id = data.get('user_id')
    csrf_token = data.get('csrf_token')
    
    if not all([meeting_id, user_id, csrf_token]):
        return
    
    # Verify CSRF token
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return
    
    # Verify user is the host
    meeting = meetings.find_one({
        'meeting_id': meeting_id,
        'host_id': current_user.id
    })
    if not meeting:
        return
    
    # Notify the participant being removed
    emit('participant_removed', {
        'user_id': user_id,
        'message': 'You have been removed from the meeting by the host',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=f"user_{user_id}")
    
    # Notify others in the meeting
    emit('participant_removed', {
        'user_id': user_id,
        'message': f'{user_id} has been removed by the host',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=f"meeting_{meeting_id}")

@socketio.on('mute_all')
def handle_mute_all(data):
    meeting_id = data.get('meeting_id')
    csrf_token = data.get('csrf_token')
    
    if not all([meeting_id, csrf_token]):
        return
    
    # Verify CSRF token
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return
    
    # Verify user is the host
    meeting = meetings.find_one({
        'meeting_id': meeting_id,
        'host_id': current_user.id
    })
    if not meeting:
        return
    
    # Notify all participants to mute
    emit('participant_muted', {
        'message': 'Host has muted all participants',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=f"meeting_{meeting_id}")

@socketio.on('disconnect')
def handle_disconnect(reason):
    try:
        logger.info(f"User disconnected: {reason}")  # Log the reason

        # Handle user disconnection
        meeting_id = sid_to_meeting.get(request.sid)
        if meeting_id and current_user.is_authenticated:
            # Notify others about participant leaving
            emit('participant_left', {
                'user_id': current_user.id,
                'username': current_user.username,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room=f"meeting_{meeting_id}")

            # Remove from sid_to_meeting mapping
            sid_to_meeting.pop(request.sid, None)
    except Exception as e:
        logger.error(f"Error in disconnect handler: {str(e)}")

@socketio.on_error_default
def default_error_handler(e):
    logger.error(f"SocketIO error: {str(e)}", exc_info=True)
    try:
        emit('error', {'message': 'An error occurred'})
    except:
        pass  # Don't try to emit if the connection is already dead


@app.route('/shutdown', methods=['POST'])
@admin_required
def shutdown():
    shutdown_server()
    return 'Server shutting down...'
# Shutdown handler
def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    
    def is_port_in_use(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    if is_port_in_use(port):
        print(f"Port {port} is already in use. Please close other applications using this port.")
        sys.exit(1)
    
    print(f"Starting server on port {port}")
    print(f"Access the application at: http://localhost:{port}")
    
    try:
        # Create application context before running
        with app.app_context():
            socketio.run(
                app,
                host='0.0.0.0',
                port=port,
                debug=True,
                use_reloader=True
            )
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import uuid
import os
import re
import bleach
import secrets
import math
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text
import mimetypes
import jwt

load_dotenv()

app = Flask(__name__)

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'zivre-super-secret-key-change-in-production-2024')
JWT_EXPIRY_HOURS = 24
# Referral System Configuration
WITHDRAWAL_THRESHOLD_GHS = 20
COMMISSION_DECAY_FACTOR = 0.5
BASE_COMMISSION_RATE = 0.20
MAX_REFERRAL_DEPTH = 100

# Request Status Constants
REQUEST_STATUS_CANCELLED_BY_CUSTOMER = 'cancelled_by_customer'
REQUEST_STATUS_REJECTED_BY_ADMIN = 'rejected_by_admin'
REQUEST_STATUS_DECLINED_BY_PROVIDER = 'declined_by_provider'

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp3', 'm4a', 'wav', 'mp4', 'pdf', 'doc', 'docx', 'txt', 'xlsx', 'pptx', 'csv', 'zip', 'rar'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    if 'neon.tech' in DATABASE_URL and 'sslmode' not in DATABASE_URL:
        if '?' in DATABASE_URL:
            app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL + '&sslmode=require'
        else:
            app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL + '?sslmode=require'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "zivre.db")}'
           
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure SocketIO with proper CORS
socketio = SocketIO(app, 
    cors_allowed_origins="*", 
    ping_timeout=120,
    ping_interval=60,
    async_mode='gevent',
    allow_upgrades=True,
    http_compression=False
)

# Configure CORS properly
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://zivre-frontend.vercel.app').split(',')

CORS(app, 
     supports_credentials=True, 
     origins=ALLOWED_ORIGINS,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Set-Cookie"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

limiter = Limiter(get_remote_address, app=app, default_limits=["1000000 per day", "100000 per hour", "10000 per minute"], storage_uri=os.environ.get('RATELIMIT_STORAGE_URL', 'memory://'))

# ==================== JWT DECORATORS ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token missing or invalid'}), 401
        
        token = token.split(' ')[1]
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
            if not current_user.is_active:
                return jsonify({'error': 'Account suspended'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.current_user = current_user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if request.current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin == 'https://zivre-frontend.vercel.app':
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    rating = db.Column(db.Float, default=0)
    total_jobs = db.Column(db.Integer, default=0)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_expiry = db.Column(db.DateTime, nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    is_online_manual = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    avatar = db.Column(db.String(500), nullable=True)
    service_specialization_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    
    # ========== ADD THESE REFERRAL COLUMNS ==========
    referrer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    referral_code = db.Column(db.String(32), unique=True, nullable=True)
    is_referral_active = db.Column(db.Boolean, default=False)  # Renamed from is_active to avoid conflict
    commission_balance = db.Column(db.Float, default=0)
    total_earned = db.Column(db.Float, default=0)
    position = db.Column(db.String(10), nullable=True)  # left, center, right
    # ===============================================
    # ========== ADD THESE VERIFICATION FIELDS ==========
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    verification_token_expiry = db.Column(db.DateTime, nullable=True)
    
    service_specialization = db.relationship('Service', foreign_keys=[service_specialization_id])


class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    total_price = db.Column(db.Float, nullable=False, default=0)
    provider_payout = db.Column(db.Float, nullable=False, default=0)
    admin_fee = db.Column(db.Float, nullable=False, default=0)
    site_fee = db.Column(db.Float, nullable=False, default=0)
    icon = db.Column(db.String(10), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Referral columns
    admin_share_percent = db.Column(db.Float, default=10.0)
    website_share_percent = db.Column(db.Float, default=10.0)
    provider_share_percent = db.Column(db.Float, default=80.0)
    referral_pool_percent = db.Column(db.Float, default=10.0)
    referral_pool_amount = db.Column(db.Float, default=0)


class Quote(db.Model):
    __tablename__ = 'quotes'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    provider_payout = db.Column(db.Float, nullable=False, default=0)
    admin_fee = db.Column(db.Float, nullable=False, default=0)
    site_fee = db.Column(db.Float, nullable=False, default=0)
    status = db.Column(db.String(30), default='pending_approval', index=True)
    location_address = db.Column(db.String(200), nullable=False, default='')
    location_city = db.Column(db.String(100), nullable=False, default='')
    location_region = db.Column(db.String(100), nullable=False, default='')
    location_landmark = db.Column(db.String(200), nullable=True)
    customer_phone = db.Column(db.String(20), nullable=False, default='')
    provider_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    rating = db.Column(db.Integer, nullable=True)
    customer_confirmed = db.Column(db.Boolean, default=False)
    provider_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    assigned_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    declined_by = db.Column(db.Integer, nullable=True)
    
    # ========== ADD THESE REFERRAL COLUMNS ==========
    referral_pool_amount = db.Column(db.Float, default=0)
    total_commissions_paid = db.Column(db.Float, default=0)
    owner_net = db.Column(db.Float, default=0)
    admin_share_percent_snapshot = db.Column(db.Float, default=10.0)
    website_share_percent_snapshot = db.Column(db.Float, default=10.0)
    provider_share_percent_snapshot = db.Column(db.Float, default=80.0)
    commissions_processed = db.Column(db.Boolean, default=False)
    referral_pool_percent_snapshot = db.Column(db.Float, default=10.0)  # <-- NEW
    
    user = db.relationship('User', foreign_keys=[user_id])
    service = db.relationship('Service')
    provider = db.relationship('User', foreign_keys=[provider_id])
    

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50), default='info')
    link = db.Column(db.String(200), nullable=True)
    read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    subject = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=False)
    attachment_path = db.Column(db.String(500), nullable=True)
    attachment_type = db.Column(db.String(50), nullable=True)
    attachment_name = db.Column(db.String(200), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id', ondelete='SET NULL'), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    is_delivered = db.Column(db.Boolean, default=False)
    is_deleted_for_sender = db.Column(db.Boolean, default=False)
    is_deleted_for_receiver = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime, nullable=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=True)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    user_name = db.Column(db.String(100), nullable=False)
    user_role = db.Column(db.String(20), default='customer')
    user_avatar = db.Column(db.String(10), nullable=True)
    rating = db.Column(db.Float, default=5)
    comment = db.Column(db.Text, nullable=False)
    is_approved = db.Column(db.Boolean, default=True)
    helpful_count = db.Column(db.Integer, default=0)
    not_helpful_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', foreign_keys=[user_id])

class CommentReply(db.Model):
    __tablename__ = 'comment_replies'
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    user_role = db.Column(db.String(20), default='customer')
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    comment = db.relationship('Comment', foreign_keys=[comment_id])
    user = db.relationship('User', foreign_keys=[user_id])

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PercentageSetting(db.Model):
    __tablename__ = 'percentage_settings'
    id = db.Column(db.Integer, primary_key=True)
    provider_percent = db.Column(db.Float, default=60.0, nullable=False)
    admin_percent = db.Column(db.Float, default=20.0, nullable=False)
    site_fee_percent = db.Column(db.Float, default=10.0, nullable=False)
    referral_pool_percent = db.Column(db.Float, default=10.0, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def get_total(self):
        return self.provider_percent + self.admin_percent + self.site_fee_percent + self.referral_pool_percent
    
    def is_valid(self):
        total = self.get_total()
        return abs(total - 100.0) < 0.01
# ==================== Referal models====================
class Commission(db.Model):
    __tablename__ = 'commissions'
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('service_requests.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    level = db.Column(db.Integer)
    amount = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    booking = db.relationship('ServiceRequest', foreign_keys=[booking_id])
    user = db.relationship('User', foreign_keys=[user_id])

class WithdrawalRequest(db.Model):
    __tablename__ = 'withdrawal_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Float, default=0)
    payment_method = db.Column(db.String(20))
    account_details = db.Column(db.String(500))
    status = db.Column(db.String(20), default='pending')
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_processed_at = db.Column(db.DateTime, nullable=True)
    user_confirmed_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.String(500))
    
    user = db.relationship('User', foreign_keys=[user_id])
# ==================== HELPER FUNCTIONS ====================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    image_exts = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
    audio_exts = {'mp3', 'm4a', 'wav', 'ogg', 'flac'}
    video_exts = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
    document_exts = {'pdf', 'doc', 'docx', 'txt', 'xlsx', 'pptx', 'csv'}
    
    if ext in image_exts:
        return 'image'
    elif ext in audio_exts:
        return 'audio'
    elif ext in video_exts:
        return 'video'
    elif ext in document_exts:
        return 'document'
    return 'file'

def create_notification(user_id, message, type='info', link=None):
    try:
        notification = Notification(user_id=user_id, message=message, type=type, link=link)
        db.session.add(notification)
        db.session.commit()
        
        try:
            socketio.emit('new_notification', {
                'user_id': user_id,
                'message': message,
                'type': type,
                'link': link
            }, room=f"user_{user_id}")
        except Exception as e:
            print(f"WebSocket emit error (non-critical): {e}")
        
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error creating notification: {str(e)}")
        return False

def delete_all_notifications(user_id):
    try:
        deleted_count = Notification.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        return deleted_count
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting all notifications: {str(e)}")
        return 0

def mark_all_notifications_read(user_id):
    try:
        updated_count = Notification.query.filter_by(user_id=user_id, read=False).update({'read': True})
        db.session.commit()
        return updated_count
    except Exception as e:
        db.session.rollback()
        print(f"Error marking all notifications read: {str(e)}")
        return 0

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def get_current_percentages():
    setting = PercentageSetting.query.first()
    if not setting:
        setting = PercentageSetting(provider_percent=60.0, admin_percent=20.0, site_fee_percent=10.0, referral_pool_percent=10.0)
        db.session.add(setting)
        db.session.commit()
    return setting

# ==================== EMAIL HELPER FUNCTION ====================

def send_reset_email(user_email, user_name, reset_token):
    try:
        frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
        reset_link = f"{frontend_url}/reset-password?token={reset_token}"
        
        print(f"\n{'='*60}")
        print(f"🔐 PASSWORD RESET LINK (copy this URL to reset password):")
        print(f"{reset_link}")
        print(f"{'='*60}\n")
        
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        smtp_username = "zivrefaserve@gmail.com"
        smtp_password = "jmivcbvhipysvgcl"
        
        subject = "Reset Your Zivre Password"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 500px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #10b981;">Reset Your Password</h2>
                <p>Hello {user_name},</p>
                <p>Click the button below to reset your password. This link expires in 1 hour.</p>
                <a href="{reset_link}" style="background-color: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                <p>Or copy this link: {reset_link}</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>Thanks,<br>Zivre Team</p>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp_username
        msg['To'] = user_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email sent to {user_email}")
        return True
        
    except Exception as e:
        print(f"❌ Email error: {str(e)}")
        return True


def send_verification_email(user_email, user_name, verification_token):
    try:
        frontend_url = os.environ.get('FRONTEND_URL', 'https://zivre-frontend.vercel.app')
        verification_link = f"{frontend_url}/verify-email?token={verification_token}"
        
        print(f"\n{'='*60}")
        print(f"📧 EMAIL VERIFICATION LINK (copy this URL to verify email):")
        print(f"{verification_link}")
        print(f"{'='*60}\n")
        
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        smtp_username = "zivrefaserve@gmail.com"
        smtp_password = os.environ.get('SMTP_PASSWORD', 'jmivcbvhipysvgcl')
        
        subject = "Verify Your Zivre Email Address"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 10px;">
                <h2 style="color: #10b981;">Welcome to Zivre!</h2>
                <p>Hello {user_name},</p>
                <p>Please verify your email address to complete your registration.</p>
                <a href="{verification_link}" style="background-color: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">Verify Email Address</a>
                <p>Or copy this link: <strong style="color: #10b981;">{verification_link}</strong></p>
                <p>This link expires in <strong>24 hours</strong>.</p>
                <p>If you didn't create an account, please ignore this email.</p>
                <hr style="margin: 20px 0;">
                <p style="color: #64748b; font-size: 12px;">Zivre Facility Services - Professional facility management across Ghana</p>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp_username
        msg['To'] = user_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Verification email sent to {user_email}")
        return True
        
    except Exception as e:
        print(f"❌ Verification email error: {str(e)}")
        return False

# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    user_id = request.args.get('userId')
    print(f"🔌 WebSocket connect attempt - User ID: {user_id}")
    
    if user_id and user_id.isdigit():
        user = db.session.get(User, int(user_id))
        if user:
            user.is_online = True
            user.last_seen = datetime.utcnow()
            db.session.commit()
            join_room(f"user_{user_id}")
            join_room(f"role_{user.role}")
            print(f"✅ User {user.full_name} connected to WebSocket")
            emit('user_status', {'userId': user_id, 'isOnline': True})
            return True
    
    print(f"🔴 WebSocket connection rejected")
    return False

@socketio.on('disconnect')
def handle_disconnect():
    user_id = request.args.get('userId')
    print(f"🔴 WebSocket disconnect - User ID: {user_id}")
    
    if user_id and user_id.isdigit():
        user = db.session.get(User, int(user_id))
        if user:
            user.is_online = False
            user.last_seen = datetime.utcnow()
            db.session.commit()
            emit('user_status', {'userId': user_id, 'isOnline': False})

@socketio.on('ping')
def handle_ping(data):
    emit('pong', {'server': 'zivre-backend', 'time': datetime.utcnow().isoformat()})

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = int(request.args.get('userId'))
    receiver_id = data.get('receiverId')
    message_text = data.get('message')
    message_id = data.get('messageId')
    reply_to_id = data.get('replyToId')
    
    sender = db.session.get(User, sender_id)
    receiver = db.session.get(User, receiver_id)
    
    if not sender or not receiver:
        emit('error', {'message': 'User not found'})
        return
    
    if sender.role == 'customer' and receiver.role == 'customer':
        emit('error', {'message': 'Customers cannot message other customers'})
        return
    
    if sender.role == 'provider' and receiver.role == 'provider':
        emit('error', {'message': 'Providers cannot message other providers'})
        return
    
    if sender.role == 'customer' and receiver.role == 'provider':
        assigned_job = ServiceRequest.query.filter(
            ServiceRequest.provider_id == receiver_id, 
            ServiceRequest.user_id == sender_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed'])
        ).first()
        if not assigned_job:
            emit('error', {'message': 'You can only message providers assigned to your active or completed jobs'})
            return
    
    if sender.role == 'provider' and receiver.role == 'customer':
        assigned_job = ServiceRequest.query.filter(
            ServiceRequest.provider_id == sender_id, 
            ServiceRequest.user_id == receiver_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed'])
        ).first()
        if not assigned_job:
            emit('error', {'message': 'You can only message customers assigned to your active or completed jobs'})
            return
    
    new_message = Message(
        sender_id=sender_id,
        receiver_id=receiver_id,
        subject=data.get('subject', ''),
        message=bleach.clean(message_text) if message_text else '',
        reply_to_id=reply_to_id,
        is_delivered=False,
        is_read=False
    )
    db.session.add(new_message)
    db.session.commit()
    
    emit('new_message', {
        'id': new_message.id,
        'sender_id': sender_id,
        'sender_name': sender.full_name,
        'sender_role': sender.role,
        'receiver_id': receiver_id,
        'receiver_name': receiver.full_name,
        'receiver_role': receiver.role,
        'message': new_message.message,
        'reply_to_id': reply_to_id,
        'created_at': new_message.created_at.isoformat(),
        'temp_id': message_id
    }, room=f"user_{receiver_id}")
    
    emit('message_delivered', {
        'message_id': new_message.id,
        'temp_id': message_id,
        'status': 'delivered'
    }, room=f"user_{sender_id}")
    
    create_notification(receiver_id, f'New message from {sender.full_name}', 'message', '/messages')

@socketio.on('typing')
def handle_typing(data):
    sender_id = int(request.args.get('userId'))
    receiver_id = data.get('receiverId')
    is_typing = data.get('isTyping')
    
    emit('typing', {
        'sender_id': sender_id,
        'isTyping': is_typing
    }, room=f"user_{receiver_id}")

@socketio.on('mark_read')
def handle_mark_read(data):
    user_id = int(request.args.get('userId'))
    message_id = data.get('messageId')
    sender_id = data.get('senderId')
    
    message = db.session.get(Message, message_id)
    if message and message.receiver_id == user_id and not message.is_read:
        message.is_read = True
        message.read_at = datetime.utcnow()
        db.session.commit()
        
        emit('message_read', {
            'message_id': message_id,
            'sender_id': sender_id
        }, room=f"user_{sender_id}")

@socketio.on('mark_delivered')
def handle_mark_delivered(data):
    user_id = int(request.args.get('userId'))
    message_id = data.get('messageId')
    sender_id = data.get('senderId')
    
    message = db.session.get(Message, message_id)
    if message and message.receiver_id == user_id and not message.is_delivered:
        message.is_delivered = True
        message.delivered_at = datetime.utcnow()
        db.session.commit()
        
        emit('message_delivered', {
            'message_id': message_id,
            'sender_id': sender_id
        }, room=f"user_{sender_id}")

# ==================== PERCENTAGE SETTINGS ROUTES ====================

@app.route('/api/settings/percentages', methods=['GET'])
def get_percentages():
    setting = get_current_percentages()
    
    return jsonify({
        'provider_percent': setting.provider_percent,
        'admin_percent': setting.admin_percent,
        'site_fee_percent': setting.site_fee_percent,
        'referral_pool_percent': setting.referral_pool_percent,
        'total': setting.get_total(),
        'is_valid': setting.is_valid(),
        'updated_at': setting.updated_at.isoformat() if setting.updated_at else None
    })

@app.route('/api/admin/settings/percentages', methods=['PUT'])
@admin_required
def update_percentages():
    data = request.json
    
    try:
        provider = float(data.get('provider_percent', 60))
        admin = float(data.get('admin_percent', 20))
        site_fee = float(data.get('site_fee_percent', 10))
        referral_pool = float(data.get('referral_pool_percent', 10))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid percentage values'}), 400
    
    total = provider + admin + site_fee + referral_pool
    if abs(total - 100) > 0.01:
        return jsonify({'error': f'Percentages must sum to 100%. Current total: {total}%'}), 400
    
    if not all(0 <= p <= 100 for p in [provider, admin, site_fee, referral_pool]):
        return jsonify({'error': 'Each percentage must be between 0 and 100'}), 400
    
    setting = get_current_percentages()
    setting.provider_percent = provider
    setting.admin_percent = admin
    setting.site_fee_percent = site_fee
    setting.referral_pool_percent = referral_pool
    setting.updated_by = request.current_user.id
    db.session.commit()
    
    # ========== AUTO-RECALCULATE ALL EXISTING SERVICES ==========
    try:
        all_services = Service.query.all()
        updated_count = 0
        for service in all_services:
            service.provider_payout = service.total_price * (provider / 100)
            service.admin_fee = service.total_price * (admin / 100)
            service.site_fee = service.total_price * (site_fee / 100)
            service.referral_pool_amount = service.total_price * (referral_pool / 100)
            updated_count += 1
        db.session.commit()
        print(f"✅ Auto-recalculated {updated_count} services with new percentages")
    except Exception as e:
        print(f"⚠️ Service recalculation error: {e}")
        # Don't fail - percentages were already saved
    
    socketio.emit('percentages_updated', {
        'provider_percent': provider,
        'admin_percent': admin,
        'site_fee_percent': site_fee,
        'referral_pool_percent': referral_pool,
        'total': total
    })
    
    return jsonify({
        'message': 'Percentages updated successfully',
        'percentages': {
            'provider_percent': provider,
            'admin_percent': admin,
            'site_fee_percent': site_fee,
            'referral_pool_percent': referral_pool,
            'total': total
        }
    })
    
# ====================  HELPER FUNCTION ====================

def generate_referral_code():
    """Generate a unique referral code for a user"""
    while True:
        code = secrets.token_urlsafe(8).upper().replace('-', '').replace('_', '')
        existing = User.query.filter_by(referral_code=code).first()
        if not existing:
            return code

def calculate_commission(referral_pool, level):
    """Calculate commission based on level (geometric decay)"""
    rate = BASE_COMMISSION_RATE * (COMMISSION_DECAY_FACTOR ** (level - 1))
    commission = referral_pool * rate
    return round(commission, 2) if commission >= 0.01 else 0


def process_referral_commissions(booking, customer):
    """
    Process referral commissions using referral_pool_percent from Percentage Settings
    """
    self_bonus = 0  
    if booking.commissions_processed:
        return {'already_processed': True, 'total_commissions': booking.total_commissions_paid}
    
    # Get percentages from GLOBAL settings (NOT from service table)
    percentages = get_current_percentages()
    referral_pool_percent = percentages.referral_pool_percent
    
    # Calculate referral pool amount from booking amount
    referral_pool = booking.amount * referral_pool_percent / 100
    
    # Store snapshots
    booking.referral_pool_amount = referral_pool
    booking.referral_pool_percent_snapshot = referral_pool_percent
    booking.admin_share_percent_snapshot = percentages.admin_percent
    booking.site_fee_percent_snapshot = percentages.site_fee_percent
    booking.provider_share_percent_snapshot = percentages.provider_percent
    
    total_commissions = 0
    level = 1
    
    # Count completed bookings EXCLUDING current one
    user_completed_bookings = ServiceRequest.query.filter(
        ServiceRequest.user_id == customer.id,
        ServiceRequest.status == 'confirmed',
        ServiceRequest.id != booking.id
    ).count()
    
    # Self-bonus for first booking (5% of referral pool)
    if user_completed_bookings == 0:
        self_bonus = referral_pool * 0.05
        if self_bonus >= 0.01:
            customer.commission_balance = (customer.commission_balance or 0) + self_bonus
            customer.total_earned = (customer.total_earned or 0) + self_bonus
            total_commissions += self_bonus
            
            new_commission = Commission(
                booking_id=booking.id,
                user_id=customer.id,
                level=0,
                amount=self_bonus
            )
            db.session.add(new_commission)
            
            # Notify customer of self-bonus
            socketio.emit('new_commission', {
                'user_id': customer.id,
                'amount': self_bonus,
                'level': 0,
                'booking_id': booking.id
            }, room=f"user_{customer.id}")
        
        # User becomes ACTIVE by doing their own service
        customer.is_referral_active = True
    
    # Process referral chain
    current_user = customer
    while current_user and current_user.referrer_id and level <= MAX_REFERRAL_DEPTH:
        referrer = db.session.get(User, current_user.referrer_id)
        if not referrer:
            break
        
        # Calculate commission based on level (geometric decay)
        rate = BASE_COMMISSION_RATE * (COMMISSION_DECAY_FACTOR ** (level - 1))
        commission = referral_pool * rate
        commission = round(commission, 2) if commission >= 0.01 else 0
        
        if commission < 0.01:
            break
        
        referrer.commission_balance = (referrer.commission_balance or 0) + commission
        referrer.total_earned = (referrer.total_earned or 0) + commission
        total_commissions += commission
        
        # Activate referrer if inactive
        if not referrer.is_referral_active:
            referrer.is_referral_active = True
        
        new_commission = Commission(
            booking_id=booking.id,
            user_id=referrer.id,
            level=level,
            amount=commission
        )
        db.session.add(new_commission)
        
        # Notify referrer of new commission
        socketio.emit('new_commission', {
            'user_id': referrer.id,
            'amount': commission,
            'level': level,
            'booking_id': booking.id
        }, room=f"user_{referrer.id}")
        
        level += 1
        current_user = referrer
    
    # Owner net = referral pool minus all commissions paid
    booking.total_commissions_paid = total_commissions
    booking.owner_net = referral_pool - total_commissions
    booking.commissions_processed = True
    
    db.session.commit()
    
    return {
        'success': True,
        'referral_pool_percent': referral_pool_percent,
        'referral_pool': referral_pool,
        'total_commissions': total_commissions,
        'owner_net': booking.owner_net,
        'levels_processed': level - 1,
        'self_bonus': self_bonus if user_completed_bookings == 0 else 0
    }
    
    
# ==================== AUTH ROUTES ====================
  # ==================== AUTH ROUTES ====================
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    
    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account has been suspended'}), 401

        # ✅ ADD THIS CHECK - Email verification required
    if not user.email_verified:
        return jsonify({
            'error': 'Please verify your email address before logging in.',
            'requires_verification': True,
            'email': user.email
        }), 403
        
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }, JWT_SECRET, algorithm='HS256')
    
    print(f"✅ Login successful for user {user.email}")
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'phone': user.phone,
            'role': user.role,
            'is_verified': user.is_verified,
            'rating': user.rating,
            'total_jobs': user.total_jobs,
            'service_specialization': user.service_specialization.name if user.service_specialization else None,
            'service_specialization_id': user.service_specialization_id,
            'referral_code': user.referral_code,
            'commission_balance': float(user.commission_balance or 0),
            'total_earned': float(user.total_earned or 0),
            'is_referral_active': user.is_referral_active
        }
    })



@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("10 per minute")
def signup():
    data = request.json
    
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    if not validate_email(data.get('email')):
        return jsonify({'error': 'Invalid email format'}), 400
    
    is_valid, password_msg = validate_password(data.get('password'))
    if not is_valid:
        return jsonify({'error': password_msg}), 400
    
    hashed_password = generate_password_hash(data.get('password'))
    
    service_specialization_id = data.get('service_specialization')
    
    if data.get('role') == 'provider' and service_specialization_id:
        service = db.session.get(Service, service_specialization_id)
        if not service:
            return jsonify({'error': 'Selected service specialization does not exist'}), 400
        if not service.is_active:
            return jsonify({'error': 'Selected service is not active'}), 400
    
    # Handle referral code
    referrer_id = None
    position = None
    referral_code_input = data.get('referral_code')
    
    if referral_code_input:
        referrer = User.query.filter_by(referral_code=referral_code_input).first()
        if referrer:
            referrer_id = referrer.id
            children_count = User.query.filter_by(referrer_id=referrer.id).count()
            if children_count == 0:
                position = 'left'
            elif children_count == 1:
                position = 'center'
            elif children_count == 2:
                position = 'right'
            else:
                return jsonify({'error': 'This referrer already has maximum children (3)'}), 400
    
    # Generate verification token
    verification_token = str(uuid.uuid4())
    verification_expiry = datetime.utcnow() + timedelta(hours=24)
    
    new_user = User(
        email=data.get('email'),
        password=hashed_password,
        full_name=data.get('full_name'),
        phone=data.get('phone'),
        role=data.get('role', 'customer'),
        service_specialization_id=service_specialization_id if data.get('role') == 'provider' else None,
        is_verified=False if data.get('role') == 'provider' else False,  # ← Changed: ALL users need email verification
        is_referral_active=False,
        referral_code=generate_referral_code(),
        referrer_id=referrer_id,
        position=position,
        email_verified=False,  # ← NEW: Not verified yet
        verification_token=verification_token,  # ← NEW
        verification_token_expiry=verification_expiry  # ← NEW
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    # Send verification email
    send_verification_email(new_user.email, new_user.full_name, verification_token)
    
    # If user signed up with a referral code, notify the referrer to update their tree
    if referrer_id:
        socketio.emit('referral_tree_updated', {
            'user_id': referrer_id,
            'new_user_id': new_user.id
        }, room=f"user_{referrer_id}")
    
    # Return response WITHOUT auto-login (they need to verify first)
    return jsonify({
        'message': 'Registration successful! Please check your email to verify your account.',
        'requires_verification': True,
        'email': new_user.email
    }), 201
        
    # Generate JWT token for auto-login
    token = jwt.encode({
        'user_id': new_user.id,
        'email': new_user.email,
        'role': new_user.role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({
        'message': 'User created successfully',
        'token': token,
        'user': {
            'id': new_user.id,
            'email': new_user.email,
            'full_name': new_user.full_name,
            'role': new_user.role,
            'service_specialization': new_user.service_specialization.name if new_user.service_specialization else None,
            'referral_code': new_user.referral_code,
            'is_referral_active': new_user.is_referral_active,  # ← FIXED: was 'is_active'
            'commission_balance': float(new_user.commission_balance or 0)
        }
    })
  
   


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    # JWT logout is client-side only - just return success
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token():
    return jsonify({
        'valid': True,
        'user': {
            'id': request.current_user.id,
            'email': request.current_user.email,
            'full_name': request.current_user.full_name,
            'role': request.current_user.role,
            'is_verified': request.current_user.is_verified,
            'rating': request.current_user.rating,
            'total_jobs': request.current_user.total_jobs,
            'service_specialization': request.current_user.service_specialization.name if request.current_user.service_specialization else None,
            'service_specialization_id': request.current_user.service_specialization_id,
            'referral_code': request.current_user.referral_code,
            'commission_balance': float(request.current_user.commission_balance or 0),
            'is_referral_active': request.current_user.is_referral_active
        }
    })

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')
    
    print(f"📧 Forgot password request for email: {email}")
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        print(f"❌ Email not found: {email}")
        return jsonify({'error': 'Email not found'}), 404
    
    reset_token = str(uuid.uuid4())
    user.reset_token = reset_token
    user.reset_expiry = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    print(f"✅ Generated reset token for {email}: {reset_token}")
    
    try:
        send_reset_email(user.email, user.full_name, reset_token)
    except Exception as e:
        print(f"Email error but continuing: {e}")
    
    return jsonify({'message': 'Password reset link has been sent to your email address.'})

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('new_password')
    
    print(f"🔐 Reset password request with token: {token}")
    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    is_valid, password_msg = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': password_msg}), 400
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user:
        print(f"❌ Invalid token: {token}")
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    if user.reset_expiry < datetime.utcnow():
        print(f"❌ Token expired for user: {user.email}")
        return jsonify({'error': 'Reset token has expired. Please request a new one.'}), 400
    
    user.password = generate_password_hash(new_password)
    user.reset_token = None
    user.reset_expiry = None
    db.session.commit()
    
    print(f"✅ Password reset successfully for: {user.email}")
    
    return jsonify({'message': 'Password reset successfully'})


@app.route('/api/auth/verify-email', methods=['POST'])
def verify_email():
    data = request.json
    token = data.get('token')
    
    print(f"📧 Email verification request with token: {token}")
    
    if not token:
        return jsonify({'error': 'Verification token is required'}), 400
    
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        return jsonify({'error': 'Invalid verification token'}), 400
    
    if user.email_verified:
        return jsonify({'message': 'Email already verified. You can now login.'}), 200
    
    if user.verification_token_expiry < datetime.utcnow():
        return jsonify({'error': 'Verification link has expired. Please request a new one.'}), 400
    
    # Verify the email
    user.email_verified = True
    user.verification_token = None
    user.verification_token_expiry = None
    
    # If user is a customer, they are now active
    if user.role == 'customer':
        user.is_verified = True
    
    db.session.commit()
    
    print(f"✅ Email verified for user: {user.email}")
    
    return jsonify({
        'message': 'Email verified successfully! You can now login.',
        'verified': True
    })

@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.email_verified:
        return jsonify({'error': 'Email already verified'}), 400
    
    # Generate new token
    verification_token = str(uuid.uuid4())
    user.verification_token = verification_token
    user.verification_token_expiry = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()
    
    # Send new verification email
    send_verification_email(user.email, user.full_name, verification_token)
    
    return jsonify({'message': 'Verification email sent. Please check your inbox.'})


    
@app.route('/api/auth/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'email': user.email,
        'full_name': user.full_name,
        'phone': user.phone,
        'role': user.role,
        'is_verified': user.is_verified,
        'rating': user.rating,
        'total_jobs': user.total_jobs,
        'created_at': user.created_at.isoformat(),
        'service_specialization': user.service_specialization.name if user.service_specialization else None,
        'service_specialization_id': user.service_specialization_id
    })

@app.route('/api/auth/update-profile/<int:user_id>', methods=['PUT'])
@limiter.limit("10 per minute")
@token_required
def update_profile(user_id):
    data = request.json
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify({'error': 'You can only update your own profile'}), 403
    
    if 'full_name' in data:
        user.full_name = data['full_name']
    if 'phone' in data:
        user.phone = data['phone']
    if 'email' in data:
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        existing = User.query.filter_by(email=data['email']).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Email already in use'}), 400
        user.email = data['email']
    
    db.session.commit()
    return jsonify({'message': 'Profile updated successfully', 'user': {
        'id': user.id, 'full_name': user.full_name, 'phone': user.phone, 'email': user.email
    }})

@app.route('/api/auth/change-password/<int:user_id>', methods=['PUT'])
@limiter.limit("5 per minute")
@token_required
def change_password(user_id):
    data = request.json
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if request.current_user.id != user_id:
        return jsonify({'error': 'You can only change your own password'}), 403
    
    if not check_password_hash(user.password, data.get('current_password')):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    is_valid, password_msg = validate_password(data.get('new_password'))
    if not is_valid:
        return jsonify({'error': password_msg}), 400
    
    user.password = generate_password_hash(data.get('new_password'))
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'})

@app.route('/api/auth/toggle-online/<int:user_id>', methods=['PUT'])
@limiter.limit("30 per minute")
@token_required
def toggle_online_status(user_id):
    try:
        if request.current_user.id != user_id:
            return jsonify({'error': f'You can only change your own status.'}), 403
        
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        is_online = data.get('is_online', False)
        
        user.is_online_manual = is_online
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        try:
            socketio.emit('user_status', {'userId': user_id, 'isOnline': is_online})
        except Exception as e:
            print(f"Error broadcasting status: {e}")
        
        return jsonify({
            'success': True,
            'message': f'{user.full_name} is now {"Online" if is_online else "Offline"}',
            'is_online': is_online
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error toggling online status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/delete-account', methods=['DELETE'])
@token_required
def delete_own_account():
    user_id = request.current_user.id
    user = db.session.get(User, user_id)
    
    if user.role == 'admin':
        return jsonify({'error': 'Admin accounts cannot be deleted through this endpoint'}), 403
    
    ServiceRequest.query.filter_by(user_id=user_id).delete()
    ServiceRequest.query.filter_by(provider_id=user_id).update({'provider_id': None})
    Notification.query.filter_by(user_id=user_id).delete()
    Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
    Comment.query.filter_by(user_id=user_id).delete()
    CommentReply.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'Account deleted successfully'})

# ==================== UPLOAD ROUTES ====================

@app.route('/api/requests/<int:request_id>/notify-no-provider', methods=['POST'])
@admin_required
def notify_no_provider(request_id):
    try:
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        create_notification(
            service_request.user_id,
            f'⚠️ We are currently looking for a provider for your {service_request.service.name} request. We will notify you as soon as one is assigned.',
            'info',
            '/customer/dashboard'
        )
        
        return jsonify({'message': 'Customer notified successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in notify_no_provider: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@limiter.limit("50 per hour")
@token_required
def upload_file():
    try:
        user_id = request.form.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        user = db.session.get(User, int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if request.current_user.id != int(user_id):
            return jsonify({'error': 'You can only upload files for yourself'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        original_filename = secure_filename(file.filename)
        ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        file_type = get_file_type(original_filename)
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file': {
                'filename': unique_filename,
                'original_name': original_filename,
                'size': file_size,
                'type': file_type,
                'mime_type': mime_type,
                'path': f'/uploads/{unique_filename}'
            }
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"Error uploading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== SERVICE ROUTES ====================

@app.route('/api/services', methods=['GET'])
def get_services():
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    if active_only:
        services = Service.query.filter_by(is_active=True).all()
    else:
        services = Service.query.all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'description': s.description,
        'total_price': s.total_price,
        'provider_payout': s.provider_payout,
        'admin_fee': s.admin_fee,
        'site_fee': s.site_fee,
        'icon': s.icon,
        'is_active': s.is_active
    } for s in services])

@app.route('/api/services', methods=['POST'])
@admin_required
def create_service():
    try:
        data = request.json
        
        try:
            total_price = float(data.get('total_price', 0))
            if total_price <= 0 or total_price > 10000:
                return jsonify({'error': 'Price must be between 0 and 10,000'}), 400
            if math.isnan(total_price) or math.isinf(total_price):
                return jsonify({'error': 'Invalid price value'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'Price must be a valid number'}), 400
        
        percentages = get_current_percentages()
        
        provider_payout = total_price * (percentages.provider_percent / 100)
        admin_fee = total_price * (percentages.admin_percent / 100)
        site_fee = total_price * (percentages.site_fee_percent / 100)
        referral_pool_amount = total_price * (percentages.referral_pool_percent / 100)
        
        new_service = Service(
            name=data.get('name'),
            description=data.get('description'),
            total_price=total_price,
            provider_payout=provider_payout,
            admin_fee=admin_fee,
            site_fee=site_fee,
            referral_pool_amount=referral_pool_amount,  # ← ADD THIS
            icon=data.get('icon', '🔧'),
            is_active=False
        )
        db.session.add(new_service)
        db.session.commit()
        
        socketio.emit('service_created', {
            'id': new_service.id,
            'name': new_service.name,
            'total_price': new_service.total_price,
            'provider_payout': new_service.provider_payout,
            'admin_fee': new_service.admin_fee,
            'site_fee': new_service.site_fee,
            'icon': new_service.icon,
            'is_active': new_service.is_active
        })
        
        return jsonify({'message': 'Service created', 'id': new_service.id})
    except Exception as e:
        db.session.rollback()
        print(f"Error creating service: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<int:service_id>/toggle', methods=['PUT'])
@admin_required
def toggle_service_active(service_id):
    service = db.session.get(Service, service_id)
    if not service:
        return jsonify({'error': 'Service not found'}), 404
    
    service.is_active = not service.is_active
    db.session.commit()
    
    socketio.emit('service_toggled', {
        'id': service.id,
        'is_active': service.is_active,
        'name': service.name
    })
    
    return jsonify({'message': f'Service {"activated" if service.is_active else "deactivated"}', 'is_active': service.is_active})

@app.route('/api/services/<int:service_id>', methods=['PUT'])
@admin_required
def update_service(service_id):
    try:
        service = db.session.get(Service, service_id)
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        data = request.json
        
        try:
            total_price = float(data.get('total_price', service.total_price))
            if total_price <= 0 or total_price > 10000:
                return jsonify({'error': 'Price must be between 0 and 10,000'}), 400
            if math.isnan(total_price) or math.isinf(total_price):
                return jsonify({'error': 'Invalid price value'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'Price must be a valid number'}), 400
        
        percentages = get_current_percentages()
        
        service.total_price = total_price
        service.provider_payout = total_price * (percentages.provider_percent / 100)
        service.admin_fee = total_price * (percentages.admin_percent / 100)
        service.site_fee = total_price * (percentages.site_fee_percent / 100)
        service.referral_pool_amount = total_price * (percentages.referral_pool_percent / 100)  # ← ADD THIS
        service.name = data.get('name', service.name)
        service.description = data.get('description', service.description)
        service.icon = data.get('icon', service.icon)
        db.session.commit()
        
        socketio.emit('service_updated', {
            'id': service.id,
            'name': service.name,
            'total_price': service.total_price,
            'provider_payout': service.provider_payout,
            'admin_fee': service.admin_fee,
            'site_fee': service.site_fee
        })
        
        return jsonify({'message': 'Service updated'})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating service: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==================== QUOTE ROUTES ====================

@app.route('/api/quotes', methods=['POST'])
@limiter.limit("5 per hour")
def create_quote():
    data = request.json
    new_quote = Quote(
        full_name=data.get('full_name'),
        phone=data.get('phone'),
        email=data.get('email'),
        service_type=data.get('service_type'),
        location=data.get('location'),
        message=data.get('message')
    )
    db.session.add(new_quote)
    db.session.commit()
    
    socketio.emit('new_quote', {
        'id': new_quote.id,
        'full_name': new_quote.full_name,
        'service_type': new_quote.service_type,
        'created_at': new_quote.created_at.isoformat()
    }, room='role_admin')
    
    return jsonify({'message': 'Quote submitted successfully', 'id': new_quote.id})

@app.route('/api/quotes', methods=['GET'])
@admin_required
def get_quotes():
    quotes = Quote.query.order_by(Quote.created_at.desc()).all()
    return jsonify([{
        'id': q.id,
        'full_name': q.full_name,
        'phone': q.phone,
        'email': q.email,
        'service_type': q.service_type,
        'location': q.location,
        'message': q.message,
        'status': q.status,
        'created_at': q.created_at.isoformat()
    } for q in quotes])

@app.route('/api/quotes/<int:quote_id>/status', methods=['PUT'])
@admin_required
def update_quote_status(quote_id):
    quote = db.session.get(Quote, quote_id)
    if not quote:
        return jsonify({'error': 'Quote not found'}), 404
    data = request.json
    quote.status = data.get('status', quote.status)
    db.session.commit()
    
    socketio.emit('quote_status_updated', {
        'quote_id': quote_id,
        'status': quote.status
    }, room='role_admin')
    
    return jsonify({'message': 'Quote status updated'})

@app.route('/api/quotes/<int:quote_id>', methods=['DELETE'])
@admin_required
def delete_quote(quote_id):
    quote = db.session.get(Quote, quote_id)
    if not quote:
        return jsonify({'error': 'Quote not found'}), 404
    db.session.delete(quote)
    db.session.commit()
    return jsonify({'message': 'Quote deleted'})

# ==================== COMMENT ROUTES ====================

@app.route('/api/comments', methods=['GET'])
def get_comments():
    try:
        comments = Comment.query.filter_by(is_approved=True).order_by(Comment.created_at.desc()).limit(100).all()
        result = []
        for c in comments:
            try:
                replies = CommentReply.query.filter_by(comment_id=c.id).order_by(CommentReply.created_at.asc()).all()
                reply_list = []
                for r in replies:
                    reply_list.append({
                        'id': r.id,
                        'user_id': r.user_id,
                        'user_name': r.user_name or 'User',
                        'user_role': r.user_role or 'customer',
                        'message': r.message or '',
                        'created_at': r.created_at.isoformat() if r.created_at else None
                    })
                
                result.append({
                    'id': c.id,
                    'user_id': c.user_id,
                    'user_name': c.user_name or 'Anonymous',
                    'user_role': c.user_role or 'customer',
                    'user_avatar': c.user_avatar or '👤',
                    'rating': c.rating or 5,
                    'comment': c.comment or '',
                    'helpful_count': c.helpful_count or 0,
                    'created_at': c.created_at.isoformat() if c.created_at else None,
                    'updated_at': c.updated_at.isoformat() if c.updated_at else None,
                    'replies': reply_list
                })
            except Exception as e:
                print(f"Error processing comment {c.id}: {str(e)}")
                continue
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_comments: {str(e)}")
        return jsonify([]), 200

@app.route('/api/comments', methods=['POST'])
def create_comment():
    try:
        data = request.json
        user_id = data.get('user_id')
        user = db.session.get(User, user_id) if user_id else None
        
        if not data.get('comment') or len(data.get('comment').strip()) < 3:
            return jsonify({'error': 'Comment must be at least 3 characters'}), 400
        
        sanitized_comment = bleach.clean(data.get('comment'), tags=['b', 'i', 'em', 'strong', 'a'], attributes={'a': ['href']})
        
        new_comment = Comment(
            user_id=user_id if user else None,
            user_name=data.get('user_name'),
            user_role=user.role if user else 'customer',
            user_avatar=data.get('user_avatar', '👤'),
            rating=data.get('rating', 5),
            comment=sanitized_comment,
            is_approved=True,
            helpful_count=0
        )
        db.session.add(new_comment)
        db.session.commit()
        
        socketio.emit('new_comment', {
            'id': new_comment.id,
            'user_name': new_comment.user_name,
            'rating': new_comment.rating,
            'comment': new_comment.comment[:100]
        })
        
        return jsonify({'message': 'Comment submitted successfully!', 'comment': {
            'id': new_comment.id,
            'user_name': new_comment.user_name,
            'user_role': new_comment.user_role,
            'user_avatar': new_comment.user_avatar,
            'rating': new_comment.rating,
            'comment': new_comment.comment,
            'helpful_count': new_comment.helpful_count,
            'created_at': new_comment.created_at.isoformat()
        }})
    except Exception as e:
        db.session.rollback()
        print(f"Error creating comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/comments/<int:comment_id>', methods=['PUT'])
@token_required
def update_comment(comment_id):
    try:
        data = request.json
        comment = db.session.get(Comment, comment_id)
        
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404
        
        if request.current_user.role != 'admin':
            time_since = datetime.utcnow() - comment.created_at
            if time_since.total_seconds() > 120:
                return jsonify({'error': 'Edit window expired (2 minutes)'}), 403
            if comment.user_id != request.current_user.id:
                return jsonify({'error': 'You can only edit your own comments'}), 403
        
        if 'comment' in data:
            comment.comment = bleach.clean(data['comment'], tags=['b', 'i', 'em', 'strong', 'a'], attributes={'a': ['href']})
        if 'rating' in data:
            comment.rating = data['rating']
        comment.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        socketio.emit('comment_updated', {
            'id': comment.id,
            'comment': comment.comment,
            'rating': comment.rating
        })
        
        return jsonify({'message': 'Comment updated successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_comment(comment_id):
    try:
        comment = db.session.get(Comment, comment_id)
        
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404
        
        if request.current_user.role != 'admin':
            time_since = datetime.utcnow() - comment.created_at
            if time_since.total_seconds() > 120:
                return jsonify({'error': 'Delete window expired (2 minutes)'}), 403
            if comment.user_id != request.current_user.id:
                return jsonify({'error': 'You can only delete your own comments'}), 403
        
        CommentReply.query.filter_by(comment_id=comment_id).delete()
        db.session.delete(comment)
        db.session.commit()
        
        socketio.emit('comment_deleted', {'id': comment_id})
        
        return jsonify({'message': 'Comment deleted successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/comments/reply', methods=['POST'])
@token_required
def create_reply():
    try:
        data = request.json
        
        new_reply = CommentReply(
            comment_id=data.get('comment_id'),
            user_id=request.current_user.id,
            user_name=request.current_user.full_name,
            user_role=request.current_user.role,
            message=bleach.clean(data.get('message'))
        )
        db.session.add(new_reply)
        db.session.commit()
        
        socketio.emit('new_reply', {
            'comment_id': new_reply.comment_id,
            'user_name': new_reply.user_name,
            'message': new_reply.message
        })
        
        return jsonify({'message': 'Reply submitted successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error creating reply: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/comments', methods=['GET'])
@admin_required
def get_all_comments():
    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return jsonify([{
        'id': c.id,
        'user_id': c.user_id,
        'user_name': c.user_name,
        'user_role': c.user_role,
        'rating': c.rating,
        'comment': c.comment,
        'is_approved': c.is_approved,
        'helpful_count': c.helpful_count,
        'created_at': c.created_at.isoformat()
    } for c in comments])

@app.route('/api/admin/comments/<int:comment_id>/toggle', methods=['PUT'])
@admin_required
def toggle_comment_approval(comment_id):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    comment.is_approved = not comment.is_approved
    db.session.commit()
    
    socketio.emit('comment_toggled', {
        'id': comment.id,
        'is_approved': comment.is_approved
    })
    
    return jsonify({'message': f'Comment {"approved" if comment.is_approved else "hidden"}'})

@app.route('/api/admin/comments/<int:comment_id>', methods=['DELETE'])
@admin_required
def admin_delete_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    CommentReply.query.filter_by(comment_id=comment_id).delete()
    db.session.delete(comment)
    db.session.commit()
    
    socketio.emit('comment_deleted', {'id': comment_id})
    
    return jsonify({'message': 'Comment deleted'})

# ==================== SERVICE REQUEST ROUTES ====================

@app.route('/api/requests', methods=['POST'])
@token_required
def create_request():
    try:
        data = request.json
        
        service = db.session.get(Service, data.get('service_id'))
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        if not service.is_active:
            return jsonify({'error': 'Service is currently inactive'}), 400
        
        customer_phone = data.get('customer_phone', request.current_user.phone)
        
        new_request = ServiceRequest(
            user_id=request.current_user.id,
            service_id=data.get('service_id'),
            amount=service.total_price,
            provider_payout=service.provider_payout,
            admin_fee=service.admin_fee,
            site_fee=service.site_fee,
            location_address=data.get('location_address', ''),
            location_city=data.get('location_city', ''),
            location_region=data.get('location_region', ''),
            location_landmark=data.get('location_landmark', ''),
            customer_phone=customer_phone,
            status='pending_approval'
        )
        db.session.add(new_request)
        db.session.commit()
        
        create_notification(request.current_user.id, f'📝 Your request for {service.name} has been submitted. Admin will review and assign a provider. You will pay the provider directly after service completion.', 'info', '/customer/dashboard')
        
        socketio.emit('new_request', {
            'id': new_request.id,
            'customer_name': request.current_user.full_name,
            'service_name': service.name,
            'amount': service.total_price,
            'created_at': new_request.created_at.isoformat()
        }, room='role_admin')
        
        socketio.emit('request_created', {
            'request_id': new_request.id,
            'service_name': service.name,
            'status': 'pending_approval'
        }, room=f"user_{request.current_user.id}")
        
        return jsonify({'message': 'Request submitted successfully! Admin will review and assign a provider. Payment will be made directly to the provider.', 'request_id': new_request.id, 'amount': service.total_price})
    
    except Exception as e:
        db.session.rollback()
        print("Error in create_request:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/requests/user/<int:user_id>', methods=['GET'])
@token_required
def get_user_requests(user_id):
    try:
        if request.current_user.id != user_id and request.current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        requests = ServiceRequest.query.filter_by(user_id=user_id).order_by(ServiceRequest.created_at.desc()).all()
        result = []
        for r in requests:
            try:
                result.append({
                    'id': r.id,
                    'service_name': r.service.name if r.service else 'Unknown',
                    'amount': r.amount,
                    'provider_payout': r.provider_payout,
                    'admin_fee': r.admin_fee,
                    'site_fee': r.site_fee,
                    'status': r.status,
                    'location_address': r.location_address or '',
                    'location_city': r.location_city or '',
                    'location_region': r.location_region or '',
                    'customer_phone': r.customer_phone or '',
                    'provider_name': r.provider.full_name if r.provider else None,
                    'provider_phone': r.provider.phone if r.provider else None,
                    'rating': r.rating,
                    'customer_confirmed': r.customer_confirmed,
                    'provider_completed': r.provider_completed,
                    'created_at': r.created_at.isoformat() if r.created_at else None
                })
            except Exception as e:
                print(f"Error processing request {r.id}: {str(e)}")
                continue
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_user_requests: {str(e)}")
        return jsonify([]), 200

@app.route('/api/requests/<int:request_id>/approve-assign', methods=['PUT'])
@admin_required
def approve_and_assign_request(request_id):
    try:
        data = request.json
        print(f"📝 Approve-assign request for ID: {request_id}")
        
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        if service_request.status != 'pending_approval':
            return jsonify({'error': f'Cannot assign provider. Current status: {service_request.status}. Only pending_approval requests can be assigned.'}), 400
        
        provider_id = data.get('provider_id')
        if not provider_id:
            return jsonify({'error': 'Provider must be assigned'}), 400
        
        provider = db.session.get(User, provider_id)
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        if provider.role != 'provider':
            return jsonify({'error': 'User is not a provider'}), 400
        
        if not provider.is_verified:
            return jsonify({'error': 'Provider not verified'}), 400
        
        if provider.service_specialization_id != service_request.service_id:
            service = db.session.get(Service, service_request.service_id)
            provider_service = db.session.get(Service, provider.service_specialization_id)
            return jsonify({
                'error': f'Provider specializes in {provider_service.name if provider_service else "unknown service"}, not {service.name if service else "this service"}. Please select a provider with matching specialization.'
            }), 400
        
        service = db.session.get(Service, service_request.service_id)
        
        service_request.provider_id = provider_id
        service_request.status = 'pending_approval'
        service_request.assigned_at = datetime.utcnow()
        
        provider.total_jobs = (provider.total_jobs or 0) + 1
        
        db.session.commit()
        print(f"✅ Provider {provider.full_name} assigned to request {request_id}")
        
        create_notification(service_request.user_id, f'✅ Provider Assigned! {provider.full_name} will call you shortly for your {service.name} service. You will pay them directly after service completion.', 'success', '/customer/dashboard')
        create_notification(provider_id, f'🔔 New Job Assigned! You have been assigned to {service.name} for {service_request.user.full_name}. Contact them immediately. Customer will pay you directly.', 'job', '/provider/dashboard')
        
        socketio.emit('provider_assigned', {
            'request_id': request_id,
            'customer_id': service_request.user_id,
            'provider_id': provider_id,
            'service_name': service.name if service else 'Service'
        })
        
        socketio.emit('request_status_changed', {
            'request_id': request_id,
            'status': 'pending_approval',  # ← Change from 'assigned' to 'pending_approval'
            'user_id': service_request.user_id,
            'provider_id': provider_id
        })
        
        return jsonify({'message': 'Provider assigned successfully! Both parties have been notified.'})
    
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in approve_and_assign_request: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/requests/<int:request_id>/provider-complete', methods=['PUT'])
@token_required
def provider_complete_request(request_id):
    try:
        print(f"📝 Provider complete request for ID: {request_id}")
        
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        if service_request.provider_id != request.current_user.id:
            return jsonify({'error': 'You can only complete your own jobs'}), 403
        
        if service_request.status != 'assigned' and service_request.status != 'in_progress':
            return jsonify({'error': f'Cannot complete. Service status: {service_request.status}. Expected: assigned or in_progress'}), 400
        
        service_request.provider_completed = True
        service_request.status = 'completed'
        service_request.completed_at = datetime.utcnow()
        db.session.commit()
        
        print(f"✅ Provider marked request {request_id} as completed")
        
        create_notification(
            service_request.user_id, 
            f'✅ Provider has completed your {service_request.service.name} service. Please confirm completion and pay the provider directly.', 
            'info', 
            '/customer/dashboard'
        )
        
        socketio.emit('job_completed', {
            'request_id': request_id,
            'customer_id': service_request.user_id,
            'provider_id': service_request.provider_id,
            'service_name': service_request.service.name
        })
        
        socketio.emit('request_status_changed', {
            'request_id': request_id,
            'status': 'completed',
            'user_id': service_request.user_id,
            'provider_id': service_request.provider_id
        })
        
        return jsonify({'message': 'Service marked as completed. Awaiting customer confirmation.'})
    
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in provider_complete_request: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/requests/<int:request_id>/confirm', methods=['PUT'])
@token_required
def confirm_request_completion(request_id):
    try:
        print(f"📝 Confirm completion request for ID: {request_id}")
        
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        if service_request.user_id != request.current_user.id:
            return jsonify({'error': 'You can only confirm your own requests'}), 403
        
        if not service_request.provider_completed:
            return jsonify({'error': 'Provider has not marked service as completed yet.'}), 400
        
        service_request.customer_confirmed = True
        service_request.status = 'confirmed'
        db.session.commit()

        
        print(f"✅ Customer confirmed completion for request {request_id}")
        
        # TRIGGER REFERRAL COMMISSIONS
        commission_result = process_referral_commissions(service_request, request.current_user)

                # Notify admin that booking is confirmed and commissions processed
        socketio.emit('booking_confirmed', {
            'booking_id': request_id,
            'customer_id': service_request.user_id,
            'amount': service_request.amount,
            'commission_result': commission_result
        }, room='role_admin')

    
        if commission_result.get('success'):
            print(f"💰 Referral commissions processed: {commission_result}")
            if commission_result.get('self_bonus', 0) > 0:
                create_notification(
                    request.current_user.id,
                    f'🎉 You earned GHS{commission_result["self_bonus"]} from your first booking! Share your referral code: {request.current_user.referral_code}',
                    'success',
                    '/referrals'
                )
        
        if service_request.provider_id:
            create_notification(
                service_request.provider_id,
                f'✅ Customer confirmed completion for {service_request.service.name}. Thank you for your service!',
                'success',
                '/provider/dashboard'
            )
            
            socketio.emit('customer_confirmed', {
                'request_id': request_id,
                'provider_id': service_request.provider_id,
                'service_name': service_request.service.name
            })
            
            socketio.emit('request_status_changed', {
                'request_id': request_id,
                'status': 'confirmed',
                'user_id': service_request.user_id,
                'provider_id': service_request.provider_id
            })
        
        return jsonify({
            'message': 'Completion confirmed. Thank you for using Zivre!',
            'commission_result': commission_result
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in confirm_request_completion: {str(e)}")
        return jsonify({'error': str(e)}), 500

        

@app.route('/api/requests/<int:request_id>/rate', methods=['POST'])
@token_required
def rate_request(request_id):
    data = request.json
    service_request = db.session.get(ServiceRequest, request_id)
    if not service_request:
        return jsonify({'error': 'Request not found'}), 404
    
    if service_request.user_id != request.current_user.id:
        return jsonify({'error': 'You can only rate your own requests'}), 403
    
    service_request.rating = data.get('rating')
    db.session.commit()
    
    if service_request.provider_id:
        provider = db.session.get(User, service_request.provider_id)
        if provider:
            all_ratings = ServiceRequest.query.filter(
                ServiceRequest.provider_id == provider.id,
                ServiceRequest.rating != None
            ).all()
            
            if all_ratings:
                avg_rating = sum(r.rating for r in all_ratings) / len(all_ratings)
                provider.rating = round(avg_rating, 1)
            else:
                provider.rating = data.get('rating')
            
            db.session.commit()
    
    create_notification(service_request.user_id, f'Thank you for rating your service experience!', 'info', '/customer/dashboard')
    
    return jsonify({'message': 'Rating submitted'})

# ==================== JOB/PROVIDER ROUTES ====================

@app.route('/api/jobs/available', methods=['GET'])
@token_required
def get_available_jobs():
    if request.current_user.role != 'provider':
        return jsonify([])
    
    if not request.current_user.is_verified:
        return jsonify([])
    
    # ONLY show jobs where THIS SPECIFIC provider is assigned
    available_jobs = ServiceRequest.query.filter(
        ServiceRequest.status == 'pending_approval',
        ServiceRequest.provider_id == request.current_user.id,
        ServiceRequest.service_id == request.current_user.service_specialization_id
    ).all()
    
    return jsonify([{
        'id': req.id,
        'service_name': req.service.name,
        'customer_name': req.user.full_name,
        'customer_phone': req.customer_phone or req.user.phone,
        'location_address': req.location_address,
        'location_city': req.location_city,
        'location_region': req.location_region,
        'location_landmark': req.location_landmark,
        'amount': req.amount,
        'provider_payout': req.provider_payout
    } for req in available_jobs])

@app.route('/api/jobs/claim', methods=['POST'])
@token_required
def claim_job():
    data = request.json
    service_request = db.session.get(ServiceRequest, data.get('request_id'))
    if not service_request:
        return jsonify({'error': 'Request not found'}), 404
    
    if service_request.provider_id and service_request.provider_id != request.current_user.id:
        return jsonify({'error': 'Job already claimed by another provider'}), 400
    
    if request.current_user.role != 'provider' or not request.current_user.is_verified:
        return jsonify({'error': 'Invalid or unverified provider'}), 400
    
    if request.current_user.service_specialization_id != service_request.service_id:
        service = db.session.get(Service, service_request.service_id)
        return jsonify({
            'error': f'You specialize in {request.current_user.service_specialization.name if request.current_user.service_specialization else "unknown service"}, not {service.name if service else "this service"}.'
        }), 400
    
    service_request.provider_id = request.current_user.id
    service_request.status = 'assigned'
    service_request.assigned_at = datetime.utcnow()
    request.current_user.total_jobs = (request.current_user.total_jobs or 0) + 1
    db.session.commit()
    
    create_notification(service_request.user_id, f'✅ Provider {request.current_user.full_name} has started working on your {service_request.service.name} request.', 'success', '/customer/dashboard')
    create_notification(request.current_user.id, f'🔔 You have claimed a new job: {service_request.service.name} for {service_request.user.full_name}', 'job', '/provider/dashboard')
    
    socketio.emit('job_claimed', {
        'request_id': service_request.id,
        'provider_id': request.current_user.id,
        'customer_id': service_request.user_id
    })
    
    socketio.emit('request_status_changed', {
        'request_id': service_request.id,
        'status': 'in_progress',
        'user_id': service_request.user_id,
        'provider_id': request.current_user.id
    })
    
    return jsonify({'message': 'Job claimed successfully'})

@app.route('/api/jobs/provider/<int:provider_id>', methods=['GET'])
@token_required
def get_provider_jobs(provider_id):
    if request.current_user.id != provider_id and request.current_user.role != 'admin':
        return jsonify([])
    
    jobs = ServiceRequest.query.filter_by(provider_id=provider_id).order_by(ServiceRequest.created_at.desc()).all()
    return jsonify([{
        'id': j.id,
        'service_name': j.service.name,
        'customer_name': j.user.full_name,
        'customer_phone': j.customer_phone or j.user.phone,
        'location_address': j.location_address,
        'location_city': j.location_city,
        'location_region': j.location_region,
        'location_landmark': j.location_landmark,
        'status': j.status,
        'amount': j.amount,
        'provider_payout': j.provider_payout,
        'rating': j.rating,
        'customer_confirmed': j.customer_confirmed,
        'provider_completed': j.provider_completed,
        'created_at': j.created_at.isoformat()
    } for j in jobs])

@app.route('/api/jobs/<int:job_id>/status', methods=['PUT'])
@token_required
def update_job_status(job_id):
    data = request.json
    service_request = db.session.get(ServiceRequest, job_id)
    if not service_request:
        return jsonify({'error': 'Job not found'}), 404
    
    if service_request.provider_id != request.current_user.id:
        return jsonify({'error': 'You can only update your own jobs'}), 403
    
    new_status = data.get('status')
    if new_status == 'in_progress':
        service_request.status = 'in_progress'
        create_notification(service_request.user_id, f'Your {service_request.service.name} service is now in progress.', 'info', '/customer/dashboard')
        socketio.emit('job_started', {'request_id': job_id, 'customer_id': service_request.user_id})
        
        socketio.emit('request_status_changed', {
            'request_id': job_id,
            'status': 'in_progress',
            'user_id': service_request.user_id,
            'provider_id': service_request.provider_id
        })
    elif new_status == 'provider_completed':
        return provider_complete_request(job_id)
    else:
        return jsonify({'error': 'Invalid status'}), 400
    
    db.session.commit()
    return jsonify({'message': f'Job status updated to {new_status}'})

# ==================== NOTIFICATION ROUTES ====================

@app.route('/api/notifications/<int:user_id>', methods=['GET'])
@token_required
def get_notifications(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify([])
    
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(100).all()
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'type': n.type,
        'link': n.link,
        'read': n.read,
        'created_at': n.created_at.isoformat()
    } for n in notifications])

@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(notification_id):
    notification = db.session.get(Notification, notification_id)
    if notification and notification.user_id == request.current_user.id:
        notification.read = True
        db.session.commit()
    return jsonify({'message': 'Marked as read'})

@app.route('/api/notifications/read-all/<int:user_id>', methods=['PUT'])
@token_required
def mark_all_notifications_read_route(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    count = mark_all_notifications_read(user_id)
    return jsonify({'message': f'{count} notifications marked as read'})

@app.route('/api/notifications/delete-all/<int:user_id>', methods=['DELETE'])
@token_required
def delete_all_notifications_route(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    count = delete_all_notifications(user_id)
    return jsonify({'message': f'{count} notifications deleted'})

@app.route('/api/notifications/unread-count/<int:user_id>', methods=['GET'])
@token_required
def get_unread_count(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify({'count': 0})
    count = Notification.query.filter_by(user_id=user_id, read=False).count()
    return jsonify({'count': count})

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@token_required
def delete_notification(notification_id):
    notification = db.session.get(Notification, notification_id)
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    if notification.user_id != request.current_user.id and request.current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(notification)
    db.session.commit()
    return jsonify({'message': 'Notification deleted'})

# ==================== MESSAGING ROUTES ====================

@app.route('/api/messages', methods=['POST'])
@token_required
def send_message():
    data = request.json
    sender_id = request.current_user.id
    receiver_id = data.get('receiver_id')
    subject = data.get('subject', '')
    message_text = data.get('message')
    reply_to_id = data.get('reply_to_id')
    attachment_path = data.get('attachment_path')
    attachment_type = data.get('attachment_type')
    attachment_name = data.get('attachment_name')
    
    if not message_text and not attachment_path:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    receiver = db.session.get(User, receiver_id)
    
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
    
    if request.current_user.role == 'customer' and receiver.role == 'customer':
        return jsonify({'error': 'Customers cannot message other customers'}), 403
    
    if request.current_user.role == 'provider' and receiver.role == 'provider':
        return jsonify({'error': 'Providers cannot message other providers'}), 403
    
    if request.current_user.role == 'customer' and receiver.role == 'provider':
        assigned_job = ServiceRequest.query.filter(
            ServiceRequest.provider_id == receiver_id, 
            ServiceRequest.user_id == sender_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed'])
        ).first()
        if not assigned_job:
            return jsonify({'error': 'You can only message providers assigned to your active or completed jobs'}), 403
    
    if request.current_user.role == 'provider' and receiver.role == 'customer':
        assigned_job = ServiceRequest.query.filter(
            ServiceRequest.provider_id == sender_id, 
            ServiceRequest.user_id == receiver_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed'])
        ).first()
        if not assigned_job:
            return jsonify({'error': 'You can only message customers assigned to your active or completed jobs'}), 403
    
    new_message = Message(
        sender_id=sender_id,
        receiver_id=receiver_id,
        subject=subject,
        message=bleach.clean(message_text) if message_text else '',
        reply_to_id=reply_to_id,
        attachment_path=attachment_path,
        attachment_type=attachment_type,
        attachment_name=attachment_name
    )
    db.session.add(new_message)
    db.session.commit()
    
    create_notification(receiver_id, f'📩 New message from {request.current_user.full_name}', 'message', '/messages')
    
    socketio.emit('new_message', {
        'id': new_message.id,
        'sender_id': sender_id,
        'sender_name': request.current_user.full_name,
        'receiver_id': receiver_id,
        'message': new_message.message,
        'attachment_path': attachment_path,
        'attachment_type': attachment_type,
        'attachment_name': attachment_name,
        'reply_to_id': reply_to_id,
        'created_at': new_message.created_at.isoformat()
    }, room=f"user_{receiver_id}")
    
    return jsonify({'message': 'Message sent', 'id': new_message.id})

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@token_required
def delete_message(message_id):
    try:
        data = request.json
        delete_for_everyone = data.get('delete_for_everyone', False)
        
        message = db.session.get(Message, message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        if delete_for_everyone:
            time_since = datetime.utcnow() - message.created_at
            if time_since.total_seconds() > 300:
                return jsonify({'error': 'Delete for everyone only available within 5 minutes of sending'}), 403
            if message.sender_id != request.current_user.id:
                return jsonify({'error': 'Only the sender can delete for everyone'}), 403
            db.session.delete(message)
        else:
            if request.current_user.id == message.sender_id:
                message.is_deleted_for_sender = True
            elif request.current_user.id == message.receiver_id:
                message.is_deleted_for_receiver = True
            else:
                return jsonify({'error': 'You can only delete your own messages'}), 403
        
        db.session.commit()
        
        return jsonify({'message': 'Message deleted successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages/<int:message_id>/edit', methods=['PUT'])
@token_required
def edit_message(message_id):
    try:
        data = request.json
        new_message_text = data.get('message')
        
        if not new_message_text:
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        message = db.session.get(Message, message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        if message.sender_id != request.current_user.id:
            return jsonify({'error': 'You can only edit your own messages'}), 403
        
        time_since = datetime.utcnow() - message.created_at
        if time_since.total_seconds() > 300:
            return jsonify({'error': 'Edit window expired (5 minutes)'}), 403
        
        old_message = message.message
        message.message = bleach.clean(new_message_text)
        message.updated_at = datetime.utcnow()
        db.session.commit()
        
        socketio.emit('message_edited', {
            'message_id': message_id,
            'new_message': message.message,
            'old_message': old_message,
            'edited_at': message.updated_at.isoformat()
        }, room=f"user_{message.receiver_id}")
        
        return jsonify({'message': 'Message edited successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error editing message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages/user/<int:user_id>', methods=['GET'])
@token_required
def get_user_messages(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify([])
    
    messages = Message.query.filter(
        ((Message.sender_id == user_id) | (Message.receiver_id == user_id)),
        Message.is_deleted_for_sender == False,
        Message.is_deleted_for_receiver == False
    ).order_by(Message.created_at.desc()).all()
    
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_name': m.sender.full_name if m.sender else 'Unknown',
        'sender_role': m.sender.role if m.sender else 'unknown',
        'receiver_id': m.receiver_id,
        'receiver_name': m.receiver.full_name if m.receiver else 'Unknown',
        'receiver_role': m.receiver.role if m.receiver else 'unknown',
        'subject': m.subject,
        'message': m.message,
        'attachment_path': m.attachment_path,
        'attachment_type': m.attachment_type,
        'attachment_name': m.attachment_name,
        'reply_to_id': m.reply_to_id,
        'is_read': m.is_read,
        'is_delivered': m.is_delivered,
        'created_at': m.created_at.isoformat(),
        'updated_at': m.updated_at.isoformat() if m.updated_at else None
    } for m in messages])

@app.route('/api/messages/<int:message_id>/read', methods=['PUT'])
@token_required
def mark_message_read(message_id):
    message = db.session.get(Message, message_id)
    if message and message.receiver_id == request.current_user.id:
        message.is_read = True
        message.read_at = datetime.utcnow()
        db.session.commit()
        
        socketio.emit('message_read', {
            'message_id': message_id,
            'sender_id': message.sender_id
        }, room=f"user_{message.sender_id}")
    
    return jsonify({'message': 'Message marked as read'})

@app.route('/api/messages/unread/<int:user_id>', methods=['GET'])
@token_required
def get_unread_messages_count(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify({'count': 0})
    count = Message.query.filter_by(receiver_id=user_id, is_read=False).count()
    return jsonify({'count': count})

@app.route('/api/messages/conversation/<int:user1>/<int:user2>', methods=['GET'])
@token_required
def get_conversation(user1, user2):
    if request.current_user.id != user1 and request.current_user.id != user2 and request.current_user.role != 'admin':
        return jsonify([])
    
    messages = Message.query.filter(
        ((Message.sender_id == user1) & (Message.receiver_id == user2)) |
        ((Message.sender_id == user2) & (Message.receiver_id == user1)),
        Message.is_deleted_for_sender == False,
        Message.is_deleted_for_receiver == False
    ).order_by(Message.created_at.asc()).all()
    
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_name': m.sender.full_name if m.sender else 'Unknown',
        'sender_role': m.sender.role if m.sender else 'unknown',
        'receiver_id': m.receiver_id,
        'receiver_name': m.receiver.full_name if m.receiver else 'Unknown',
        'receiver_role': m.receiver.role if m.receiver else 'unknown',
        'subject': m.subject,
        'message': m.message,
        'attachment_path': m.attachment_path,
        'attachment_type': m.attachment_type,
        'attachment_name': m.attachment_name,
        'reply_to_id': m.reply_to_id,
        'is_read': m.is_read,
        'is_delivered': m.is_delivered,
        'created_at': m.created_at.isoformat(),
        'updated_at': m.updated_at.isoformat() if m.updated_at else None
    } for m in messages])

# ==================== CONTACTS ROUTE ====================

@app.route('/api/contacts/<int:user_id>', methods=['GET'])
@token_required
def get_contacts(user_id):
    if request.current_user.id != user_id and request.current_user.role != 'admin':
        return jsonify([])
    
    current_user = request.current_user
    contacts = []
    all_users = User.query.filter(User.id != user_id).all()
    
    if current_user.role == 'admin':
        for u in all_users:
            contacts.append({
                'id': u.id, 
                'full_name': u.full_name, 
                'role': u.role, 
                'rating': u.rating, 
                'total_jobs': u.total_jobs,
                'email': u.email,
                'phone': u.phone,
                'is_verified': u.is_verified,
                'is_online': u.is_online_manual,
                'last_seen': u.last_seen.isoformat() if u.last_seen else None,
                'service_specialization': u.service_specialization.name if u.service_specialization else None
            })
    
    elif current_user.role == 'provider':
        admin = User.query.filter_by(role='admin').first()
        if admin and admin.id != user_id:
            contacts.append({
                'id': admin.id, 
                'full_name': admin.full_name, 
                'role': admin.role,
                'rating': admin.rating, 
                'total_jobs': admin.total_jobs,
                'email': admin.email, 
                'phone': admin.phone, 
                'is_verified': admin.is_verified,
                'is_online': admin.is_online_manual,
                'last_seen': admin.last_seen.isoformat() if admin.last_seen else None
            })
        
        active_jobs = ServiceRequest.query.filter(
            ServiceRequest.provider_id == user_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed'])
        ).all()
        
        customer_ids = set()
        for job in active_jobs:
            if job.user_id and job.user_id not in customer_ids:
                customer_ids.add(job.user_id)
                customer = db.session.get(User, job.user_id)
                if customer:
                    contacts.append({
                        'id': customer.id, 
                        'full_name': customer.full_name, 
                        'role': customer.role,
                        'rating': customer.rating, 
                        'total_jobs': customer.total_jobs,
                        'email': customer.email, 
                        'phone': customer.phone, 
                        'is_verified': customer.is_verified,
                        'is_online': customer.is_online_manual,
                        'last_seen': customer.last_seen.isoformat() if customer.last_seen else None
                    })
    
    elif current_user.role == 'customer':
        admin = User.query.filter_by(role='admin').first()
        if admin and admin.id != user_id:
            contacts.append({
                'id': admin.id, 
                'full_name': admin.full_name, 
                'role': admin.role,
                'rating': admin.rating, 
                'total_jobs': admin.total_jobs,
                'email': admin.email, 
                'phone': admin.phone, 
                'is_verified': admin.is_verified,
                'is_online': admin.is_online_manual,
                'last_seen': admin.last_seen.isoformat() if admin.last_seen else None
            })
        
        active_requests = ServiceRequest.query.filter(
            ServiceRequest.user_id == user_id,
            ServiceRequest.status.in_(['assigned', 'in_progress', 'completed', 'confirmed']),
            ServiceRequest.provider_id != None
        ).all()
        
        provider_ids = set()
        for req in active_requests:
            if req.provider_id and req.provider_id not in provider_ids:
                provider_ids.add(req.provider_id)
                provider = db.session.get(User, req.provider_id)
                if provider:
                    contacts.append({
                        'id': provider.id, 
                        'full_name': provider.full_name, 
                        'role': provider.role,
                        'rating': provider.rating, 
                        'total_jobs': provider.total_jobs,
                        'email': provider.email, 
                        'phone': provider.phone, 
                        'is_verified': provider.is_verified,
                        'is_online': provider.is_online_manual,
                        'last_seen': provider.last_seen.isoformat() if provider.last_seen else None,
                        'service_specialization': provider.service_specialization.name if provider.service_specialization else None
                    })
    
    return jsonify(contacts)

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_all_users():
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'full_name': u.full_name,
        'email': u.email,
        'phone': u.phone,
        'role': u.role,
        'is_active': u.is_active,
        'is_verified': u.is_verified,
        'rating': u.rating,
        'total_jobs': u.total_jobs,
        'created_at': u.created_at.isoformat(),
        'service_specialization': u.service_specialization.name if u.service_specialization else None
    } for u in users])

@app.route('/api/admin/users/<int:user_id>/full-details', methods=['GET'])
@admin_required
def get_user_full_details(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.role == 'customer':
        requests = ServiceRequest.query.filter_by(user_id=user_id).all()
        total_spent = sum(r.amount for r in requests)
        completed_requests = [r for r in requests if r.status == 'confirmed']
        
        requests_data = [{
            'id': r.id,
            'service_name': r.service.name if r.service else 'Unknown',
            'amount': r.amount,
            'status': r.status,
            'provider_name': r.provider.full_name if r.provider else None,
            'created_at': r.created_at.isoformat(),
            'completed_at': r.completed_at.isoformat() if r.completed_at else None
        } for r in requests]
        
        return jsonify({
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone': user.phone,
            'role': user.role,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'rating': user.rating,
            'total_jobs': user.total_jobs,
            'created_at': user.created_at.isoformat(),
            'last_seen': user.last_seen.isoformat() if user.last_seen else None,
            'is_online': user.is_online_manual,
            'total_spent': total_spent,
            'total_requests': len(requests),
            'completed_requests_count': len(completed_requests),
            'service_requests': requests_data
        })
    
    elif user.role == 'provider':
        jobs = ServiceRequest.query.filter_by(provider_id=user_id).all()
        total_earned = sum(j.provider_payout for j in jobs if j.status == 'confirmed')
        completed_jobs = [j for j in jobs if j.status == 'confirmed']
        
        jobs_data = [{
            'id': j.id,
            'service_name': j.service.name if j.service else 'Unknown',
            'amount': j.amount,
            'provider_payout': j.provider_payout,
            'status': j.status,
            'customer_name': j.user.full_name if j.user else None,
            'created_at': j.created_at.isoformat(),
            'completed_at': j.completed_at.isoformat() if j.completed_at else None,
            'rating': j.rating
        } for j in jobs]
        
        return jsonify({
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone': user.phone,
            'role': user.role,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'rating': user.rating,
            'total_jobs': user.total_jobs,
            'created_at': user.created_at.isoformat(),
            'last_seen': user.last_seen.isoformat() if user.last_seen else None,
            'is_online': user.is_online_manual,
            'total_earned': total_earned,
            'total_jobs_count': len(jobs),
            'completed_jobs_count': len(completed_jobs),
            'service_specialization': user.service_specialization.name if user.service_specialization else None,
            'jobs': jobs_data
        })
    
    else:
        return jsonify({
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone': user.phone,
            'role': user.role,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'rating': user.rating,
            'total_jobs': user.total_jobs,
            'created_at': user.created_at.isoformat(),
            'last_seen': user.last_seen.isoformat() if user.last_seen else None,
            'is_online': user.is_online_manual
        })

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.role == 'admin':
            return jsonify({'error': 'Cannot delete admin user'}), 403
        
        # Delete related records safely
        try:
            ServiceRequest.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting service requests: {e}")
            
        try:
            ServiceRequest.query.filter_by(provider_id=user_id).update({'provider_id': None})
        except Exception as e:
            print(f"Error updating provider requests: {e}")
            
        try:
            Notification.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting notifications: {e}")
            
        try:
            Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
        except Exception as e:
            print(f"Error deleting messages: {e}")
            
        try:
            Comment.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting comments: {e}")
            
        try:
            CommentReply.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting comment replies: {e}")
        
        # Also delete commission records
        try:
            Commission.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting commissions: {e}")
        
        # Also delete withdrawal requests
        try:
            WithdrawalRequest.query.filter_by(user_id=user_id).delete()
        except Exception as e:
            print(f"Error deleting withdrawal requests: {e}")
        
        db.session.delete(user)
        db.session.commit()
        
        socketio.emit('user_deleted', {'user_id': user_id})
        socketio.emit('users_updated', {})
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'error': f'Error deleting user: {str(e)}'}), 500
        

@app.route('/api/admin/users/<int:user_id>/verify', methods=['PUT'])
@admin_required
def verify_provider(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.role != 'provider':
            return jsonify({'error': 'Only providers can be verified'}), 400
        
        user.is_verified = True
        db.session.commit()
        
        try:
            create_notification(user_id, '✅ Your provider account has been verified! You can now claim jobs.', 'success', '/provider/dashboard')
        except Exception as e:
            print(f"Notification error (non-critical): {e}")
        
        try:
            socketio.emit('user_verified', {
                'user_id': user_id,
                'is_verified': True
            })
            socketio.emit('users_updated', {})
        except Exception as e:
            print(f"SocketIO error (non-critical): {e}")
        
        return jsonify({'message': 'Provider verified successfully', 'is_verified': True})
    
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in verify_provider: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['PUT'])
@admin_required
def suspend_user(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.role == 'admin':
            return jsonify({'error': 'Cannot suspend admin users'}), 403
        
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'suspended' if not user.is_active else 'activated'
        
        try:
            create_notification(user_id, f'⚠️ Your account has been {status}.', 'warning', '/')
        except Exception as e:
            print(f"Notification error (non-critical): {e}")
        
        try:
            socketio.emit('user_suspended', {
                'user_id': user_id,
                'is_active': user.is_active
            })
            socketio.emit('users_updated', {})
        except Exception as e:
            print(f"SocketIO error (non-critical): {e}")
        
        return jsonify({'message': f'User {status} successfully', 'is_active': user.is_active})
    
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in suspend_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/requests', methods=['GET'])
@admin_required
def get_all_requests():
    requests = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    return jsonify([{
        'id': r.id,
        'user_id': r.user_id,
        'customer_name': r.user.full_name if r.user else 'Unknown',
        'customer_phone': r.customer_phone or (r.user.phone if r.user else 'Unknown'),
        'service_name': r.service.name if r.service else 'Unknown',
        'service_id': r.service_id,
        'amount': r.amount,
        'provider_payout': r.provider_payout,
        'admin_fee': r.admin_fee,
        'site_fee': r.site_fee,
        'status': r.status,
        'location_address': r.location_address,
        'location_city': r.location_city,
        'location_region': r.location_region,
        'location_landmark': r.location_landmark,
        'provider_name': r.provider.full_name if r.provider else None,
        'provider_id': r.provider_id,
        'customer_confirmed': r.customer_confirmed,
        'provider_completed': r.provider_completed,
        'created_at': r.created_at.isoformat(),
        'assigned_at': r.assigned_at.isoformat() if r.assigned_at else None,
        'completed_at': r.completed_at.isoformat() if r.completed_at else None
    } for r in requests])

@app.route('/api/admin/providers', methods=['GET'])
@admin_required
def get_available_providers():
    service_id = request.args.get('service_id', type=int)
    
    # ✅ Only select needed fields - excludes password, email, etc. for SPEED
    if service_id:
        providers = db.session.query(
            User.id, 
            User.full_name, 
            User.rating, 
            User.total_jobs,
            Service.name.label('service_specialization')
        ).join(
            Service, User.service_specialization_id == Service.id
        ).filter(
            User.role == 'provider',
            User.is_verified == True,
            User.is_active == True,
            User.service_specialization_id == service_id
        ).limit(50).all()  # ✅ Limit to 50 providers for SPEED
    else:
        providers = db.session.query(
            User.id, 
            User.full_name, 
            User.rating, 
            User.total_jobs,
            Service.name.label('service_specialization')
        ).join(
            Service, User.service_specialization_id == Service.id
        ).filter(
            User.role == 'provider',
            User.is_verified == True,
            User.is_active == True
        ).limit(50).all()  # ✅ Limit to 50 providers for SPEED
    
    return jsonify([{
        'id': p.id,
        'full_name': p.full_name,
        'rating': float(p.rating) if p.rating else 0,
        'total_jobs': p.total_jobs or 0,
        'service_specialization': p.service_specialization
    } for p in providers])

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    total_users = User.query.count()
    total_customers = User.query.filter_by(role='customer').count()
    total_providers = User.query.filter_by(role='provider').count()
    total_requests = ServiceRequest.query.count()
    pending_approval = ServiceRequest.query.filter_by(status='pending_approval').count()
    assigned_requests = ServiceRequest.query.filter_by(status='assigned').count()
    in_progress = ServiceRequest.query.filter_by(status='in_progress').count()
    completed_requests = ServiceRequest.query.filter_by(status='completed').count()
    confirmed_requests = ServiceRequest.query.filter_by(status='confirmed').count()
    total_quotes = Quote.query.count()
    active_services = Service.query.filter_by(is_active=True).count()
    total_comments = Comment.query.count()
    
    # ONLY count revenue from completed jobs (when provider marks complete)
    completed_requests_list = ServiceRequest.query.filter(ServiceRequest.status.in_(['completed', 'confirmed'])).all()
    total_revenue = sum(r.amount for r in completed_requests_list)
    total_admin_fees = sum(r.admin_fee for r in completed_requests_list)
    total_site_fees = sum(r.site_fee for r in completed_requests_list)
    total_provider_payouts = sum(r.provider_payout for r in completed_requests_list)
    
    return jsonify({
        'total_users': total_users,
        'total_customers': total_customers,
        'total_providers': total_providers,
        'total_requests': total_requests,
        'pending_approval': pending_approval,
        'assigned_requests': assigned_requests,
        'in_progress': in_progress,
        'completed_requests': completed_requests,
        'confirmed_requests': confirmed_requests,
        'total_quotes': total_quotes,
        'active_services': active_services,
        'total_comments': total_comments,
        'total_revenue': total_revenue,
        'total_admin_fees': total_admin_fees,
        'total_site_fees': total_site_fees,
        'total_provider_payouts': total_provider_payouts
    })

# ==================== PAYMENT SETTINGS ROUTES ====================

@app.route('/api/admin/payment-settings', methods=['GET'])
def get_payment_settings():
    payment_number = SystemSetting.query.filter_by(key='payment_number').first()
    momopay_number = SystemSetting.query.filter_by(key='momopay_number').first()
    support_number = SystemSetting.query.filter_by(key='support_number').first()
    whatsapp_number = SystemSetting.query.filter_by(key='whatsapp_number').first()
    
    return jsonify({
        'payment_number': payment_number.value if payment_number else '024 000 0000',
        'momopay_number': momopay_number.value if momopay_number else '024 000 0000',
        'support_number': support_number.value if support_number else '050 000 0000',
        'whatsapp_number': whatsapp_number.value if whatsapp_number else '233500000000'
    })

@app.route('/api/admin/payment-settings', methods=['PUT'])
@admin_required
def update_payment_settings():
    data = request.json
    
    payment_number = SystemSetting.query.filter_by(key='payment_number').first()
    if payment_number:
        payment_number.value = data.get('payment_number', payment_number.value)
    else:
        payment_number = SystemSetting(key='payment_number', value=data.get('payment_number', '024 000 0000'))
        db.session.add(payment_number)
    
    momopay_number = SystemSetting.query.filter_by(key='momopay_number').first()
    if momopay_number:
        momopay_number.value = data.get('momopay_number', momopay_number.value)
    else:
        momopay_number = SystemSetting(key='momopay_number', value=data.get('momopay_number', '024 000 0000'))
        db.session.add(momopay_number)
    
    support_number = SystemSetting.query.filter_by(key='support_number').first()
    if support_number:
        support_number.value = data.get('support_number', support_number.value)
    else:
        support_number = SystemSetting(key='support_number', value=data.get('support_number', '050 000 0000'))
        db.session.add(support_number)
    
    whatsapp_number = SystemSetting.query.filter_by(key='whatsapp_number').first()
    if whatsapp_number:
        whatsapp_number.value = data.get('whatsapp_number', whatsapp_number.value)
    else:
        whatsapp_number = SystemSetting(key='whatsapp_number', value=data.get('whatsapp_number', '233500000000'))
        db.session.add(whatsapp_number)
    
    db.session.commit()
    
    socketio.emit('payment_settings_updated', {
        'payment_number': payment_number.value,
        'momopay_number': momopay_number.value,
        'support_number': support_number.value,
        'whatsapp_number': whatsapp_number.value
    })
    
    return jsonify({'message': 'Payment settings updated successfully'})

# ==================== SESSION KEEP ALIVE ====================

@app.route('/api/auth/ping', methods=['GET'])
@token_required
def ping():
    return jsonify({'message': 'session active', 'user_id': request.current_user.id})

# ==================== INITIAL DATA ====================
# ==================== INITIAL DATA ====================

def init_db():
    db.create_all()
    
    # ============================================
    # REFERRAL SYSTEM - AUTO CREATE TABLES & COLUMNS
    # ============================================
    
    # 1. Add referral columns to users table
    try:
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS referrer_id INTEGER'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(32) UNIQUE'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_referral_active BOOLEAN DEFAULT false'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS commission_balance DECIMAL(12,2) DEFAULT 0'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS total_earned DECIMAL(12,2) DEFAULT 0'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS position VARCHAR(10)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_users_referrer_id ON users(referrer_id)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)'))
        db.session.commit()
        print("✅ Referral columns added to users table")
    except Exception as e:
        print(f"⚠️ Users columns note: {e}")
    
    # 2. Add share columns to services table
    try:
        db.session.execute(text('ALTER TABLE services ADD COLUMN IF NOT EXISTS admin_share_percent DECIMAL(5,2) DEFAULT 10.0'))
        db.session.execute(text('ALTER TABLE services ADD COLUMN IF NOT EXISTS website_share_percent DECIMAL(5,2) DEFAULT 10.0'))
        db.session.execute(text('ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_share_percent DECIMAL(5,2) DEFAULT 80.0'))
        db.session.execute(text('ALTER TABLE services ADD COLUMN IF NOT EXISTS referral_pool_percent DECIMAL(5,2) DEFAULT 10.0'))
        db.session.commit()
        print("✅ Share columns added to services table")
    except Exception as e:
        print(f"⚠️ Services columns note: {e}")
    
    # 3. Add referral_pool_amount to services table
    try:
        db.session.execute(text('ALTER TABLE services ADD COLUMN IF NOT EXISTS referral_pool_amount DECIMAL(12,2) DEFAULT 0'))
        db.session.commit()
        print("✅ referral_pool_amount added to services table")
    except Exception as e:
        print(f"⚠️ services column note: {e}")
    
    # 4. Add referral tracking to service_requests
    try:
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS referral_pool_amount DECIMAL(12,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS total_commissions_paid DECIMAL(12,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS owner_net DECIMAL(12,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS admin_share_percent_snapshot DECIMAL(5,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS website_share_percent_snapshot DECIMAL(5,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS provider_share_percent_snapshot DECIMAL(5,2)'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS commissions_processed BOOLEAN DEFAULT false'))
        db.session.execute(text('ALTER TABLE service_requests ADD COLUMN IF NOT EXISTS referral_pool_percent_snapshot DECIMAL(5,2)'))
        db.session.commit()
        print("✅ Referral tracking columns added to service_requests")
    except Exception as e:
        print(f"⚠️ Service requests columns note: {e}")

    # 5. Add email verification columns to users table
    try:
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(100)'))
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_expiry TIMESTAMP'))
        db.session.commit()
        print("✅ Email verification columns added to users table")
    except Exception as e:
        print(f"⚠️ Verification columns note: {e}")
        
    # 6. Create commissions table
    try:
        db.session.execute(text('''
            CREATE TABLE IF NOT EXISTS commissions (
                id SERIAL PRIMARY KEY,
                booking_id INTEGER REFERENCES service_requests(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                level INTEGER,
                amount DECIMAL(12,2),
                created_at TIMESTAMP DEFAULT NOW()
            )
        '''))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_commissions_booking_id ON commissions(booking_id)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_commissions_user_id ON commissions(user_id)'))
        db.session.commit()
        print("✅ Commissions table created")
    except Exception as e:
        print(f"⚠️ Commissions table note: {e}")
    
    # 7. Create withdrawal_requests table
    try:
        db.session.execute(text('''
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                amount DECIMAL(12,2),
                payment_method VARCHAR(20),
                account_details TEXT,
                status VARCHAR(20) DEFAULT 'pending',
                requested_at TIMESTAMP DEFAULT NOW(),
                admin_processed_at TIMESTAMP,
                user_confirmed_at TIMESTAMP,
                admin_notes TEXT
            )
        '''))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON withdrawal_requests(user_id)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON withdrawal_requests(status)'))
        db.session.commit()
        print("✅ Withdrawal requests table created")
    except Exception as e:
        print(f"⚠️ Withdrawal requests table note: {e}")
    
    # 8. Update existing services with default shares
    try:
        db.session.execute(text('''
            UPDATE services SET 
                admin_share_percent = 10.0,
                website_share_percent = 10.0,
                provider_share_percent = 80.0,
                referral_pool_percent = 10.0,
                referral_pool_amount = total_price * 10.0 / 100
            WHERE admin_share_percent IS NULL
        '''))
        db.session.commit()
        print("✅ Default shares updated for services")
    except Exception as e:
        print(f"⚠️ Services update note: {e}")
    
    # 9. Generate referral codes for existing users who don't have one
    try:
        db.session.execute(text('''
            UPDATE users SET referral_code = UPPER(SUBSTRING(MD5(id::TEXT) FROM 1 FOR 8))
            WHERE referral_code IS NULL
        '''))
        db.session.commit()
        print("✅ Referral codes generated for existing users")
    except Exception as e:
        print(f"⚠️ Referral codes note: {e}")
    
    # ============================================
    # END OF REFERRAL SYSTEM MIGRATION
    # ============================================
    
    # ========== YOUR EXISTING CODE CONTINUES BELOW ==========
    
    if not PercentageSetting.query.first():
        default_percentages = PercentageSetting(
            provider_percent=60.0,
            admin_percent=20.0,
            site_fee_percent=10.0,
            referral_pool_percent=10.0
        )
        db.session.add(default_percentages)
    
    try:
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",
            "CREATE INDEX IF NOT EXISTS idx_requests_user_id ON service_requests(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_requests_provider_id ON service_requests(provider_id)",
            "CREATE INDEX IF NOT EXISTS idx_requests_status ON service_requests(status)",
            "CREATE INDEX IF NOT EXISTS idx_requests_created_at ON service_requests(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_receiver_id ON messages(receiver_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_comments_is_approved ON comments(is_approved)",
        ]
        
        for index_sql in indexes:
            try:
                db.session.execute(text(index_sql))
            except Exception as e:
                print(f"⚠️ Index creation warning: {e}")
        
        db.session.commit()
        print("✅ Database indexes created successfully")
    except Exception as e:
        print(f"⚠️ Index creation warning: {e}")
    
    if 'sqlite' in str(db.engine.url):
        try:
            db.session.execute(text('PRAGMA journal_mode=WAL'))
            db.session.commit()
            print("✅ WAL mode enabled")
        except Exception as e:
            print(f"⚠️ WAL mode warning: {e}")
    
    default_services = [
        ('HVAC Systems', 'Heating, ventilation, and air conditioning maintenance and repair', 500, '❄️'),
        ('Electrical', 'Complete electrical installations, repairs, and safety checks', 400, '⚡'),
        ('Plumbing', 'Pipe installations, leak repairs, and drainage solutions', 350, '💧'),
        ('Fire Safety', 'Fire alarm systems, extinguishers, and safety equipment', 600, '🔥'),
        ('Cleaning', 'Professional cleaning for homes and businesses across Ghana', 250, '🧹'),
        ('Security', 'CCTV, access control, and security systems monitoring', 550, '🔒'),
        ('Waste Management', 'Eco-friendly waste disposal and recycling solutions', 300, '🗑️'),
        ('Reception', 'Front desk and reception management services', 450, '📋'),
        ('Industry Services', 'Industrial facility maintenance and operations support', 700, '🏭'),
        ('Healthcare', 'Medical facility cleaning and specialized maintenance', 650, '🏥'),
        ('Poultry & Agri', 'Agricultural and poultry farm facility management', 500, '🐔'),
        ('Hospitality', 'Hotel and restaurant facility solutions', 550, '🏨'),
        ('Wellness', 'Spa, gym, and wellness center maintenance', 480, '🧘')
    ]
    
    percentages = get_current_percentages()
    created_services = []
    
    for name, desc, price, icon in default_services:
        existing = Service.query.filter_by(name=name).first()
        if not existing:
            provider_payout = price * (percentages.provider_percent / 100)
            admin_fee = price * (percentages.admin_percent / 100)
            site_fee = price * (percentages.site_fee_percent / 100)
            referral_pool_amount = price * (percentages.referral_pool_percent / 100)
            
            service = Service(
                name=name, 
                description=desc, 
                total_price=price,
                provider_payout=provider_payout,
                admin_fee=admin_fee,
                site_fee=site_fee,
                referral_pool_amount=referral_pool_amount,
                icon=icon, 
                is_active=False
            )
            db.session.add(service)
            created_services.append(service)
    
    admin = User.query.filter_by(email='admin@zivre.com').first()
    if not admin:
        admin = User(
            email='admin@zivre.com',
            password=generate_password_hash('Admin123!'),
            full_name='Admin User',
            phone='+233000000000',
            role='admin',
            is_verified=True,
            is_active=True,
            email_verified=True,           # ← ADD THIS
            verification_token=None,        # ← ADD THIS
            verification_token_expiry=None  # ← ADD THIS
        )
        db.session.add(admin)
    else:
        admin.is_active = True
        admin.is_verified = True
        admin.email_verified = True         # ← ADD THIS
        admin.verification_token = None     # ← ADD THIS
        admin.verification_token_expiry = None  # ← ADD THIS
        if not check_password_hash(admin.password, 'Admin123!'):
            admin.password = generate_password_hash('Admin123!')
        db.session.add(admin)
    
    hvac_service = Service.query.filter_by(name='HVAC Systems').first()
    
    sample_provider = User.query.filter_by(email='provider@test.com').first()
    if not sample_provider:
        sample_provider = User(
            email='provider@test.com',
            password=generate_password_hash('Provider123!'),
            full_name='Test Provider',
            phone='+233500000000',
            role='provider',
            is_verified=True,
            is_active=True,
            service_specialization_id=hvac_service.id if hvac_service else None,
            email_verified=True,           # ← ADD THIS
            verification_token=None,        # ← ADD THIS
            verification_token_expiry=None  # ← ADD THIS
        )
        db.session.add(sample_provider)
        print("✅ Created new test provider")
    else:
        sample_provider.is_verified = True
        sample_provider.is_active = True
        sample_provider.email_verified = True      # ← ADD THIS
        sample_provider.verification_token = None  # ← ADD THIS
        sample_provider.verification_token_expiry = None  # ← ADD THIS
        if hvac_service:
            sample_provider.service_specialization_id = hvac_service.id
        sample_provider.password = generate_password_hash('Provider123!')
        db.session.add(sample_provider)
        print("✅ Updated existing test provider with correct password")
    
    db.session.commit()
    
    payment_number = SystemSetting.query.filter_by(key='payment_number').first()
    if not payment_number:
        payment_number = SystemSetting(key='payment_number', value='024 000 0000')
        db.session.add(payment_number)
    
    momopay_number = SystemSetting.query.filter_by(key='momopay_number').first()
    if not momopay_number:
        momopay_number = SystemSetting(key='momopay_number', value='024 000 0000')
        db.session.add(momopay_number)
    
    support_number = SystemSetting.query.filter_by(key='support_number').first()
    if not support_number:
        support_number = SystemSetting(key='support_number', value='050 000 0000')
        db.session.add(support_number)
    
    whatsapp_number = SystemSetting.query.filter_by(key='whatsapp_number').first()
    if not whatsapp_number:
        whatsapp_number = SystemSetting(key='whatsapp_number', value='233500000000')
        db.session.add(whatsapp_number)

    db.session.commit()
    print("✅ Database initialized successfully!")

# ==================== INITIALIZE DATABASE ====================
with app.app_context():
    init_db()

@app.route('/api/debug/session', methods=['GET'])
@token_required
def debug_session():
    return jsonify({
        'session_user_id': request.current_user.id,
        'email': request.current_user.email,
        'role': request.current_user.role,
        'is_active': request.current_user.is_active,
        'is_verified': request.current_user.is_verified
    })
# ====================  ====================    
@app.route('/api/requests/<int:request_id>/cancel', methods=['PUT'])
@token_required
def cancel_request(request_id):
    try:
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        if service_request.user_id != request.current_user.id:
            return jsonify({'error': 'You can only cancel your own requests'}), 403
        
        if service_request.status not in ['pending_approval', 'assigned']:
            return jsonify({'error': f'Cannot cancel. Current status: {service_request.status}'}), 400
        
        service_request.status = REQUEST_STATUS_CANCELLED_BY_CUSTOMER
        db.session.commit()
        
        if service_request.provider_id:
            create_notification(
                service_request.provider_id,
                f'❌ Customer cancelled the {service_request.service.name} job.',
                'warning',
                '/provider/dashboard'
            )
        
        admin = User.query.filter_by(role='admin').first()
        if admin:
            create_notification(
                admin.id,
                f'📝 Request #{request_id} for {service_request.service.name} was cancelled by customer.',
                'info',
                '/admin/dashboard'
            )
        
        return jsonify({'message': 'Request cancelled successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in cancel_request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/requests/<int:request_id>/reject', methods=['PUT'])
@admin_required
def reject_request(request_id):
    try:
        data = request.json
        reason = data.get('reason', 'No reason provided')
        
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        if service_request.status != 'pending_approval':
            return jsonify({'error': f'Cannot reject. Current status: {service_request.status}'}), 400
        
        service_request.status = REQUEST_STATUS_REJECTED_BY_ADMIN
        db.session.commit()
        
        create_notification(
            service_request.user_id,
            f'❌ Your request for {service_request.service.name} was rejected. Reason: {reason}',
            'error',
            '/customer/dashboard'
        )
        
        return jsonify({'message': 'Request rejected successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in reject_request: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs/<int:job_id>/decline', methods=['PUT'])
@token_required
def decline_job(job_id):
    try:
        data = request.json
        reason = data.get('reason', 'No reason provided')
        
        service_request = db.session.get(ServiceRequest, job_id)
        if not service_request:
            return jsonify({'error': 'Job not found'}), 404
        
        if service_request.provider_id != request.current_user.id:
            return jsonify({'error': 'You can only decline jobs assigned to you'}), 403
        
        if service_request.status not in ['assigned', 'in_progress']:
            return jsonify({'error': f'Cannot decline. Current status: {service_request.status}'}), 400
        
        service_request.provider_id = None
        service_request.status = 'pending_approval'
        db.session.commit()
        
        create_notification(
            service_request.user_id,
            f'⚠️ Provider declined your {service_request.service.name} request. Reason: {reason}. Admin will assign another provider.',
            'warning',
            '/customer/dashboard'
        )
        
        admin = User.query.filter_by(role='admin').first()
        if admin:
            create_notification(
                admin.id,
                f'⚠️ Provider declined job #{job_id}. Please reassign.',
                'warning',
                '/admin/dashboard'
            )
        
        return jsonify({'message': 'Job declined successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in decline_job: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/admin/requests/<int:request_id>/delete', methods=['DELETE'])
@admin_required
def delete_request_permanently(request_id):
    try:
        service_request = db.session.get(ServiceRequest, request_id)
        if not service_request:
            return jsonify({'error': 'Request not found'}), 404
        
        customer_id = service_request.user_id
        service_name = service_request.service.name if service_request.service else 'Unknown'
        
        db.session.delete(service_request)
        db.session.commit()
        
        create_notification(
            customer_id,
            f'🗑️ Your request for {service_name} has been deleted by admin.',
            'warning',
            '/customer/dashboard'
        )
        
        return jsonify({'message': 'Request permanently deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in delete_request_permanently: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ==================== REFERRAL ENDPOINTS ====================

@app.route('/api/referrals/my-info', methods=['GET'])
@token_required
def get_my_referral_info():
    user = request.current_user
    frontend_url = os.environ.get('FRONTEND_URL', 'https://zivre-frontend.vercel.app')
    
    return jsonify({
        'referral_code': user.referral_code,
        'referral_link': f"{frontend_url}/signup?ref={user.referral_code}",
        'commission_balance': float(user.commission_balance or 0),
        'total_earned': float(user.total_earned or 0),
        'is_referral_active': user.is_referral_active,
        'referrer_id': user.referrer_id,
        'position': user.position
    })

@app.route('/api/referrals/my-tree', methods=['GET'])
@token_required
def get_my_referral_tree():
    user = request.current_user
    
    def build_tree(u, depth=0, max_depth=5):
        if depth > max_depth:
            return None
        
        children = User.query.filter_by(referrer_id=u.id).all()
        
        return {
            'id': u.id,
            'full_name': u.full_name,
            'email': u.email,
            'commission_balance': float(u.commission_balance or 0),
            'is_referral_active': u.is_referral_active,
            'total_earned': float(u.total_earned or 0),
            'position': u.position,
            'children': [build_tree(child, depth + 1, max_depth) for child in children],
            'depth': depth
        }
    
    tree = build_tree(user)
    
    return jsonify({'tree': tree})

@app.route('/api/referrals/commission-history', methods=['GET'])
@token_required
def get_commission_history():
    user = request.current_user
    
    commissions = Commission.query.filter_by(user_id=user.id).order_by(Commission.created_at.desc()).limit(100).all()
    
    return jsonify([{
        'id': c.id,
        'booking_id': c.booking_id,
        'level': c.level,
        'amount': float(c.amount),
        'created_at': c.created_at.isoformat(),
        'service_name': c.booking.service.name if c.booking and c.booking.service else 'Unknown',
        'booking_amount': float(c.booking.amount) if c.booking else 0
    } for c in commissions])

@app.route('/api/referrals/withdraw', methods=['POST'])
@token_required
def request_withdrawal():
    data = request.json
    user = request.current_user
    
    # Check if user has any pending or admin_sent withdrawal
    pending_withdrawal = WithdrawalRequest.query.filter(
        WithdrawalRequest.user_id == user.id,
        WithdrawalRequest.status.in_(['pending', 'admin_sent'])
    ).first()
    
    if pending_withdrawal:
        return jsonify({
            'error': f'You have a withdrawal with status "{pending_withdrawal.status}". Please confirm or wait for processing before requesting a new withdrawal.'
        }), 400
    
    amount = data.get('amount', 0)
    payment_method = data.get('payment_method')
    account_details = data.get('account_details')
    
    if not amount or amount < WITHDRAWAL_THRESHOLD_GHS:
        return jsonify({'error': f'Minimum withdrawal amount is GHS{WITHDRAWAL_THRESHOLD_GHS}'}), 400
    
    if amount > (user.commission_balance or 0):
        return jsonify({'error': 'Insufficient balance'}), 400
    
    if not payment_method or not account_details:
        return jsonify({'error': 'Payment method and account details are required'}), 400
    
    # DO NOT deduct balance here - deduct only when user confirms receipt
    withdrawal = WithdrawalRequest(
        user_id=user.id,
        amount=amount,
        payment_method=payment_method,
        account_details=account_details,
        status='pending'
    )
    
    db.session.add(withdrawal)
    db.session.commit()
    
    # Notify admin of new withdrawal request
    admin = User.query.filter_by(role='admin').first()
    if admin:
        socketio.emit('new_withdrawal_request', {
            'withdrawal_id': withdrawal.id,
            'user_name': user.full_name,
            'amount': amount,
            'user_id': user.id
        }, room=f"user_{admin.id}")
        
    # Notify admin
    admin = User.query.filter_by(role='admin').first()
    if admin:
        create_notification(
            admin.id,
            f'💰 New withdrawal request from {user.full_name} for GHS{amount}',
            'info',
            '/admin/referrals'
        )
    
    return jsonify({
        'message': 'Withdrawal request submitted successfully',
        'withdrawal_id': withdrawal.id,
        'new_balance': float(user.commission_balance)  # Balance unchanged
    })

@app.route('/api/referrals/withdrawal-history', methods=['GET'])
@token_required
def get_withdrawal_history():
    user = request.current_user
    
    withdrawals = WithdrawalRequest.query.filter_by(user_id=user.id).order_by(WithdrawalRequest.requested_at.desc()).all()
    
    return jsonify([{
        'id': w.id,
        'amount': float(w.amount),
        'payment_method': w.payment_method,
        'account_details': w.account_details,
        'status': w.status,
        'requested_at': w.requested_at.isoformat(),
        'admin_processed_at': w.admin_processed_at.isoformat() if w.admin_processed_at else None,
        'user_confirmed_at': w.user_confirmed_at.isoformat() if w.user_confirmed_at else None
    } for w in withdrawals])

@app.route('/api/referrals/kpis', methods=['GET'])
@token_required
def get_referral_kpis():
    user = request.current_user
    
    def count_downline(u_id):
        direct = User.query.filter_by(referrer_id=u_id).count()
        total = direct
        for child in User.query.filter_by(referrer_id=u_id).all():
            total += count_downline(child.id)
        return total
    
    downline_count = count_downline(user.id)
    
    def get_max_depth(u_id, current_depth=1):
        children = User.query.filter_by(referrer_id=u_id).all()
        if not children:
            return current_depth
        max_child_depth = 0
        for child in children:
            depth = get_max_depth(child.id, current_depth + 1)
            max_child_depth = max(max_child_depth, depth)
        return max_child_depth
    
    active_depth = get_max_depth(user.id) if downline_count > 0 else 0
    
    return jsonify({
        'downline_count': downline_count,
        'active_depth': active_depth,
        'total_earned': float(user.total_earned or 0),
        'current_balance': float(user.commission_balance or 0),
        'is_referral_active': user.is_referral_active,
        'withdrawal_threshold': WITHDRAWAL_THRESHOLD_GHS
    })

# ==================== ADMIN REFERRAL ENDPOINTS ====================

@app.route('/api/admin/referrals/pending-withdrawals', methods=['GET'])
@admin_required
def get_pending_withdrawals():
    withdrawals = WithdrawalRequest.query.filter_by(status='pending').order_by(WithdrawalRequest.requested_at.asc()).all()
    
    return jsonify([{
        'id': w.id,
        'user_id': w.user_id,
        'user_name': w.user.full_name,
        'user_email': w.user.email,
        'user_phone': w.user.phone,
        'amount': float(w.amount),
        'payment_method': w.payment_method,
        'account_details': w.account_details,
        'requested_at': w.requested_at.isoformat()
    } for w in withdrawals])


@app.route('/api/admin/referrals/withdrawals/<int:withdrawal_id>/mark-sent', methods=['PUT'])
@admin_required
def mark_withdrawal_sent(withdrawal_id):
    data = request.json
    notes = data.get('notes', '')
    
    withdrawal = db.session.get(WithdrawalRequest, withdrawal_id)
    if not withdrawal:
        return jsonify({'error': 'Withdrawal request not found'}), 404
    
    if withdrawal.status != 'pending':
        return jsonify({'error': f'Withdrawal already {withdrawal.status}'}), 400
    
    # DO NOT deduct balance here - balance is still with user
    withdrawal.status = 'admin_sent'
    withdrawal.admin_processed_at = datetime.utcnow()
    withdrawal.admin_notes = notes
    
    db.session.commit()


        # Notify user that withdrawal has been sent
    socketio.emit('withdrawal_updated', {
        'withdrawal_id': withdrawal_id,
        'status': 'admin_sent',
        'amount': withdrawal.amount
    }, room=f"user_{withdrawal.user_id}")
    
    # Notify admin (for dashboard refresh)
    socketio.emit('withdrawal_updated', {
        'withdrawal_id': withdrawal_id,
        'status': 'admin_sent'
    }, room='role_admin')

    
    create_notification(
        withdrawal.user_id,
        f'💰 Your withdrawal of GHS{withdrawal.amount} has been sent to your {withdrawal.payment_method}. Please confirm receipt.',
        'success',
        '/referrals'
    )
    
    return jsonify({'message': 'Withdrawal marked as sent', 'status': 'admin_sent'})
    
@app.route('/api/referrals/withdrawals/<int:withdrawal_id>/confirm', methods=['PUT'])
@token_required
def confirm_withdrawal_receipt(withdrawal_id):
    withdrawal = db.session.get(WithdrawalRequest, withdrawal_id)
    
    if not withdrawal:
        return jsonify({'error': 'Withdrawal request not found'}), 404
    
    if withdrawal.user_id != request.current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if withdrawal.status != 'admin_sent':
        return jsonify({'error': f'Cannot confirm. Current status: {withdrawal.status}'}), 400
    
    # Deduct balance ONLY when user confirms receipt
    user = request.current_user
    if user.commission_balance >= withdrawal.amount:
        user.commission_balance = (user.commission_balance or 0) - withdrawal.amount
    else:
        return jsonify({'error': 'Insufficient balance for confirmation'}), 400
    
    withdrawal.status = 'user_confirmed'
    withdrawal.user_confirmed_at = datetime.utcnow()
    
    db.session.commit()


        # Notify admin that user confirmed receipt
    socketio.emit('withdrawal_updated', {
        'withdrawal_id': withdrawal_id,
        'status': 'user_confirmed',
        'user_id': withdrawal.user_id
    }, room='role_admin')
    
    return jsonify({
        'message': 'Withdrawal confirmed successfully',
        'status': 'user_confirmed',
        'new_balance': float(user.commission_balance)
    })


@app.route('/api/admin/referrals/owner-net-summary', methods=['GET'])
@admin_required
def get_owner_net_summary():
    bookings = ServiceRequest.query.filter(
        ServiceRequest.status == 'confirmed',
        ServiceRequest.commissions_processed == True
    ).all()
    
    total_pool = sum(b.referral_pool_amount or 0 for b in bookings)
    total_commissions = sum(b.total_commissions_paid or 0 for b in bookings)
    total_owner_net = sum(b.owner_net or 0 for b in bookings)
    
    return jsonify({
        'total_referral_pool': float(total_pool),
        'total_commissions_paid': float(total_commissions),
        'total_owner_net': float(total_owner_net),
        'total_bookings': len(bookings)
    })

@app.route('/api/admin/referrals/pending-bookings', methods=['GET'])
@admin_required
def get_pending_bookings_for_commission():
    bookings = ServiceRequest.query.filter(
        ServiceRequest.status == 'completed',
        ServiceRequest.provider_completed == True,
        ServiceRequest.customer_confirmed == False
    ).all()
    
    return jsonify([{
        'id': b.id,
        'customer_name': b.user.full_name if b.user else 'Unknown',
        'customer_phone': b.customer_phone,
        'service_name': b.service.name if b.service else 'Unknown',
        'amount': float(b.amount),
        'provider_name': b.provider.full_name if b.provider else 'Not assigned',
        'completed_at': b.completed_at.isoformat() if b.completed_at else None
    } for b in bookings])

@app.route('/api/admin/services/<int:service_id>/shares', methods=['PUT'])
@admin_required
def update_service_shares(service_id):
    data = request.json
    
    service = db.session.get(Service, service_id)
    if not service:
        return jsonify({'error': 'Service not found'}), 404
    
    if 'admin_share_percent' in data:
        service.admin_share_percent = data['admin_share_percent']
    if 'website_share_percent' in data:
        service.website_share_percent = data['website_share_percent']
    if 'provider_share_percent' in data:
        service.provider_share_percent = data['provider_share_percent']
    if 'referral_pool_percent' in data:
        service.referral_pool_percent = data['referral_pool_percent']
    
    total = (service.admin_share_percent or 0) + \
            (service.website_share_percent or 0) + \
            (service.provider_share_percent or 0) + \
            (service.referral_pool_percent or 0)
    
    if abs(total - 100) > 0.01:
        return jsonify({'error': f'Total must equal 100%. Current total: {total}%'}), 400
    
    db.session.commit()

    socketio.emit('service_shares_updated', {  # ← 4 spaces (aligned with commit)
        'service_id': service_id,
        'admin_share_percent': service.admin_share_percent,
        'website_share_percent': service.website_share_percent,
        'provider_share_percent': service.provider_share_percent,
        'referral_pool_percent': service.referral_pool_percent
    })
    
    return jsonify({
        'message': 'Service shares updated successfully',
        'service': {
            'id': service.id,
            'name': service.name,
            'admin_share_percent': service.admin_share_percent,
            'website_share_percent': service.website_share_percent,
            'provider_share_percent': service.provider_share_percent,
            'referral_pool_percent': service.referral_pool_percent
        }
    })

@app.route('/api/admin/referrals/user-tree/<int:user_id>', methods=['GET'])
@admin_required
def get_user_tree_for_admin(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    def build_tree(u, depth=0, max_depth=5):
        if depth > max_depth:
            return None
        
        children = User.query.filter_by(referrer_id=u.id).all()
        
        return {
            'id': u.id,
            'full_name': u.full_name,
            'email': u.email,
            'commission_balance': float(u.commission_balance or 0),
            'is_referral_active': u.is_referral_active,
            'total_earned': float(u.total_earned or 0),
            'position': u.position,
            'children': [build_tree(child, depth + 1, max_depth) for child in children],
            'depth': depth
        }
    
    tree = build_tree(user)
    
    return jsonify({'tree': tree})

# ==================== RUN THE APP ====================
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)

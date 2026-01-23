import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, date, timedelta
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import hashlib
import secrets
import re
from functools import wraps

# ==================== KONFIGURASI HALAMAN ====================
st.set_page_config(
    page_title="Dashboard Analitik Penjualan",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CSS CUSTOM (ENHANCED) ====================
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .stMetric {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 8px;
    }
    
    .stMetric label {
        color: #0e1117 !important;
        font-weight: 600 !important;
    }
    
    .stMetric [data-testid="stMetricValue"] {
        color: #0e1117 !important;
        font-size: 1.2rem !important;
        font-weight: bold !important;
    }
    
    .stMetric [data-testid="stMetricDelta"] {
        color: #31333F !important;
    }
    
    .stDataFrame {
        color: #0e1117 !important;
    }
    
    .stSelectbox label, .stTextInput label, .stNumberInput label, .stDateInput label {
        color: #0e1117 !important;
        font-weight: 600 !important;
    }
    
    .streamlit-expanderHeader {
        color: #0e1117 !important;
    }
    
    /* LOGIN PAGE STYLING */
    .login-container {
        max-width: 450px;
        margin: 3rem auto;
        padding: 2.5rem;
        background: white;
        border-radius: 15px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.1);
    }
    
    .login-header {
        text-align: center;
        color: #1f77b4;
        font-size: 2rem;
        font-weight: bold;
        margin-bottom: 1.5rem;
    }
    
    .user-badge {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        display: inline-block;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    </style>
""", unsafe_allow_html=True)

# ==================== SECURITY & AUTH CONFIG ====================

# Session timeout (minutes)
SESSION_TIMEOUT = 30

# Max login attempts before lockout
MAX_LOGIN_ATTEMPTS = 5

# Lockout duration (minutes)
LOCKOUT_DURATION = 15

# Password policy
PASSWORD_MIN_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL = True

# ==================== DATABASE FUNCTIONS (ENHANCED) ====================

def get_db_path():
    """Mengembalikan path database SQLite"""
    return Path("sales_data.db")

def hash_password(password: str, salt: str = None) -> tuple:
    """
    Hash password dengan salt menggunakan SHA-256
    
    Returns:
        tuple: (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(32)
    
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return pwd_hash.hex(), salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verifikasi password"""
    pwd_hash, _ = hash_password(password, salt)
    return pwd_hash == hashed

def validate_password_policy(password: str) -> tuple:
    """
    Validasi password sesuai policy
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password minimal {PASSWORD_MIN_LENGTH} karakter"
    
    if REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        return False, "Password harus mengandung huruf besar"
    
    if REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        return False, "Password harus mengandung huruf kecil"
    
    if REQUIRE_DIGIT and not re.search(r'\d', password):
        return False, "Password harus mengandung angka"
    
    if REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password harus mengandung karakter spesial (!@#$%^&* dll)"
    
    return True, ""

def init_database():
    """
    Inisialisasi database dengan tabel users dan activity logs
    """
    db_path = get_db_path()
    
    with sqlite3.connect(db_path, check_same_thread=False) as conn:
        cursor = conn.cursor()
        
        # Tabel transactions (EXISTING - TIDAK DIUBAH)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_date DATE NOT NULL,
                product_name TEXT NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                total_amount REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT 'system'
            )
        """)
        
        # Tabel users (NEW)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabel activity logs (NEW)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transaction_date ON transactions(transaction_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_product_name ON transactions(product_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON transactions(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(username)")
        
        # Create default admin user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_pass, admin_salt = hash_password("Admin@123")
            cursor.execute("""
                INSERT INTO users (username, password_hash, password_salt, full_name, email, role)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('admin', admin_pass, admin_salt, 'System Administrator', 'admin@company.com', 'admin'))
        
        conn.commit()

def get_database_connection():
    """Membuat koneksi ke database SQLite"""
    return sqlite3.connect(get_db_path(), check_same_thread=False)

def log_activity(username: str, activity_type: str, description: str = None):
    """
    Log user activity
    
    Args:
        username: Username
        activity_type: Type of activity (login, logout, create, update, delete)
        description: Additional description
    """
    try:
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_logs (username, activity_type, description)
                VALUES (?, ?, ?)
            """, (username, activity_type, description))
            conn.commit()
    except Exception as e:
        st.error(f"Error logging activity: {e}")

def check_user_lockout(username: str) -> tuple:
    """
    Check if user is locked out
    
    Returns:
        tuple: (is_locked, remaining_time)
    """
    with get_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT locked_until, failed_login_attempts 
            FROM users 
            WHERE username = ?
        """, (username,))
        
        result = cursor.fetchone()
        if not result:
            return False, 0
        
        locked_until, attempts = result
        
        if locked_until:
            locked_time = datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S')
            if datetime.now() < locked_time:
                remaining = (locked_time - datetime.now()).total_seconds() / 60
                return True, int(remaining)
            else:
                # Unlock user
                cursor.execute("""
                    UPDATE users 
                    SET locked_until = NULL, failed_login_attempts = 0
                    WHERE username = ?
                """, (username,))
                conn.commit()
        
        return False, 0

def authenticate_user(username: str, password: str) -> tuple:
    """
    Authenticate user credentials
    
    Returns:
        tuple: (success, user_data, message)
    """
    # Check lockout
    is_locked, remaining_time = check_user_lockout(username)
    if is_locked:
        return False, None, f"⛔ Akun terkunci. Coba lagi dalam {remaining_time} menit."
    
    with get_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, password_hash, password_salt, full_name, email, role, is_active, failed_login_attempts
            FROM users
            WHERE username = ?
        """, (username,))
        
        user = cursor.fetchone()
        
        if not user:
            log_activity(username, 'failed_login', 'User tidak ditemukan')
            return False, None, "❌ Username atau password salah"
        
        user_id, uname, pwd_hash, pwd_salt, full_name, email, role, is_active, failed_attempts = user
        
        if not is_active:
            log_activity(username, 'failed_login', 'Akun tidak aktif')
            return False, None, "⛔ Akun Anda tidak aktif. Hubungi administrator."
        
        # Verify password
        if verify_password(password, pwd_hash, pwd_salt):
            # Reset failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP
                WHERE username = ?
            """, (username,))
            conn.commit()
            
            log_activity(username, 'login', 'Login berhasil')
            
            user_data = {
                'id': user_id,
                'username': uname,
                'full_name': full_name,
                'email': email,
                'role': role
            }
            
            return True, user_data, "✅ Login berhasil!"
        else:
            # Increment failed attempts
            new_attempts = failed_attempts + 1
            
            if new_attempts >= MAX_LOGIN_ATTEMPTS:
                lockout_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION)
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = ?, locked_until = ?
                    WHERE username = ?
                """, (new_attempts, lockout_time.strftime('%Y-%m-%d %H:%M:%S'), username))
                
                log_activity(username, 'account_locked', f'Akun terkunci setelah {MAX_LOGIN_ATTEMPTS} percobaan gagal')
                message = f"⛔ Akun terkunci selama {LOCKOUT_DURATION} menit karena terlalu banyak percobaan login gagal."
            else:
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = ?
                    WHERE username = ?
                """, (new_attempts, username))
                
                remaining = MAX_LOGIN_ATTEMPTS - new_attempts
                message = f"❌ Password salah. Sisa percobaan: {remaining}"
            
            conn.commit()
            log_activity(username, 'failed_login', 'Password salah')
            
            return False, None, message

def register_user(username: str, password: str, full_name: str, email: str, role: str = 'user') -> tuple:
    """
    Register new user
    
    Returns:
        tuple: (success, message)
    """
    # Validate password
    is_valid, error_msg = validate_password_policy(password)
    if not is_valid:
        return False, error_msg
    
    # Validate email
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return False, "❌ Format email tidak valid"
    
    pwd_hash, pwd_salt = hash_password(password)
    
    try:
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, password_salt, full_name, email, role)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, pwd_hash, pwd_salt, full_name, email, role))
            conn.commit()
        
        log_activity('system', 'user_registered', f'User baru: {username}')
        return True, "✅ Registrasi berhasil! Silakan login."
    
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return False, "❌ Username sudah digunakan"
        elif 'email' in str(e):
            return False, "❌ Email sudah terdaftar"
        else:
            return False, f"❌ Error: {e}"
    except Exception as e:
        return False, f"❌ Error: {e}"

def get_all_users():
    """Get all users (admin only)"""
    with get_database_connection() as conn:
        query = """
            SELECT id, username, full_name, email, role, is_active, 
                   failed_login_attempts, last_login, created_at
            FROM users
            ORDER BY created_at DESC
        """
        df = pd.read_sql_query(query, conn)
    return df

def update_user_status(user_id: int, is_active: bool):
    """Toggle user active status"""
    with get_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET is_active = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (1 if is_active else 0, user_id))
        conn.commit()

def get_activity_logs(username: str = None, limit: int = 100):
    """Get activity logs"""
    with get_database_connection() as conn:
        if username:
            query = """
                SELECT * FROM activity_logs 
                WHERE username = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(username, limit))
        else:
            query = """
                SELECT * FROM activity_logs 
                ORDER BY timestamp DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
    return df

# ==================== SESSION MANAGEMENT ====================

def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_data' not in st.session_state:
        st.session_state.user_data = None
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now()
    if 'selected_ids' not in st.session_state:
        st.session_state.selected_ids = []

def check_session_timeout():
    """Check if session has timed out"""
    if st.session_state.authenticated:
        time_diff = (datetime.now() - st.session_state.last_activity).total_seconds() / 60
        
        if time_diff > SESSION_TIMEOUT:
            logout_user()
            st.warning(f"⏱️ Sesi Anda telah berakhir setelah {SESSION_TIMEOUT} menit tidak aktif. Silakan login kembali.")
            st.rerun()
        else:
            st.session_state.last_activity = datetime.now()

def logout_user():
    """Logout current user"""
    if st.session_state.authenticated and st.session_state.user_data:
        log_activity(
            st.session_state.user_data['username'],
            'logout',
            'User logout'
        )
    
    st.session_state.authenticated = False
    st.session_state.user_data = None
    st.session_state.last_activity = datetime.now()

def require_auth(allowed_roles=None):
    """
    Decorator untuk proteksi halaman dengan role-based access
    
    Args:
        allowed_roles: List of roles allowed to access (None = all authenticated users)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not st.session_state.authenticated:
                st.error("⛔ Anda harus login terlebih dahulu")
                st.stop()
            
            if allowed_roles:
                user_role = st.session_state.user_data.get('role')
                if user_role not in allowed_roles:
                    st.error(f"⛔ Akses ditolak. Halaman ini hanya untuk: {', '.join(allowed_roles)}")
                    st.stop()
            
            check_session_timeout()
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ==================== LOGIN/REGISTER PAGES ====================

def page_login():
    """Login page"""
    st.markdown("<div class='login-header'>🔐 Login Dashboard</div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form", clear_on_submit=False):
            st.markdown("### Masuk ke Akun Anda")
            
            username = st.text_input(
                "👤 Username",
                placeholder="Masukkan username",
                key="login_username"
            )
            
            password = st.text_input(
                "🔒 Password",
                type="password",
                placeholder="Masukkan password",
                key="login_password"
            )
            
            col_btn1, col_btn2 = st.columns(2)
            
            with col_btn1:
                submit = st.form_submit_button("🚀 Login", use_container_width=True, type="primary")
            
            with col_btn2:
                register_btn = st.form_submit_button("📝 Register", use_container_width=True)
            
            if submit:
                if not username or not password:
                    st.error("❌ Username dan password harus diisi")
                else:
                    success, user_data, message = authenticate_user(username, password)
                    
                    if success:
                        st.session_state.authenticated = True
                        st.session_state.user_data = user_data
                        st.session_state.last_activity = datetime.now()
                        st.success(message)
                        st.balloons()
                        st.rerun()
                    else:
                        st.error(message)
            
            if register_btn:
                st.session_state.show_register = True
                st.rerun()
        
        # Info box
        with st.expander("ℹ️ Informasi Login"):
            st.markdown("""
            **Default Admin Account:**
            - Username: `admin`
            - Password: `Admin@123`
            
            **Keamanan:**
            - Session timeout: {SESSION_TIMEOUT} menit
            - Max login attempts: {MAX_LOGIN_ATTEMPTS}
            - Lockout duration: {LOCKOUT_DURATION} menit
            """.format(
                SESSION_TIMEOUT=SESSION_TIMEOUT,
                MAX_LOGIN_ATTEMPTS=MAX_LOGIN_ATTEMPTS,
                LOCKOUT_DURATION=LOCKOUT_DURATION
            ))

def page_register():
    """Register page"""
    st.markdown("<div class='login-header'>📝 Registrasi Pengguna Baru</div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("register_form", clear_on_submit=True):
            st.markdown("### Buat Akun Baru")
            
            full_name = st.text_input(
                "👤 Nama Lengkap",
                placeholder="Masukkan nama lengkap"
            )
            
            email = st.text_input(
                "📧 Email",
                placeholder="email@example.com"
            )
            
            username = st.text_input(
                "🆔 Username",
                placeholder="Pilih username unik"
            )
            
            password = st.text_input(
                "🔒 Password",
                type="password",
                placeholder="Minimal 8 karakter"
            )
            
            password_confirm = st.text_input(
                "🔒 Konfirmasi Password",
                type="password",
                placeholder="Ketik ulang password"
            )
            
            st.markdown("---")
            
            col_btn1, col_btn2 = st.columns(2)
            
            with col_btn1:
                submit = st.form_submit_button("✅ Daftar", use_container_width=True, type="primary")
            
            with col_btn2:
                back_btn = st.form_submit_button("⬅️ Kembali", use_container_width=True)
            
            if submit:
                if not all([full_name, email, username, password, password_confirm]):
                    st.error("❌ Semua field harus diisi")
                elif password != password_confirm:
                    st.error("❌ Password dan konfirmasi password tidak cocok")
                else:
                    success, message = register_user(username, password, full_name, email)
                    
                    if success:
                        st.success(message)
                        st.balloons()
                        st.session_state.show_register = False
                        st.rerun()
                    else:
                        st.error(message)
            
            if back_btn:
                st.session_state.show_register = False
                st.rerun()
        
        # Password policy info
        with st.expander("ℹ️ Kebijakan Password"):
            st.markdown(f"""
            Password harus memenuhi kriteria:
            - Minimal **{PASSWORD_MIN_LENGTH} karakter**
            - Mengandung **huruf besar** (A-Z)
            - Mengandung **huruf kecil** (a-z)
            - Mengandung **angka** (0-9)
            - Mengandung **karakter spesial** (!@#$%^&*)
            """)

# ==================== ADMIN PAGES ====================

@require_auth(allowed_roles=['admin'])
def page_user_management():
    """User management page (admin only)"""
    st.markdown("<h1 class='main-header'>👥 Manajemen Pengguna</h1>", unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Get all users
    df_users = get_all_users()
    
    # Summary
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Users", len(df_users))
    
    with col2:
        active_users = df_users[df_users['is_active'] == 1]
        st.metric("Users Aktif", len(active_users))
    
    with col3:
        admins = df_users[df_users['role'] == 'admin']
        st.metric("Administrators", len(admins))
    
    with col4:
        locked = df_users[df_users['failed_login_attempts'] >= MAX_LOGIN_ATTEMPTS]
        st.metric("Akun Terkunci", len(locked))
    
    st.markdown("---")
    
    # User table
    st.subheader("📋 Daftar Pengguna")
    
    for idx, user in df_users.iterrows():
        with st.expander(
            f"👤 {user['full_name']} (@{user['username']}) - {user['role'].upper()}",
            expanded=False
        ):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write(f"**Email:** {user['email']}")
                st.write(f"**Role:** {user['role']}")
                st.write(f"**Status:** {'✅ Aktif' if user['is_active'] else '⛔ Nonaktif'}")
            
            with col2:
                st.write(f"**Failed Attempts:** {user['failed_login_attempts']}")
                last_login = user['last_login'] if user['last_login'] else 'Never'
                st.write(f"**Last Login:** {last_login}")
            
            with col3:
                st.write(f"**Created:** {user['created_at']}")
                
                # Actions
                if user['username'] != 'admin':  # Protect admin account
                    col_act1, col_act2 = st.columns(2)
                    
                    with col_act1:
                        new_status = not user['is_active']
                        action_text = "🔓 Aktifkan" if not user['is_active'] else "🔒 Nonaktifkan"
                        
                        if st.button(action_text, key=f"toggle_{user['id']}", use_container_width=True):
                            update_user_status(user['id'], new_status)
                            log_activity(
                                st.session_state.user_data['username'],
                                'user_status_changed',
                                f"Changed status of {user['username']} to {'active' if new_status else 'inactive'}"
                            )
                            st.success(f"✅ Status user {user['username']} berhasil diubah")
                            st.rerun()
                    
                    with col_act2:
                        if st.button("📊 Lihat Log", key=f"log_{user['id']}", use_container_width=True):
                            st.session_state.view_user_log = user['username']
                            st.rerun()

@require_auth(allowed_roles=['admin'])
def page_activity_logs():
    """Activity logs page (admin only)"""
    st.markdown("<h1 class='main-header'>📜 Log Aktivitas</h1>", unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Filter
    col1, col2 = st.columns([3, 1])
    
    with col1:
        users = ['Semua'] + get_all_users()['username'].tolist()
        selected_user = st.selectbox("Filter User", users)
    
    with col2:
        limit = st.number_input("Jumlah Log", min_value=10, max_value=1000, value=100)
    
    # Get logs
    if selected_user == 'Semua':
        df_logs = get_activity_logs(limit=limit)
    else:
        df_logs = get_activity_logs(username=selected_user, limit=limit)
    
    st.markdown("---")
    
    if df_logs.empty:
        st.info("📭 Tidak ada log aktivitas")
    else:
        st.metric("Total Log", len(df_logs))
        
        # Display logs
        for idx, log in df_logs.iterrows():
            timestamp = pd.to_datetime(log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            # Color based on activity type
            activity_icons = {
                'login': '🟢',
                'logout': '🔵',
                'failed_login': '🔴',
                'account_locked': '🔒',
                'user_registered': '✅',
                'create': '➕',
                'update': '✏️',
                'delete': '🗑️',
                'user_status_changed': '🔄'
            }
            
            icon = activity_icons.get(log['activity_type'], '📌')
            
            with st.expander(
                f"{icon} {timestamp} | {log['username']} | {log['activity_type']}",
                expanded=False
            ):
                st.write(f"**Description:** {log['description'] or 'N/A'}")
                st.write(f"**IP Address:** {log['ip_address'] or 'N/A'}")
        
        # Download logs
        csv = df_logs.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Log CSV",
            data=csv,
            file_name=f"activity_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# ==================== TRANSACTION FUNCTIONS (EXISTING - UNCHANGED) ====================

def delete_transaction(transaction_id):
    """Menghapus transaksi berdasarkan ID"""
    try:
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM transactions WHERE id = ?", (transaction_id,))
            conn.commit()
        
        # Log activity
        log_activity(
            st.session_state.user_data['username'],
            'delete',
            f'Deleted transaction ID: {transaction_id}'
        )
        
        return True
    except Exception as e:
        st.error(f"Error menghapus data: {e}")
        return False

def delete_multiple_transactions(transaction_ids):
    """Menghapus beberapa transaksi sekaligus"""
    try:
        with get_database_connection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(transaction_ids))
            cursor.execute(f"DELETE FROM transactions WHERE id IN ({placeholders})", transaction_ids)
            deleted_count = cursor.rowcount
            conn.commit()
        
        # Log activity
        log_activity(
            st.session_state.user_data['username'],
            'delete',
            f'Bulk deleted {deleted_count} transactions'
        )
        
        return deleted_count
    except Exception as e:
        st.error(f"Error menghapus data: {e}")
        return 0

def normalize_text(text):
    """Normalisasi input teks untuk konsistensi database"""
    if not text:
        return ""
    return text.strip().title()

def insert_transaction(transaction_date, product_name, category, quantity, unit_price, total_amount):
    """Menyimpan transaksi baru ke database"""
    try:
        product_name = normalize_text(product_name)
        category = normalize_text(category)
        
        created_by = st.session_state.user_data['username'] if st.session_state.authenticated else 'system'
        
        with get_database_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO transactions 
                (transaction_date, product_name, category, quantity, unit_price, total_amount, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (transaction_date, product_name, category, quantity, unit_price, total_amount, created_by))
            
            conn.commit()
        
        # Log activity
        log_activity(
            created_by,
            'create',
            f'Created transaction: {product_name} - {format_currency(total_amount)}'
        )
        
        return True
    except Exception as e:
        st.error(f"Error menyimpan data: {e}")
        return False

def get_all_transactions():
    """Mengambil semua data transaksi dari database"""
    with get_database_connection() as conn:
        query = """
            SELECT 
                id,
                transaction_date,
                product_name,
                category,
                quantity,
                unit_price,
                total_amount,
                created_at,
                created_by
            FROM transactions
            ORDER BY transaction_date DESC, created_at DESC
        """
        df = pd.read_sql_query(query, conn)
    
    if not df.empty:
        df['transaction_date'] = pd.to_datetime(df['transaction_date'])
    
    return df

def get_filtered_transactions(start_date=None, end_date=None, product=None, category=None):
    """Mengambil data transaksi dengan filter"""
    with get_database_connection() as conn:
        query = "SELECT * FROM transactions WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND transaction_date >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND transaction_date <= ?"
            params.append(end_date)
        
        if product and product != "Semua":
            query += " AND product_name = ?"
            params.append(product)
        
        if category and category != "Semua":
            query += " AND category = ?"
            params.append(category)
        
        query += " ORDER BY transaction_date DESC, created_at DESC"
        
        df = pd.read_sql_query(query, conn, params=params)
    
    if not df.empty:
        df['transaction_date'] = pd.to_datetime(df['transaction_date'])
    
    return df

def get_unique_products():
    """Mengambil daftar produk unik dari database"""
    with get_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT product_name FROM transactions ORDER BY product_name")
        products = [row[0] for row in cursor.fetchall()]
    
    return products

def get_unique_categories():
    """Mengambil daftar kategori unik dari database"""
    with get_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT category FROM transactions ORDER BY category")
        categories = [row[0] for row in cursor.fetchall()]
    
    return categories

def format_currency(amount):
    """Format angka menjadi format currency Rupiah"""
    return f"Rp {amount:,.0f}".replace(",", ".")

def format_number(number):
    """Format angka dengan thousand separator"""
    return f"{number:,.0f}".replace(",", ".")

# ==================== HALAMAN INPUT TRANSAKSI ====================

@require_auth()
def page_input_transaction():
    """Halaman untuk input transaksi penjualan baru"""
    st.markdown("<h1 class='main-header'>📝 Input Transaksi Penjualan</h1>", unsafe_allow_html=True)
    
    st.markdown("---")
    
    existing_products = get_unique_products()
    existing_categories = get_unique_categories()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Informasi Transaksi")
        
        st.markdown("**📅 Tanggal Transaksi**")
        transaction_date = st.date_input(
            "Tanggal Transaksi",
            value=date.today(),
            max_value=date.today(),
            help="Pilih tanggal transaksi",
            label_visibility="collapsed"
        )
        
        st.markdown("**🏷️ Pilih Produk**")
        product_options = ["-- Pilih Produk --"] + existing_products + ["➕ Tambah Produk Baru"]
        selected_product_option = st.selectbox(
            "Pilih Produk",
            product_options,
            help="Pilih produk yang sudah ada atau tambah baru",
            label_visibility="collapsed"
        )
        
        if selected_product_option == "➕ Tambah Produk Baru":
            st.markdown("**✏️ Nama Produk Baru**")
            product_name = st.text_input(
                "Nama Produk Baru",
                placeholder="Contoh: Laptop ASUS ROG",
                help="Masukkan nama produk baru",
                label_visibility="collapsed"
            )
        elif selected_product_option == "-- Pilih Produk --":
            product_name = ""
        else:
            product_name = selected_product_option
        
        st.markdown("**📂 Pilih Kategori**")
        category_options = ["-- Pilih Kategori --"] + existing_categories + ["➕ Tambah Kategori Baru"]
        selected_category_option = st.selectbox(
            "Pilih Kategori",
            category_options,
            help="Pilih kategori yang sudah ada atau tambah baru",
            label_visibility="collapsed"
        )
        
        if selected_category_option == "➕ Tambah Kategori Baru":
            st.markdown("**✏️ Nama Kategori Baru**")
            category = st.text_input(
                "Nama Kategori Baru",
                placeholder="Contoh: Elektronik",
                help="Masukkan nama kategori baru",
                label_visibility="collapsed"
            )
        elif selected_category_option == "-- Pilih Kategori --":
            category = ""
        else:
            category = selected_category_option
    
    with col2:
        st.subheader("Detail Penjualan")
        
        st.markdown("**📦 Jumlah Terjual**")
        quantity = st.number_input(
            "Jumlah Terjual",
            min_value=1,
            value=1,
            step=1,
            help="Masukkan jumlah produk yang terjual",
            label_visibility="collapsed"
        )
        
        st.markdown("**💰 Harga Satuan (Rp)**")
        unit_price = st.number_input(
            "Harga Satuan (Rp)",
            min_value=0.0,
            value=0.0,
            step=1000.0,
            format="%.0f",
            help="Masukkan harga satuan produk",
            label_visibility="collapsed"
        )
        
        total_amount = quantity * unit_price
        st.metric(
            "Total Penjualan",
            format_currency(total_amount),
            help="Total dihitung otomatis"
        )
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("💾 Simpan Transaksi", use_container_width=True, type="primary"):
            if not product_name or not product_name.strip():
                st.error("⚠️ Nama produk harus diisi!")
            elif not category or not category.strip():
                st.error("⚠️ Kategori produk harus diisi!")
            elif quantity <= 0:
                st.error("⚠️ Jumlah terjual harus lebih dari 0!")
            elif unit_price <= 0:
                st.error("⚠️ Harga satuan harus lebih dari 0!")
            else:
                success = insert_transaction(
                    transaction_date,
                    product_name,
                    category,
                    quantity,
                    unit_price,
                    total_amount
                )
                
                if success:
                    st.success("✅ Transaksi berhasil disimpan!")
                    st.balloons()
                    st.rerun()

# ==================== HALAMAN DATA PENJUALAN ====================

@require_auth()
def page_sales_data():
    """Halaman untuk melihat dan filter data penjualan"""
    st.markdown("<h1 class='main-header'>📋 Data Penjualan</h1>", unsafe_allow_html=True)
    
    st.subheader("🔍 Filter Data")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("**📅 Tanggal Mulai**")
        default_start = date.today() - timedelta(days=30)
        start_date = st.date_input(
            "Tanggal Mulai",
            value=default_start,
            max_value=date.today(),
            help="Pilih tanggal awal periode",
            label_visibility="collapsed"
        )
    
    with col2:
        st.markdown("**📅 Tanggal Akhir**")
        end_date = st.date_input(
            "Tanggal Akhir",
            value=date.today(),
            max_value=date.today(),
            help="Pilih tanggal akhir periode",
            label_visibility="collapsed"
        )
    
    products = ["Semua"] + get_unique_products()
    categories = ["Semua"] + get_unique_categories()
    
    with col3:
        st.markdown("**🏷️ Produk**")
        selected_product = st.selectbox(
            "Produk", 
            products,
            help="Filter berdasarkan produk",
            label_visibility="collapsed"
        )
    
    with col4:
        st.markdown("**📂 Kategori**")
        selected_category = st.selectbox(
            "Kategori", 
            categories,
            help="Filter berdasarkan kategori",
            label_visibility="collapsed"
        )
    
    st.markdown("---")
    
    df = get_filtered_transactions(
        start_date=start_date,
        end_date=end_date,
        product=selected_product if selected_product != "Semua" else None,
        category=selected_category if selected_category != "Semua" else None
    )
    
    if df.empty:
        st.info("📭 Belum ada data transaksi. Silakan input transaksi terlebih dahulu.")
    else:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Transaksi", format_number(len(df)))
        
        with col2:
            st.metric("Total Omzet", format_currency(df['total_amount'].sum()))
        
        with col3:
            st.metric("Total Item Terjual", format_number(df['quantity'].sum()))
        
        with col4:
            st.metric("Rata-rata Transaksi", format_currency(df['total_amount'].mean()))
        
        st.markdown("---")
        
        st.subheader("📊 Tabel Transaksi")
        
        display_df = df.copy()
        display_df['transaction_date'] = display_df['transaction_date'].dt.strftime('%d-%m-%Y')
        display_df['unit_price'] = display_df['unit_price'].apply(format_currency)
        display_df['total_amount'] = display_df['total_amount'].apply(format_currency)
        
        display_df = display_df.rename(columns={
            'id': 'ID',
            'transaction_date': 'Tanggal',
            'product_name': 'Produk',
            'category': 'Kategori',
            'quantity': 'Jumlah',
            'unit_price': 'Harga Satuan',
            'total_amount': 'Total',
            'created_by': 'Dibuat Oleh'
        })
        
        st.dataframe(
            display_df[['ID', 'Tanggal', 'Produk', 'Kategori', 'Jumlah', 'Harga Satuan', 'Total', 'Dibuat Oleh']],
            use_container_width=True,
            hide_index=True
        )
        
        # Check role for delete permission
        user_role = st.session_state.user_data.get('role')
        if user_role == 'admin':
            st.info("💡 **Tip:** Untuk menghapus data, gunakan menu '🗂️ Manajemen Transaksi'")
        else:
            st.info("💡 **Info:** Hanya Admin yang dapat menghapus data transaksi")
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Data CSV",
            data=csv,
            file_name=f"data_penjualan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# ==================== HALAMAN MANAJEMEN TRANSAKSI ====================

@require_auth(allowed_roles=['admin'])
def page_transaction_management():
    """Halaman khusus untuk manajemen (hapus) transaksi - ADMIN ONLY"""
    st.markdown("<h1 class='main-header'>🗂️ Manajemen Transaksi</h1>", unsafe_allow_html=True)
    
    st.warning("⚠️ **Peringatan:** Penghapusan data bersifat permanen dan tidak dapat dibatalkan!")
    
    st.markdown("---")
    
    df = get_all_transactions()
    
    if df.empty:
        st.info("📭 Belum ada data transaksi untuk dikelola.")
        return
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Data", format_number(len(df)))
    with col2:
        st.metric("Total Omzet", format_currency(df['total_amount'].sum()))
    with col3:
        st.metric("Range Tanggal", 
                 f"{df['transaction_date'].min().strftime('%d-%m-%Y')} s/d {df['transaction_date'].max().strftime('%d-%m-%Y')}")
    
    st.markdown("---")
    
    st.subheader("🔍 Filter Data")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🏷️ Filter Produk**")
        products = ["Semua"] + get_unique_products()
        filter_product = st.selectbox(
            "Filter Produk", 
            products, 
            key="mgmt_product",
            label_visibility="collapsed"
        )
    
    with col2:
        st.markdown("**📂 Filter Kategori**")
        categories = ["Semua"] + get_unique_categories()
        filter_category = st.selectbox(
            "Filter Kategori", 
            categories, 
            key="mgmt_category",
            label_visibility="collapsed"
        )
    
    filtered_df = df.copy()
    if filter_product != "Semua":
        filtered_df = filtered_df[filtered_df['product_name'] == filter_product]
    if filter_category != "Semua":
        filtered_df = filtered_df[filtered_df['category'] == filter_category]
    
    st.markdown("---")
    
    st.subheader("📋 Pilih Transaksi untuk Dihapus")
    
    if filtered_df.empty:
        st.info("Tidak ada data sesuai filter.")
        return
    
    if 'selected_ids' not in st.session_state:
        st.session_state.selected_ids = []
    
    for idx, row in filtered_df.iterrows():
        col_check, col_data = st.columns([0.3, 9.7])
        
        with col_check:
            is_checked = row['id'] in st.session_state.selected_ids
            if st.checkbox("", value=is_checked, key=f"check_{row['id']}", label_visibility="collapsed"):
                if row['id'] not in st.session_state.selected_ids:
                    st.session_state.selected_ids.append(row['id'])
            else:
                if row['id'] in st.session_state.selected_ids:
                    st.session_state.selected_ids.remove(row['id'])
        
        with col_data:
            tanggal_str = row['transaction_date'].strftime('%d-%m-%Y')
            total_str = format_currency(row['total_amount'])
            harga_satuan_str = format_currency(row['unit_price'])
            
            with st.expander(
                f"ID: {row['id']} | {tanggal_str} | {row['product_name']} | {total_str}",
                expanded=False
            ):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Produk:** {row['product_name']}")
                    st.write(f"**Kategori:** {row['category']}")
                with col2:
                    st.write(f"**Jumlah:** {row['quantity']}")
                    st.write(f"**Harga Satuan:** {harga_satuan_str}")
                with col3:
                    st.write(f"**Total:** {total_str}")
                    st.write(f"**Tanggal:** {tanggal_str}")
                    st.write(f"**Dibuat oleh:** {row.get('created_by', 'system')}")
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns([2, 2, 6])
    
    with col1:
        st.metric("Terpilih", len(st.session_state.selected_ids))
    
    with col2:
        if st.button("🔄 Reset Pilihan", use_container_width=True):
            st.session_state.selected_ids = []
            st.rerun()
    
    with col3:
        if len(st.session_state.selected_ids) > 0:
            if st.button(f"🗑️ Hapus {len(st.session_state.selected_ids)} Transaksi Terpilih", 
                        type="primary", 
                        use_container_width=True):
                st.session_state.confirm_bulk_delete = True
                st.rerun()
    
    if st.session_state.get('confirm_bulk_delete', False):
        st.markdown("---")
        st.error(f"⚠️ **KONFIRMASI:** Anda akan menghapus {len(st.session_state.selected_ids)} transaksi secara permanen!")
        
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            if st.button("✅ Ya, Hapus Sekarang", type="primary", use_container_width=True):
                deleted_count = delete_multiple_transactions(st.session_state.selected_ids)
                if deleted_count > 0:
                    st.success(f"✅ Berhasil menghapus {deleted_count} transaksi!")
                    st.session_state.selected_ids = []
                    st.session_state.confirm_bulk_delete = False
                    st.balloons()
                    st.rerun()
        
        with col2:
            if st.button("❌ Batal", use_container_width=True):
                st.session_state.confirm_bulk_delete = False
                st.rerun()

# ==================== HALAMAN DASHBOARD ANALITIK ====================

@require_auth()
def page_analytics_dashboard():
    """Halaman dashboard analitik dengan visualisasi data"""
    st.markdown("<h1 class='main-header'>📊 Dashboard Analitik Penjualan</h1>", unsafe_allow_html=True)
    
    df = get_all_transactions()
    
    if df.empty:
        st.info("📭 Belum ada data untuk ditampilkan. Silakan input transaksi terlebih dahulu.")
        return
    
    st.subheader("📈 Key Performance Indicators")
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_revenue = df['total_amount'].sum()
    total_transactions = len(df)
    total_items = df['quantity'].sum()
    avg_transaction = df['total_amount'].mean()
    
    with col1:
        st.metric(
            label="💰 Total Omzet",
            value=format_currency(total_revenue)
        )
    
    with col2:
        st.metric(
            label="🛒 Total Transaksi",
            value=format_number(total_transactions)
        )
    
    with col3:
        st.metric(
            label="📦 Total Produk Terjual",
            value=format_number(total_items)
        )
    
    with col4:
        st.metric(
            label="💳 Rata-rata Nilai Transaksi",
            value=format_currency(avg_transaction)
        )
    
    st.markdown("---")
    
    st.subheader("📊 Analisis Pertumbuhan Penjualan")
    
    daily_sales = df.groupby('transaction_date')['total_amount'].sum().reset_index()
    daily_sales = daily_sales.sort_values('transaction_date')
    
    if len(daily_sales) >= 2:
        daily_sales['growth_rate'] = daily_sales['total_amount'].pct_change() * 100
        
        col1, col2 = st.columns(2)
        
        with col1:
            avg_growth = daily_sales['growth_rate'].mean()
            growth_delta = f"{avg_growth:+.2f}%" if not pd.isna(avg_growth) else "N/A"
            
            st.metric(
                label="📈 Rata-rata Pertumbuhan Harian",
                value=growth_delta
            )
        
        with col2:
            max_sales_day = daily_sales.loc[daily_sales['total_amount'].idxmax()]
            st.metric(
                label="🏆 Hari Penjualan Tertinggi",
                value=max_sales_day['transaction_date'].strftime('%d-%m-%Y'),
                delta=format_currency(max_sales_day['total_amount'])
            )
    
    st.markdown("---")
    
    st.subheader("📅 Tren Penjualan Berdasarkan Waktu")
    
    daily_sales['date_display'] = daily_sales['transaction_date'].dt.strftime('%d %b %Y')
    
    fig_trend = px.line(
        daily_sales,
        x='transaction_date',
        y='total_amount',
        title='Tren Penjualan Harian',
        labels={'transaction_date': 'Tanggal', 'total_amount': 'Total Penjualan (Rp)'},
        markers=True
    )
    
    fig_trend.update_traces(
        line_color='#1f77b4', 
        line_width=3
    )
    
    fig_trend.update_layout(
        hovermode='x unified',
        plot_bgcolor='rgba(0,0,0,0)',
        yaxis_tickformat=',.0f'
    )
    st.plotly_chart(fig_trend, use_container_width=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🏆 Top 10 Produk Terlaris")
        
        top_products = df.groupby('product_name').agg({
            'quantity': 'sum',
            'total_amount': 'sum'
        }).reset_index()
        top_products = top_products.sort_values('total_amount', ascending=False).head(10)
        
        fig_products = px.bar(
            top_products,
            x='total_amount',
            y='product_name',
            orientation='h',
            title='Berdasarkan Total Penjualan'
        )
        st.plotly_chart(fig_products, use_container_width=True)
    
    with col2:
        st.subheader("📂 Penjualan per Kategori")
        
        category_sales = df.groupby('category')['total_amount'].sum().reset_index()
        
        fig_category = px.pie(
            category_sales,
            values='total_amount',
            names='category',
            title='Distribusi Penjualan per Kategori'
        )
        st.plotly_chart(fig_category, use_container_width=True)

# ==================== MAIN APPLICATION ====================

def main():
    """Fungsi utama aplikasi dengan authentication wrapper"""
    
    # Initialize database
    try:
        init_database()
    except Exception as e:
        st.error(f"❌ Error inisialisasi database: {e}")
        st.stop()
    
    # Initialize session state
    init_session_state()
    
    # ==================== AUTHENTICATION GATE ====================
    
    if not st.session_state.authenticated:
        # Show login/register page
        if st.session_state.get('show_register', False):
            page_register()
        else:
            page_login()
        return
    
    # ==================== AUTHENTICATED SECTION ====================
    
    # Check session timeout
    check_session_timeout()
    
    # Sidebar navigation
    st.sidebar.title("🎯 Navigasi")
    
    # User info badge
    user = st.session_state.user_data
    role_badge = "🔑 ADMIN" if user['role'] == 'admin' else "👤 USER"
    st.sidebar.markdown(f"""
    <div class='user-badge'>
        {role_badge}<br>
        {user['full_name']}<br>
        @{user['username']}
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    # Menu based on role
    if user['role'] == 'admin':
        pages = [
            "📝 Input Transaksi", 
            "📋 Data Penjualan", 
            "🗂️ Manajemen Transaksi", 
            "📊 Dashboard Analitik",
            "👥 Manajemen User",
            "📜 Log Aktivitas"
        ]
    else:
        pages = [
            "📝 Input Transaksi", 
            "📋 Data Penjualan", 
            "📊 Dashboard Analitik"
        ]
    
    page = st.sidebar.radio(
        "Pilih Halaman:",
        pages,
        label_visibility="collapsed"
    )
    
    st.sidebar.markdown("---")
    
    # Logout button
    if st.sidebar.button("🚪 Logout", use_container_width=True, type="primary"):
        logout_user()
        st.success("✅ Logout berhasil!")
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📌 Informasi Aplikasi")
    st.sidebar.info(
        """
        **Dashboard Analitik Penjualan**
        
        Aplikasi profesional untuk mengelola dan menganalisis data penjualan bisnis/UMKM.
        
        **Fitur:**
        - ✅ Authentication & Authorization
        - ✅ Role-based Access Control
        - ✅ Session Management
        - ✅ Activity Logging
        - ✅ Input transaksi mudah
        - ✅ Filter data lanjutan
        - ✅ Visualisasi interaktif
        - ✅ Export data CSV
        
        **Versi:** 4.0 Enterprise
        """
    )
    
    st.sidebar.markdown("---")
    
    # Tampilkan statistik cepat di sidebar
    try:
        df = get_all_transactions()
        if not df.empty:
            st.sidebar.markdown("### 📊 Statistik Cepat")
            st.sidebar.metric("Total Data", format_number(len(df)))
            st.sidebar.metric("Total Omzet", format_currency(df['total_amount'].sum()))
            
            # Session info
            time_since_login = (datetime.now() - st.session_state.last_activity).total_seconds() / 60
            remaining_time = SESSION_TIMEOUT - time_since_login
            
            if remaining_time > 0:
                st.sidebar.markdown("---")
                st.sidebar.markdown("### ⏱️ Sesi Aktif")
                st.sidebar.metric("Sisa Waktu", f"{int(remaining_time)} menit")
    except:
        pass
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("©️ 2026 Dashboard Analitik Penjualan")
    
    # ==================== PAGE ROUTING ====================
    
    try:
        if page == "📝 Input Transaksi":
            page_input_transaction()
        elif page == "📋 Data Penjualan":
            page_sales_data()
        elif page == "🗂️ Manajemen Transaksi":
            page_transaction_management()
        elif page == "📊 Dashboard Analitik":
            page_analytics_dashboard()
        elif page == "👥 Manajemen User":
            page_user_management()
        elif page == "📜 Log Aktivitas":
            page_activity_logs()
    except Exception as e:
        st.error(f"❌ Terjadi kesalahan: {e}")
        st.info("Silakan refresh halaman atau hubungi administrator.")

# ==================== RUN APPLICATION ====================

if __name__ == "__main__":
    main()
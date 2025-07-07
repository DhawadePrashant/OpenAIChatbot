import os
import requests
from bs4 import BeautifulSoup
import mysql.connector
from dotenv import load_dotenv
from flask import Flask, request, jsonify, redirect, url_for, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from functools import wraps
from openai import OpenAI
from flask_cors import CORS

# --- App Initialization and Configuration ---
load_dotenv()

# Validate required environment variables
required_env_vars = ['OPENAI_API_KEY', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
    print("Please set these variables in your .env file before running the application.")

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "a-very-secret-key-you-must-change")
CORS(app, origins=['*'])

# --- Extension Initialization ---
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "You must be logged in to access this page."
login_manager.login_message_category = "error"

# --- Database and AI Model Setup ---
db_config = {
    'host': os.getenv("DB_HOST"),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASSWORD"),
    'database': os.getenv("DB_NAME"),
    'autocommit': True,
    'charset': 'utf8mb4'
}

# Enhanced OpenAI configuration with better error handling
try:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    if not api_key.startswith('sk-'):
        raise ValueError("Invalid OpenAI API key format")
    
    client = OpenAI(api_key=api_key)
    model = "gpt-4o"
    
    # Test the connection
    test_response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "test"}],
        max_tokens=5
    )
    print("✅ OpenAI API configured and tested successfully.")
    
except ValueError as ve:
    client = None
    print(f"❌ OpenAI Configuration Error: {ve}")
except Exception as e:
    client = None
    print(f"❌ OpenAI API Error: {e}")

website_context = ""

# --- Helper Functions ---
def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        print(f"❌ Database Connection Error: {err}")
        return None

def get_public_ip():
    """Fetches the public IP address of the user."""
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text.strip()
        if ip:
            return ip
    except requests.exceptions.RequestException as e:
        print(f"Could not fetch public IP from ipify: {e}")
   
    # Fallback to request headers
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

def get_location_from_ip(ip_address):
    """Fetches geolocation data for a given IP address."""
    city, region, country = "Unknown", "Unknown", "Unknown"
    if ip_address in ['127.0.0.1', 'localhost']:
        return city, region, country
    
    try:
        geo_response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
        if geo_response.status_code == 200:
            geo_data = geo_response.json()
            city = geo_data.get('city', 'Unknown')
            region = geo_data.get('region', 'Unknown')
            country = geo_data.get('country', 'Unknown')
    except requests.exceptions.RequestException as e:
        print(f"Could not fetch geolocation data: {e}")
    
    return city, region, country

def get_or_create_anonymous_user():
    """Get or create an anonymous user for WordPress integration"""
    conn = get_db_connection()
    if not conn:
        return 1  # Fallback user ID
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username = 'anonymous_wp_user'")
        user = cursor.fetchone()
        
        if not user:
            # Create anonymous user for WordPress integration
            cursor.execute("""
                INSERT INTO users (username, name, email, role, last_ip, city, region, country)
                VALUES ('anonymous_wp_user', 'Anonymous WordPress User', 'anonymous@wordpress.local', 'user', %s, %s, %s, %s)
            """, (get_public_ip(), 'Unknown', 'Unknown', 'Unknown'))
            conn.commit()
            user_id = cursor.lastrowid
        else:
            user_id = user['id']
        
        cursor.close()
        conn.close()
        return user_id
    except Exception as e:
        print(f"Error managing anonymous user: {e}")
        return 1

# --- Role-Based Access Control Decorator ---
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                return jsonify(error="Permission denied"), 403
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# --- User Authentication Model and Setup ---
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], role=user_data['role'])
    except Exception as e:
        print(f"Error loading user: {e}")
    
    return None

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.path.startswith('/api/'):
        return jsonify(error="Authentication required."), 401
    return redirect(url_for('login'))

# --- Route Definitions ---

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error="Username and password are required.")
        
        conn = get_db_connection()
        if not conn:
            return render_template('login.html', error="Database connection failed. Please try again.")
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s AND password IS NOT NULL", (username,))
            user_data = cursor.fetchone()
           
            if user_data and bcrypt.check_password_hash(user_data['password'], password):
                ip_address = get_public_ip()
                city, region, country = get_location_from_ip(ip_address)
                
                cursor.execute("""
                    UPDATE users SET last_ip = %s, city = %s, region = %s, country = %s
                    WHERE id = %s
                """, (ip_address, city, region, country, user_data['id']))
                conn.commit()
               
                user = User(id=user_data['id'], username=user_data['username'], role=user_data['role'])
                login_user(user)
                
                cursor.close()
                conn.close()
                return redirect(url_for('index'))
            else:
                cursor.close()
                conn.close()
                return render_template('login.html', error="Invalid username or password.")
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('login.html', error="An error occurred during login.")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        contact_number = request.form.get('contact_number', '').strip()

        if not all([username, password, email]):
            return render_template('signup.html', error="Username, email, and password are required.")
       
        conn = get_db_connection()
        if not conn:
            return render_template('signup.html', error="Database connection failed. Please try again.")
        
        try:
            cursor = conn.cursor(dictionary=True)
           
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return render_template('signup.html', error="Username or email already exists.")
           
            ip_address = get_public_ip()
            city, region, country = get_location_from_ip(ip_address)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            cursor.execute("""
                INSERT INTO users (username, password, name, email, contact_number, last_ip, city, region, country, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'user')
            """, (username, hashed_password, username, email, contact_number, ip_address, city, region, country))
            conn.commit()
            
            cursor.close()
            conn.close()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Signup error: {e}")
            return render_template('signup.html', error="An error occurred during registration.")
       
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Frontend Serving Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

# --- API Routes for Chat Application ---
@app.route('/wp-api/process-url', methods=['POST'])
def wp_process_url():
    global website_context
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "URL is required."}), 400
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return jsonify({"error": "Invalid URL format. Must start with http:// or https://"}), 400
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script_or_style in soup(["script", "style", "nav", "footer", "header"]):
            script_or_style.decompose()
        
        text = soup.get_text(separator=' ', strip=True)
        website_context = text[:8000]  # Limit context size
        
        return jsonify({"message": f"Successfully processed content from {url}."})
        
    except requests.exceptions.Timeout:
        website_context = ""
        return jsonify({"error": "Website took too long to respond. Please try a different URL."}), 500
    except requests.exceptions.RequestException as e:
        website_context = ""
        return jsonify({"error": f"Error accessing URL: {str(e)}"}), 500
    except Exception as e:
        website_context = ""
        return jsonify({"error": f"Error processing URL: {str(e)}"}), 500

@app.route('/wp-api/chat', methods=['POST'])
def wp_chat():
    global website_context
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return jsonify({"error": "Message cannot be empty"}), 400
        
        if len(user_message) > 1000:
            return jsonify({"error": "Message too long. Please limit to 1000 characters."}), 400
        
        if not client:
            return jsonify({"error": "AI model not configured"}), 500
        
        # Create prompt based on context
        if website_context:
            prompt = (f"Based on the following website content, provide a concise and helpful answer. "
                      f"Keep your entire response between 400 and 500 characters.\n\n"
                      f"--- WEBSITE CONTENT ---\n{website_context}\n--- END OF CONTENT ---\n\n"
                      f"User's Question: {user_message}")
        else:
            prompt = (f"Please provide a concise and helpful answer to the following question. "
                      f"Keep your entire response between 400 and 500 characters.\n\n"
                      f"Question: {user_message}")
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.7
        )
        
        bot_response = response.choices[0].message.content
        
        # Save to database with proper user handling
        user_id = get_or_create_anonymous_user()
        conn = get_db_connection()
        
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO chat_history (user_id, user_message, bot_response, context_url)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, user_message, bot_response, website_context[:2048] if website_context else None))
                conn.commit()
                cursor.close()
                conn.close()
            except Exception as e:
                print(f"Error saving chat history: {e}")
        
        return jsonify({"response": bot_response})
        
    except Exception as e:
        print(f"Error in chat endpoint: {str(e)}")
        return jsonify({"error": "AI service error. Please try again."}), 500

@app.route('/wp-api/test', methods=['GET'])
def wp_test():
    return jsonify({
        "status": "Flask server is running",
        "message": "WordPress integration ready",
        "openai_configured": client is not None,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/dashboard/list/<list_type>')
@login_required
def get_dashboard_list(list_type):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    
    try:
        cursor = conn.cursor(dictionary=True)
        items = []
        
        if list_type == 'users':
            if current_user.role in ['admin', 'superadmin']:
                cursor.execute("SELECT id, name as title, email as subtitle FROM users ORDER BY name ASC")
            else:
                cursor.execute("SELECT id, name as title, email as subtitle FROM users WHERE id = %s", (current_user.id,))
            items = cursor.fetchall()
            
        elif list_type == 'chats':
            if current_user.role in ['admin', 'superadmin']:
                cursor.execute("""
                    SELECT 
                        ch.user_id as id,
                        u.name as title, 
                        ch.user_message as subtitle, 
                        ch.created_at,
                        COUNT(ch2.id) as message_count
                    FROM chat_history ch 
                    JOIN users u ON ch.user_id = u.id 
                    LEFT JOIN chat_history ch2 ON ch2.user_id = ch.user_id
                    WHERE ch.created_at = (
                        SELECT MAX(created_at) 
                        FROM chat_history ch3 
                        WHERE ch3.user_id = ch.user_id
                    )
                    GROUP BY ch.user_id, u.name, ch.user_message, ch.created_at
                    ORDER BY ch.created_at DESC 
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT 
                        ch.id,
                        CONCAT('Chat ', DATE_FORMAT(ch.created_at, '%m/%d')) as title,
                        ch.user_message as subtitle, 
                        ch.created_at
                    FROM chat_history ch
                    WHERE ch.user_id = %s 
                    ORDER BY ch.created_at DESC 
                    LIMIT 50
                """, (current_user.id,))
            
            items = cursor.fetchall()
            for item in items:
                item['timestamp'] = item.pop('created_at').strftime('%I:%M %p')
                item['subtitle'] = (item['subtitle'][:40] + '...') if len(item['subtitle']) > 40 else item['subtitle']
                if current_user.role in ['admin', 'superadmin'] and 'message_count' in item:
                    item['badge'] = item['message_count']
        
        cursor.close()
        conn.close()
        return jsonify(items)
        
    except Exception as e:
        print(f"Error in dashboard list: {e}")
        return jsonify({"error": "Failed to fetch data"}), 500

@app.route('/api/dashboard/details/<item_type>/<int:item_id>')
@login_required
def get_item_details(item_type, item_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    
    try:
        cursor = conn.cursor(dictionary=True)
        details = {}
        
        if item_type == 'user':
            if current_user.role == 'user' and current_user.id != item_id:
                return jsonify({"error": "Permission denied"}), 403
            
            cursor.execute("SELECT * FROM users WHERE id = %s", (item_id,))
            user = cursor.fetchone()
            
            if user:
                details = {
                    'title': user['name'],
                    'status': user['role'],
                    'contacts': {
                        'phone': user['contact_number'] or 'N/A',
                        'email': user['email']
                    },
                    'visit_source': {
                        'type': 'Direct visit',
                        'location': f"{user.get('city', 'Unknown')}, {user.get('country', 'Unknown')}".replace(", Unknown", "").replace("Unknown, ", ""),
                        'ip': user['last_ip']
                    }
                }
                
        elif item_type == 'chat':
            if current_user.role in ['admin', 'superadmin']:
                cursor.execute("""
                    SELECT ch.*, u.name as user_name, u.email as user_email, u.contact_number as user_contact, 
                           u.city, u.country, u.last_ip 
                    FROM chat_history ch 
                    JOIN users u ON ch.user_id = u.id 
                    WHERE ch.user_id = %s 
                    ORDER BY ch.created_at ASC
                """, (item_id,))
            else:
                cursor.execute("""
                    SELECT ch.*, u.name as user_name, u.email as user_email, u.contact_number as user_contact, 
                           u.city, u.country, u.last_ip 
                    FROM chat_history ch 
                    JOIN users u ON ch.user_id = u.id 
                    WHERE ch.user_id = %s AND ch.user_id = %s 
                    ORDER BY ch.created_at ASC
                """, (item_id, current_user.id))
            
            chat_messages = cursor.fetchall()
            if chat_messages:
                first_chat = chat_messages[0]
                
                chat_log = []
                for chat in chat_messages:
                    chat_log.append({
                        'sender': chat['user_name'],
                        'message': chat['user_message'],
                        'time': chat['created_at'].strftime('%I:%M %p'),
                        'date': chat['created_at'].strftime('%B %d, %Y')
                    })
                    chat_log.append({
                        'sender': 'Bot',
                        'message': chat['bot_response'],
                        'time': chat['created_at'].strftime('%I:%M %p'),
                        'date': chat['created_at'].strftime('%B %d, %Y')
                    })
                
                details = {
                    'title': f"Chat with {first_chat['user_name']}",
                    'status': 'Online',
                    'chat_topic': first_chat['context_url'] or 'General Inquiry',
                    'chat_log': chat_log,
                    'contacts': {
                        'phone': first_chat['user_contact'] or 'N/A',
                        'email': first_chat['user_email']
                    },
                    'visit_source': {
                        'type': 'Direct visit',
                        'location': f"{first_chat.get('city', 'Unknown')}, {first_chat.get('country', 'Unknown')}".replace(", Unknown", "").replace("Unknown, ", ""),
                        'ip': first_chat['last_ip']
                    }
                }
        
        cursor.close()
        conn.close()
        return jsonify(details)
        
    except Exception as e:
        print(f"Error in dashboard details: {e}")
        return jsonify({"error": "Failed to fetch details"}), 500

@app.route('/api/dashboard/statistics')
@login_required
@role_required('admin', 'superadmin')
def get_statistics():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    
    try:
        cursor = conn.cursor(dictionary=True)
       
        # Daily chats for the last 7 days
        daily_chats = {(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'): 0 for i in range(7)}
        seven_days_ago = (datetime.now() - timedelta(days=6)).strftime('%Y-%m-%d 00:00:00')
        
        cursor.execute("SELECT DATE(created_at) as chat_date, COUNT(*) as count FROM chat_history WHERE created_at >= %s GROUP BY DATE(created_at)", (seven_days_ago,))
        for row in cursor.fetchall():
            daily_chats[row['chat_date'].strftime('%Y-%m-%d')] = row['count']

        # User chat counts
        cursor.execute("SELECT u.name, COUNT(ch.id) as message_count FROM users u LEFT JOIN chat_history ch ON u.id = ch.user_id GROUP BY u.id, u.name ORDER BY message_count DESC")
        user_chats = cursor.fetchall()

        stats = {
            'daily_chats': {
                'labels': sorted(daily_chats.keys()),
                'data': [daily_chats[day] for day in sorted(daily_chats.keys())]
            },
            'user_chats': {
                'labels': [user['name'] for user in user_chats],
                'data': [user['message_count'] for user in user_chats]
            }
        }
        
        cursor.close()
        conn.close()
        return jsonify(stats)
        
    except Exception as e:
        print(f"Error in statistics: {e}")
        return jsonify({"error": "Failed to fetch statistics"}), 500

# --- Main Execution ---
def create_tables():
    """Create database tables with improved error handling"""
    conn = get_db_connection()
    if not conn:
        print("❌ Cannot create tables: Database connection failed")
        return False
    
    try:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(150) NOT NULL UNIQUE,
                email VARCHAR(150) UNIQUE,
                google_id VARCHAR(255) UNIQUE,
                name VARCHAR(150),
                password VARCHAR(150),
                last_ip VARCHAR(45),
                contact_number VARCHAR(20),
                city VARCHAR(100),
                region VARCHAR(100),
                country VARCHAR(100),
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
        """)
        
        # Create chat_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                user_message TEXT NOT NULL,
                bot_response TEXT NOT NULL,
                context_url VARCHAR(2048),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database tables are ready.")
        return True
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    if create_tables():
        print("🚀 Starting Flask application...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("❌ Failed to initialize database. Please check your database configuration.")

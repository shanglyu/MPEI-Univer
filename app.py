from flask import Flask, render_template, request, g, make_response, redirect, render_template_string
import jwt
import sqlite3
import datetime
from functools import wraps

app = Flask(__name__)
SECRET = '8PXVxFsBEu'
DATABASE = 'users.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def get_payload(token, key):
    try:
        payload = jwt.decode(token.encode(), SECRET, algorithms=['HS256'])
        print(payload)
        return payload[key].strip()
    except Exception as e:
        print(f'Error: {e}')
        return None

def adduser(username, password, role):
    if role not in ['ADMIN', 'USER']:
        return 2
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    existed = cur.fetchone()

    if existed:
        return 1

    try:
        cur.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
        db.commit()
        return 0
    except:
        return 2

def role_required(required_roles):
    def decorator(view_func):
        @wraps(view_func)
        def decorated_view(*args, **kwargs):
            token = request.cookies.get('token')
            role = get_payload(token, 'role')

            if not role or role not in required_roles:
                response = make_response(redirect('/login'))
                response.set_cookie('token', 'You shall not pass!', expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=30), httponly=True)
                return response

            return view_func(*args, **kwargs)

        return decorated_view

    return decorator

@app.route('/')
@role_required(['ADMIN', 'USER'])
def index():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
@role_required(['ADMIN'])
def admin():
    username = get_payload(request.cookies.get('token'), 'username')
    db = get_db()
    cur = db.cursor()

    cur.execute('SELECT * FROM users WHERE username != ?', (username,))
    users = cur.fetchall()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        status = adduser(username, password, role)
        if status == 1:
            return render_template('admin.html', message=f'Username {username} has been taken!', username=render_template_string(username), users=users)
        elif status == 0:
            return render_template('admin.html', message='Signed up successfully! Now you can <a href="/login">login</a>!', username=render_template_string(username), users=users)
        else:
            return render_template('admin.html', message='Error! Please contact administrators for support!', username=render_template_string(username), users=users)

    return render_template('admin.html', username=render_template_string(username), users=users)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            return render_template('signup.html', message='Username and password are required!')
        
        status = adduser(username, password, 'USER')

        if status == 1:
            return render_template('signup.html', message=f'Username {username} has been taken!')
        elif status == 0:
            return render_template('signup.html', message='Signed up successfully! Now you can <a href="/login">login</a>!')
        else:
            return render_template('signup.html', message='Error! Please contact administrators for support!')

    return render_template('signup.html', message='Enter your username and password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            return render_template('login.html', message='Username and password are required!')
        
        db = get_db()
        cur = db.cursor()

        cur.execute('SELECT id, role FROM users WHERE username = ? AND password = ?', (username, password))
        user = cur.fetchone()

        if user:
            payload = {
                'id': user[0],
                'username': username,
                'role': user[1]
            }
            token = jwt.encode(payload, SECRET, algorithm='HS256')
            
            response = make_response(redirect('/admin')) if user[1] == 'ADMIN' else make_response(redirect('/'))
            response.set_cookie('token', token, expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=30), httponly=True)

            return response

        return render_template('login.html', message='Incorrect username/password!')

    return render_template('login.html', message='Enter your username and password')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555)
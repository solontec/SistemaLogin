from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = '' 
DB_NAME = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                senha BLOB NOT NULL
            )
        ''')
        conn.commit()
        print(f"✅ Tabela 'usuarios' verificada/criada com sucesso em '{DB_NAME}'.")
    except sqlite3.Error as e:
        print(f"❌ Erro ao configurar o banco de dados SQLite: {e}")
    finally:
        if conn:
            conn.close()

def register_user(email, password):
    if not email or not password:
        return False

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO usuarios (email, senha) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        if conn: conn.close()
        return False
    except sqlite3.Error as e:
        print(f"❌ Erro ao registrar usuário no SQLite: {e}")
        if conn: conn.close()
        return False

def login_check(email, password):
    if not email or not password:
        return False

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, senha FROM usuarios WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash = result['senha']
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['user_id'] = result['id']
                return True
        return False
    except sqlite3.Error as e:
        print(f"❌ Erro ao verificar login no SQLite: {e}")
        if conn: conn.close()
        return False

def get_all_users():
    """
    Retorna uma lista de todos os usuários (ID e Email) do banco de dados.
    """
    conn = None
    users = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM usuarios ORDER BY id")
        users = cursor.fetchall()
    except sqlite3.Error as e:
        print(f"❌ Erro ao listar usuários no SQLite: {e}")
    finally:
        if conn:
            conn.close()
    return users


@app.before_request
def before_request():
    setup_database()

@app.route('/')
def index():
    if 'user_id' in session:
        return f"Olá, usuário ID: {session['user_id']}! Você está logado. <a href='/logout'>Sair</a> | <a href='/users'>Ver Usuários</a>"
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if register_user(email, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error='Email já cadastrado ou campos vazios.')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if login_check(email, password):
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Email ou senha incorretos.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/users')
def list_users():
    """
    Rota para exibir todos os usuários cadastrados.
    Apenas acessível se o usuário estiver logado.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    users = get_all_users()
    return render_template('users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)

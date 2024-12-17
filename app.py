from flask import Flask, render_template, request, redirect, url_for, session, current_app, abort
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from os import path
import os
import re
from functools import wraps

app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.environ.get('DB_TYPE', 'postgres')


@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html', login=session.get('login', 'Незнакомец'))


def validate_input(data):
    """
    Проверяет строку на допустимые символы (латинские буквы, цифры, знаки препинания).
    """
    pattern = r'^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{};:\'",.<>?/\\|`~ ]+$'
    return bool(re.match(pattern, data))


def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host = '127.0.0.1',
            database = 'initiatives',
            user = 'initiatives',
            password = '123'
        )
        cur = conn.cursor(cursor_factory =  RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
    return conn, cur


def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()


@app.route('/register', methods = ['GET', 'POST'])
def register():
    if 'login' in session:
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('register.html')

    login = request.form.get('login')
    password = request.form.get('password')

    if not (login and password):
        return render_template('register.html', error='Заполните все поля')

    # Проверяем формат логина и пароля
    if not validate_input(login) or not validate_input(password):
        return render_template('register.html', error='Недопустимые символы в логине или пароле')

    if not (5 <= len(login) <= 30 and 5 <= len(password) <= 162):
        return render_template('register.html', error='Логин должен быть от 5 до 30 символов, пароль – от 5 до 162')

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT login FROM users WHERE login=%s;", (login, ))
    else:
        cur.execute("SELECT login FROM users WHERE login=?;", (login, ))
    
    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Такой пользователь уже существует')
    
    password_hash = generate_password_hash(password)
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO users (login, password) VALUES (%s, %s) RETURNING id;", (login, password_hash))
        user_id = cur.fetchone()['id']
    else:
        cur.execute("INSERT INTO users (login, password) VALUES (?, ?);", (login, password_hash))
        cur.execute("SELECT last_insert_rowid();")
        user_id = cur.fetchone()[0]

    db_close(conn, cur)

    # Сохраняем данные в сессии
    session['login'] = login
    session['user_id'] = user_id

    return render_template('success.html', login=login, action='register')
    

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if 'login' in session:
        return redirect(url_for('index'))
    
    if request.method == 'GET':
        return render_template('login.html')
    
    login = request.form.get('login')
    password = request.form.get('password')

    if not (login and password):
        return render_template('login.html', error='Заполните все поля')
    
    # Проверяем формат логина и пароля
    if not validate_input(login) or not validate_input(password):
        return render_template('register.html', error='Недопустимые символы в логине или пароле')

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE login=%s;", (login, ))
    else:
        cur.execute("SELECT * FROM users WHERE login=?;", (login, ))

    user = cur.fetchone()

    if not user:
        db_close(conn, cur)
        return render_template('login.html',
                               error='Логин и/или пароль неверны')
    
    if not check_password_hash(user['password'], password):
        db_close(conn, cur)
        return render_template('login.html',
                               error='Логин и/или пароль неверны')
    
    session['login'] = login
    session['user_id'] = user['id']
    session['is_admin'] = bool(user['is_admin'])  # Сохраняем статус администратора


    db_close(conn, cur)
    return render_template('success.html', login=login, action='login')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    # Проверяем, авторизован ли пользователь
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Возвращаем шаблон профиля
    return render_template('profile.html')


@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Проверяем, авторизован ли пользователь
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    # Удаляем учетную запись из базы данных
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?;", (user_id,))
    conn.commit()
    db_close(conn, cur)
    
    # Очищаем сессию
    session.clear()
    
    return redirect(url_for('index'))


@app.route('/start', methods=['GET'])
def start():
    page = request.args.get('page', default=1, type=int)
    per_page = 20  # Количество инициатив на одной странице
    offset = (page - 1) * per_page

    conn, cur = db_connect()

    # Выполняем запрос к базе данных
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT id, title, content, created_at, votes, user_id FROM initiatives ORDER BY votes DESC LIMIT %s OFFSET %s;", (per_page, offset))
    else:
        cur.execute("SELECT id, title, content, created_at, votes, user_id FROM initiatives ORDER BY votes DESC LIMIT ? OFFSET ?;", (per_page, offset))

    initiatives = cur.fetchall()
    print(initiatives)  # Проверьте, что данные из БД корректно получены

    # Форматируем дату и добавляем порядковый номер
    formatted_initiatives = []
    for i, initiative in enumerate(initiatives):
        # Преобразуем кортеж или словарь
        if isinstance(initiative, tuple):
            id, title, content, created_at, votes, user_id = initiative
            formatted_initiatives.append({
                'id': id,
                'title': title,
                'content': content,
                'created_at': created_at.strftime("%d.%m.%Y %H:%M") if isinstance(created_at, datetime) else created_at,
                'votes': votes,
                'number': i + 1 + offset,  # Добавляем порядковый номер
                'user_id': user_id
            })
        elif isinstance(initiative, dict):  # Если возвращается словарь
            initiative['created_at'] = initiative['created_at'].strftime("%d.%m.%Y %H:%M") if isinstance(initiative['created_at'], datetime) else initiative['created_at']
            initiative['number'] = i + 1 + offset  # Добавляем порядковый номер
            formatted_initiatives.append(initiative)


    # Проверяем наличие следующей страницы
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT COUNT(*) FROM initiatives;")
    else:
        cur.execute("SELECT COUNT(*) FROM initiatives;")

    total_count = cur.fetchone()

    # Извлекаем общее количество
    if isinstance(total_count, dict):  # Если возвращен словарь
        total_count = total_count['count']
    else:  # Если возвращен кортеж
        total_count = total_count[0]

    has_next_page = (offset + per_page) < total_count

    db_close(conn, cur)

    # Передаем отформатированные данные в шаблон
    return render_template('start.html', initiatives=formatted_initiatives, page=page, has_next_page=has_next_page)


@app.route('/add_initiative', methods=['GET', 'POST'])
def add_initiative():
    # Проверка на авторизацию
    if 'login' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('add_initiative.html')

    title = request.form.get('title')
    content = request.form.get('content')

    if not (title and content):
        return render_template('add_initiative.html', error='Заполните все поля!')

    conn, cur = db_connect()

    if app.config['DB_TYPE'] == 'postgres':
            cur.execute(
                "INSERT INTO initiatives (title, content, created_at, user_id) VALUES (%s, %s, %s, %s);",
                (title, content, datetime.now(), session['user_id'])
            )
    else:
            cur.execute(
                "INSERT INTO initiatives (title, content, created_at, user_id) VALUES (?, ?, ?, ?);",
                (title, content, datetime.now(), session['user_id'])
            )
    
    conn.commit()

    db_close(conn, cur)
    return redirect(url_for('start'))


@app.route('/delete_initiative/<int:initiative_id>', methods=['POST'])
def delete_initiative(initiative_id):
    if 'user_id' not in session:  # Проверяем, авторизован ли пользователь
        return redirect(url_for('login'))

    conn, cur = db_connect()

    if app.config['DB_TYPE'] == 'postgres':
        cur.execute(
            "SELECT id FROM initiatives WHERE id = %s AND user_id = %s;",
            (initiative_id, session['user_id'])
        )
    else:
        cur.execute(
            "SELECT id FROM initiatives WHERE id = ? AND user_id = ?;",
            (initiative_id, session['user_id'])
        )

    if not cur.fetchone():
        abort(403)

    # Удаляем инициативу
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM initiatives WHERE id = %s;", (initiative_id,))
    else:
        cur.execute("DELETE FROM initiatives WHERE id = ?;", (initiative_id,))
    conn.commit()

    db_close(conn, cur)

    return redirect(url_for('start'))


@app.route('/vote', methods=['POST'])
def vote():
    if 'login' not in session:  # Проверяем, авторизован ли пользователь
        return {'success': False, 'error': 'Unauthorized'}, 401

    user_id = session['user_id']  # Предполагаем, что ID пользователя хранится в сессии
    data = request.json
    initiative_id = data.get('id')
    vote_type = data.get('vote') # 'up' или 'down'

    if not initiative_id or vote_type not in ['up', 'down']:
        return {'success': False, 'error': 'Invalid data'}, 400

    conn, cur = db_connect()

    try:
        # Проверяем, голосовал ли пользователь ранее
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT vote_type FROM votes WHERE user_id = %s AND initiative_id = %s;", (user_id, initiative_id))
        else:
            cur.execute("SELECT vote_type FROM votes WHERE user_id = ? AND initiative_id = ?;", (user_id, initiative_id))

        existing_vote = cur.fetchone()

        # Логика обработки голосов
        vote_change = 0
        if existing_vote is not None:
            # Упрощение обработки fetched данных
            existing_vote_type = existing_vote[0] if isinstance(existing_vote, tuple) else existing_vote.get('vote_type')

            if existing_vote_type == vote_type:
                return {'success': False, 'error': 'Вы уже проголосовали таким образом'}, 400

            # Если голос изменился
            vote_change = 2 if vote_type == 'up' else -2  # Изменение на 2, если голос меняется с up на down или наоборот
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute(
                    "DELETE FROM votes WHERE user_id = %s AND initiative_id = %s;",
                    (user_id, initiative_id)
                )
                cur.execute(
                    "INSERT INTO votes (user_id, initiative_id, vote_type) VALUES (%s, %s, %s);",
                    (user_id, initiative_id, vote_type)
                )
            else:
                cur.execute(
                    "DELETE FROM votes WHERE user_id = ? AND initiative_id = ?;",
                    (user_id, initiative_id)
                )
                cur.execute(
                    "INSERT INTO votes (user_id, initiative_id, vote_type) VALUES (?, ?, ?);",
                    (user_id, initiative_id, vote_type)
                )
        else:
            # Новый голос
            vote_change = 1 if vote_type == 'up' else -1
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute(
                    "INSERT INTO votes (user_id, initiative_id, vote_type) VALUES (%s, %s, %s);",
                    (user_id, initiative_id, vote_type)
                )
            else:
                cur.execute(
                    "INSERT INTO votes (user_id, initiative_id, vote_type) VALUES (?, ?, ?);",
                    (user_id, initiative_id, vote_type)
                )

        # Обновляем количество голосов в инициативе
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("UPDATE initiatives SET votes = votes + %s WHERE id = %s;", (vote_change, initiative_id))
        else:
            cur.execute("UPDATE initiatives SET votes = votes + ? WHERE id = ?;", (vote_change, initiative_id))

        # Удаляем инициативу, если голосов меньше -10
        if current_app.config['DB_TYPE'] == 'sqlite':
            cur.execute("SELECT id FROM initiatives WHERE votes < -10 AND id = ?", (initiative_id,))
            deleted_initiative = cur.fetchone()
            if deleted_initiative:
                cur.execute("DELETE FROM initiatives WHERE id = ?", (initiative_id,))
        else:
            cur.execute("DELETE FROM initiatives WHERE votes < -10 AND id = %s RETURNING id;", (initiative_id,))
            deleted_initiative = cur.fetchone()

        if deleted_initiative:
            conn.commit()
            return {'success': True, 'deleted': True, 'updated_votes': None}, 200

        # Получаем обновленное количество голосов
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT votes FROM initiatives WHERE id = %s;", (initiative_id,))
        else:
            cur.execute("SELECT votes FROM initiatives WHERE id = ?;", (initiative_id,))

        updated_votes = cur.fetchone()
        conn.commit()

        if updated_votes is None:
            return {'success': False, 'error': 'Не удалось получить обновленные голоса'}, 500

        if isinstance(updated_votes, dict):  # Если возвращен словарь
            updated_votes = updated_votes['votes']
        else:  # Если возвращен кортеж
            updated_votes = updated_votes[0]

        return {'success': True, 'updated_votes': updated_votes, 'deleted': False}, 200

    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}, 500
    finally:
        db_close(conn, cur)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn, cur = db_connect()
        try:
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("SELECT is_admin FROM users WHERE id = %s;", (session['user_id'],))
            else:
                cur.execute("SELECT is_admin FROM users WHERE id = ?;", (session['user_id'],))
            user = cur.fetchone()
            if not user or not user['is_admin']:
                abort(403)  # Запрещено
        finally:
            db_close(conn, cur)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    conn, cur = db_connect()
    cur.execute("SELECT id, login, is_admin FROM users;")
    users = cur.fetchall()
    db_close(conn, cur)
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn, cur = db_connect()

    if request.method == 'GET':
        cur.execute("SELECT id, login, is_admin FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()
        if not user:
            abort(404)
        return render_template('edit_user.html', user=user)

    # POST: обновляем пользователя
    login = request.form.get('login')
    is_admin = request.form.get('is_admin') == 'on'

    cur.execute(
        "UPDATE users SET login = %s, is_admin = %s WHERE id = %s;",
        (login, is_admin, user_id)
    )
    conn.commit()
    
    db_close(conn, cur)
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn, cur = db_connect()
    cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
    conn.commit()
    db_close(conn, cur)
    return redirect(url_for('admin_users'))


@app.route('/admin/initiatives/delete/<int:initiative_id>', methods=['POST'])
@admin_required
def admin_delete_initiative(initiative_id):
    conn, cur = db_connect()
    cur.execute("DELETE FROM initiatives WHERE id = %s;", (initiative_id,))
    conn.commit()
    db_close(conn, cur)
    return redirect(url_for('start'))


@app.errorhandler(404)
def not_found(err):
    return "нет такой страницы", 404


@app.errorhandler(500)
def server_error(err):
    return "ошибка сервера", 500


from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

# Constants
SECRET_KEY = "your_secret_key_here"  # Replace with a secure value
MONGO_URI = "mongodb://localhost:27017"
DATABASE_NAME = 'user_database'
USER_COLLECTION_NAME = 'users'

# Flash Messages
ERROR_EMAIL_MISMATCH = "Os e-mails não coincidem. Tente novamente!"
ERROR_PASSWORD_MISMATCH = "As senhas não coincidem. Tente novamente!"
ERROR_EMAIL_REGISTERED = "Este e-mail já está registrado. Por favor, use outro."
ERROR_USER_NOT_FOUND = "Usuário não encontrado. Por favor, tente novamente."
ERROR_PASSWORD_INCORRECT = "A senha atual está incorreta. Por favor, tente novamente."
ERROR_ACCOUNT_CREATION = "Erro ao criar a conta: "
ERROR_PASSWORD_CHANGE = "Erro ao alterar sua senha: "
SUCCESS_ACCOUNT_CREATED = "Conta criada com sucesso! Faça login agora."
SUCCESS_PASSWORD_CHANGED = "Sua senha foi alterada com sucesso!"
SUCCESS_LOGIN = "Bem-vindo de volta, {}!"

# App setup
app = Flask(__name__)
app.secret_key = SECRET_KEY
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
user_collection = db[USER_COLLECTION_NAME]  # Renamed for clarity


# Utility functions
def validate_input_match(input1, input2, error_message):
    """Validates if two inputs match and flashes an error if they do not."""
    if input1 != input2:
        flash(error_message, "error")
        return False
    return True


def is_email_registered(email):
    """Checks if the email is already registered."""
    if user_collection.find_one({"email": email}):
        flash(ERROR_EMAIL_REGISTERED, "error")
        return True
    return False


def generate_hashed_password(password):
    """Generates a hashed password."""
    return generate_password_hash(password)


def handle_database_error(action, redirect_route):
    """Handles database-related errors gracefully."""
    try:
        action()
    except Exception as e:
        flash(f"{redirect_route}: {str(e)}", "error")
        return redirect(url_for(redirect_route))


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/lobby')
def lobby():
    return render_template('lobby.html')


@app.route('/change_nickname', methods=['GET', 'POST'])
def change_nickname():
    if request.method == 'POST':
        user_email = request.form.get('email')
        current_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        proposed_nickname = request.form.get('nickname')

        if not validate_input_match(current_password, confirm_password, ERROR_PASSWORD_MISMATCH):
            return redirect(url_for('change_nickname'))

        user = user_collection.find_one({"email": user_email})

        if not user or not check_password_hash(user['password'], current_password):
            flash_error_message("A senha atual está incorreta. Por favor, tente novamente.")
            return redirect(url_for('change_nickname'))

        if not validate_nickname_length(proposed_nickname):
            flash_error_message("O nickname deve ter entre 5 e 50 caracteres.")
            return redirect(url_for('change_nickname'))

        if update_nickname(user_email, proposed_nickname):
            flash("Seu nickname foi alterado com sucesso!", "success")
            return redirect(url_for('lobby'))

        flash_error_message("Erro desconhecido ou conflito com nome de usuário existente.")
        return redirect(url_for('change_nickname'))

    return render_template('change_nickname.html')

def validate_nickname_length(nickname):
    return 5 <= len(nickname) <= 50

def update_nickname(email, new_nickname):
    try:
        user_collection.update_one({"email": email}, {"$set": {"username": new_nickname}})
        return True
    except Exception as e:
        flash_error_message(f"Ocorreu um erro ao alterar o nickname: {str(e)}")
        return False

def flash_error_message(message):
    flash(message, "error")

@app.route('/lobby/train')
def train():
    return render_template('train.html')


@app.route('/lobby/history')
def history():
    return render_template('history.html')


@app.route('/lobby/game')
def game():
    return render_template('game.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Validate input
        if not validate_input_match(new_password, confirm_new_password, ERROR_PASSWORD_MISMATCH):
            return redirect(url_for('change_password'))  # Passwords don't match

        user = user_collection.find_one({"email": email})
        if not user:
            flash(ERROR_USER_NOT_FOUND, "error")
            return redirect(url_for('change_password'))

        if not check_password_hash(user['password'], current_password):
            flash(ERROR_PASSWORD_INCORRECT, "error")
            return redirect(url_for('change_password'))

        hashed_password = generate_hashed_password(new_password)
        handle_database_error(
            lambda: user_collection.update_one({"email": email}, {"$set": {"password": hashed_password}}),
            "change_password"
        )
        flash(SUCCESS_PASSWORD_CHANGED, "success")
        return redirect(url_for('home'))

    return render_template('change_password.html')


@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        confirm_email = request.form.get('confirm_email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if not validate_input_match(email, confirm_email, ERROR_EMAIL_MISMATCH) or \
                not validate_input_match(password, confirm_password, ERROR_PASSWORD_MISMATCH) or \
                is_email_registered(email):
            return redirect(url_for('create_account'))

        hashed_password = generate_hashed_password(password)
        user_data = {"username": username, "email": email, "password": hashed_password}
        handle_database_error(lambda: user_collection.insert_one(user_data), "create_account")
        flash(SUCCESS_ACCOUNT_CREATED, "success")
        return redirect(url_for('home'))

    return render_template('create_account.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = user_collection.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            flash(SUCCESS_LOGIN.format(user['username']), "success")
            return redirect(url_for('lobby'))

        flash("Credenciais inválidas. Tente novamente!", "error")
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, jsonify
from app.models import db, User, RoleEnum
from app.rbac import get_current_user

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            flash(f"Welcome back, {user.username}! Logged in as {user.role}.", "success")
            next_url = request.args.get('next')
            return redirect(next_url or url_for('routes.dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html')

@auth_bp.route('/quick-login/<username>', methods=['POST', 'GET'])
def quick_login(username: str):
    """Convenience endpoint for pair programming / demo testing role switching."""
    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f"User {username} not found. Ensure the database is seeded.", "danger")
        return redirect(url_for('auth.login'))

    session.clear()
    session['user_id'] = user.id
    flash(f"Switched session to {user.username} ({user.role}).", "info")
    return redirect(url_for('routes.dashboard'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user():
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', RoleEnum.VIEWER.value)

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template('register.html')

        valid_roles = [r.value for r in RoleEnum]
        if role not in valid_roles:
            role = RoleEnum.VIEWER.value

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash(f"Account created successfully for {username} with role {role}! Please log in.", "success")
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('auth.login'))

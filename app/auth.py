from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, jsonify
from app.models import db, User, RoleEnum
from app.rbac import get_current_user

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/me', methods=['GET'])
def get_auth_me():
    """Returns the currently authenticated session user or null."""
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "user": None}), 200
    return jsonify({
        "authenticated": True,
        "user": user.to_dict()
    }), 200

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    current_user = get_current_user()
    if current_user:
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "authenticated": True,
                "user": current_user.to_dict(),
                "redirect": url_for('routes.dashboard')
            }), 200
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        data = request.get_json(silent=True) if request.is_json else None
        if data:
            username = str(data.get('username', '')).strip()
            password = str(data.get('password', ''))
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            flash(f"Welcome back, {user.username}! Logged in as {user.role}.", "success")
            next_url = request.args.get('next') or url_for('routes.dashboard')

            if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                return jsonify({
                    "success": True,
                    "message": f"Welcome back, {user.username}!",
                    "user": user.to_dict(),
                    "redirect": next_url
                }), 200

            return redirect(next_url)
        else:
            if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                return jsonify({
                    "success": False,
                    "error": "Invalid username or password."
                }), 401
            flash("Invalid username or password.", "danger")

    return render_template('login.html')

@auth_bp.route('/quick-login/<username>', methods=['POST', 'GET'])
def quick_login(username: str):
    """Convenience endpoint for pair programming / demo testing role switching."""
    user = User.query.filter_by(username=username).first()
    if not user:
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({"success": False, "error": f"User {username} not found."}), 404
        flash(f"User {username} not found. Ensure the database is seeded.", "danger")
        return redirect(url_for('auth.login'))

    session.clear()
    session['user_id'] = user.id
    flash(f"Switched session to {user.username} ({user.role}).", "info")

    if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
        return jsonify({
            "success": True,
            "message": f"Switched session to {user.username} ({user.role}).",
            "user": user.to_dict(),
            "redirect": url_for('routes.dashboard')
        }), 200

    return redirect(url_for('routes.dashboard'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    current_user = get_current_user()
    if current_user:
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "authenticated": True,
                "user": current_user.to_dict(),
                "redirect": url_for('routes.dashboard')
            }), 200
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        data = request.get_json(silent=True) if request.is_json else None
        if data:
            username = str(data.get('username', '')).strip()
            email = str(data.get('email', '')).strip()
            password = str(data.get('password', ''))
            role = str(data.get('role', RoleEnum.VIEWER.value))
        else:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            role = request.form.get('role', RoleEnum.VIEWER.value)

        if not username or not email or not password:
            msg = "All fields are required."
            if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "danger")
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            msg = "Username already exists."
            if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                return jsonify({"success": False, "error": msg}), 409
            flash(msg, "danger")
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            msg = "Email already registered."
            if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                return jsonify({"success": False, "error": msg}), 409
            flash(msg, "danger")
            return render_template('register.html')

        valid_roles = [r.value for r in RoleEnum]
        if role not in valid_roles:
            role = RoleEnum.VIEWER.value

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "success": True,
                "message": f"Account created successfully for {username} with role {role}!",
                "user": user.to_dict(),
                "redirect": url_for('auth.login')
            }), 201

        flash(f"Account created successfully for {username} with role {role}! Please log in.", "success")
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash("You have been securely logged out.", "info")
    if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
        return jsonify({
            "success": True,
            "message": "You have been securely logged out.",
            "redirect": url_for('auth.login')
        }), 200
    return redirect(url_for('auth.login'))


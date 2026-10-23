import os
from flask import Flask, render_template, jsonify, request
from app.config import Config
from app.models import db, User, RoleEnum
from app.rbac import get_current_user

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Register blueprints
    from app.auth import auth_bp
    from app.routes import routes_bp
    from app.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)
    app.register_blueprint(admin_bp)

    # Context processor for templates
    @app.context_processor
    def inject_user():
        return {
            'current_user': get_current_user(),
            'RoleEnum': RoleEnum
        }

    # Custom Jinja filters
    @app.template_filter('short_hash')
    def short_hash_filter(value):
        if not value:
            return ""
        if value == "GENESIS":
            return "GENESIS"
        return f"{value[:8]}...{value[-6:]}"

    @app.template_filter('format_bytes')
    def format_bytes_filter(size):
        try:
            size = float(size)
        except (TypeError, ValueError):
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    # Security error handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "error": "Forbidden",
                "message": getattr(error, 'description', "Access forbidden by server-side RBAC policy."),
                "status": 403
            }), 403
        return render_template('error.html', code=403, title="403 Forbidden", description=getattr(error, 'description', "Access denied. Server-side RBAC policy violation.")), 403

    @app.errorhandler(401)
    def unauthorized_error(error):
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication credentials required.",
                "status": 401
            }), 401
        return render_template('error.html', code=401, title="401 Unauthorized", description="Authentication is required to access this resource."), 401

    @app.errorhandler(404)
    def not_found_error(error):
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "error": "Not Found",
                "message": getattr(error, 'description', "Resource not found."),
                "status": 404
            }), 404
        return render_template('error.html', code=404, title="404 Not Found", description=getattr(error, 'description', "The requested document or resource was not found.")), 404

    @app.errorhandler(500)
    def internal_error(error):
        if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred.",
                "status": 500
            }), 500
        return render_template('error.html', code=500, title="500 Internal Server Error", description="An internal server error occurred."), 500

    return app

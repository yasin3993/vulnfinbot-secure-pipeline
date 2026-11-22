"""Mini-VulnFinBot application factory."""
import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

MAX_CONTENT_LENGTH = 16 * 1024  # 16 KB request body limit


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["JSON_SORT_KEYS"] = False
    if config:
        app.config.update(config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    from .routes import bp
    app.register_blueprint(bp)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers.pop("Server", None)
        return response

    @app.errorhandler(HTTPException)
    def handle_http_error(err):
        return jsonify({"error": err.name}), err.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(err):  # never leak stack traces
        app.logger.error("Unhandled error: %s", type(err).__name__)
        return jsonify({"error": "Internal server error"}), 500

    return app

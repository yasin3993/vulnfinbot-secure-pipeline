import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")  # nosec B104 - required inside the container
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=False)

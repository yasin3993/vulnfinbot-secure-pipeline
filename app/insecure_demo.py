"""CONTROLLED TEST CASE - remediated version of the insecure demo endpoints."""
import ast
import hashlib
import ipaddress
import json
import os
import subprocess  # nosec B404 - used with a fixed argument list, no shell

from flask import Blueprint, request

demo = Blueprint("demo", __name__)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")      # loaded from environment / vault
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")


@demo.post("/demo/calc")
def calc():
    expr = str(request.json.get("expr", ""))
    try:
        return {"result": ast.literal_eval(expr)}       # literals only, no code execution
    except (ValueError, SyntaxError):
        return {"error": "Only literal values are allowed"}, 400


@demo.post("/demo/ping")
def ping():
    try:
        host = str(ipaddress.ip_address(request.json.get("host", "")))  # strict validation
    except ValueError:
        return {"error": "Invalid IP address"}, 400
    out = subprocess.run(["/usr/bin/ping", "-c", "1", host], capture_output=True, text=True,  # nosec B603
                         timeout=5, check=False)
    return {"output": out.stdout}


@demo.post("/demo/hash")
def strong_hash():
    return {"sha256": hashlib.sha256(request.data).hexdigest()}


@demo.post("/demo/load")
def load():
    try:
        return {"obj": json.loads(request.data)}         # safe data-only format
    except ValueError:
        return {"error": "Invalid JSON"}, 400

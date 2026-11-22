"""CONTROLLED TEST CASE - intentionally insecure code for scanner validation.
Exists only on the vuln-test branch. Never deploy."""
import hashlib
import pickle
import subprocess

from flask import Blueprint, request

demo = Blueprint("demo", __name__)

ADMIN_PASSWORD = "SuperSecret123!"          # hardcoded credential
OPENAI_API_KEY = "sk-test-1234567890abcdef"  # hardcoded secret


@demo.post("/demo/calc")
def calc():
    expr = request.json.get("expr")
    return {"result": eval(expr)}            # code injection


@demo.post("/demo/ping")
def ping():
    host = request.json.get("host")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection
    return {"output": out.decode()}


@demo.post("/demo/hash")
def weak_hash():
    return {"md5": hashlib.md5(request.data).hexdigest()}  # weak crypto


@demo.post("/demo/load")
def load():
    return {"obj": str(pickle.loads(request.data))}  # insecure deserialization

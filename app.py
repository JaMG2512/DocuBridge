import os, json, time, uuid, hmac, hashlib, mimetypes
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, render_template
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv

# Opcional: filetype (si no lo tienes, se usará mimetypes)
try:
    import filetype
except ImportError:
    filetype = None

# --- Configuración ---
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))
ALLOWED_EXTS = set(
    e.strip().lower()
    for e in os.getenv("ALLOWED_EXTS", "pdf,txt,jpg,jpeg,png,zip,mp3,mp4").split(",")
    if e.strip()
)
ALLOWED_MIME = set(
    m.strip().lower()
    for m in os.getenv(
        "ALLOWED_MIME",
        "application/pdf,text/plain,image/jpeg,image/png,application/zip",
    ).split(",")
    if m.strip()
)
RETENTION_HOURS = int(os.getenv("RETENTION_HOURS", "24"))
STORAGE_DIR = os.getenv("STORAGE_DIR", "storage")
REQUIRE_PASSWORD = os.getenv("REQUIRE_PASSWORD", "false").lower() == "true"

FILES_DIR = os.path.join(STORAGE_DIR, "files")
META_DIR = os.path.join(STORAGE_DIR, "meta")
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
ts = URLSafeTimedSerializer(SECRET_KEY)

# --- Utilidades ---
def meta_path(fid: str) -> str:
    return os.path.join(META_DIR, f"{fid}.json")


def save_meta(fid: str, data: dict):
    tmp = meta_path(fid) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, meta_path(fid))


def load_meta(fid: str) -> dict | None:
    p = meta_path(fid)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def guess_mime_from_head(head: bytes, fname: str) -> str:
    if filetype:
        try:
            kind = filetype.guess(head)
            if kind:
                return kind.mime.lower()
        except Exception:
            pass
    guess, _ = mimetypes.guess_type(fname)
    return (guess or "application/octet-stream").lower()


def allowed_extension(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_EXTS


def allowed_mime_type(mime: str) -> bool:
    return mime in ALLOWED_MIME


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pw_hash(password: str, salt: bytes = None, iters: int = 200_000):
    if not password:
        return None, None, None
    salt = os.urandom(16) if salt is None else salt
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
    return dk.hex(), salt.hex(), iters


def pw_verify(password: str, salt_hex: str, iters: int, expected_hex: str) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iters, dklen=32)
    return hmac.compare_digest(dk.hex(), expected_hex)


def make_download_token(fid: str) -> str:
    return ts.dumps({"fid": fid})


def verify_download_token(token: str, max_age_seconds: int) -> str:
    data = ts.loads(token, max_age=max_age_seconds)
    return data.get("fid")

# --- Rutas principales ---
@app.get("/")
def home():
    """Página principal HTML"""
    return render_template("index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "time": int(time.time())}


@app.post("/api/upload")
def upload():
    if "file" not in request.files:
        return jsonify({"error": "faltó 'file' en form-data"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "nombre de archivo vacío"}), 400
    if not allowed_extension(f.filename):
        return jsonify({"error": "extensión no permitida", "allowed_exts": sorted(ALLOWED_EXTS)}), 400

    head = f.read(262)
    mime = guess_mime_from_head(head, f.filename)
    if not allowed_mime_type(mime):
        return jsonify({"error": "MIME no permitido", "detected_mime": mime, "allowed_mime": sorted(ALLOWED_MIME)}), 400
    f.seek(0)

    fid = str(uuid.uuid4())
    safe_name = secure_filename(f.filename)
    stored_name = f"{fid}__{safe_name}"
    dest_path = os.path.join(FILES_DIR, stored_name)
    f.save(dest_path)

    file_sha = sha256_file(dest_path)
    size = os.path.getsize(dest_path)

    pw = request.form.get("password")
    pw_hash_hex, pw_salt_hex, pw_iters = (None, None, None)
    if pw:
        pw_hash_hex, pw_salt_hex, pw_iters = pw_hash(pw)

    created = int(time.time())
    meta = {
        "id": fid,
        "original_name": safe_name,
        "stored_name": stored_name,
        "size": size,
        "mime": mime,
        "sha256": file_sha,
        "created_at": created,
        "pw_hash": pw_hash_hex,
        "pw_salt": pw_salt_hex,
        "pw_iters": pw_iters,
    }
    save_meta(fid, meta)

    token = make_download_token(fid)
    max_age = RETENTION_HOURS * 3600
    download_url = f"/api/download/{fid}?token={token}"

    return jsonify({
        "file_id": fid,
        "original_name": safe_name,
        "size": size,
        "mime": mime,
        "sha256": file_sha,
        "download_url": download_url,
        "link_expires_in_seconds": max_age,
        "password_protected": bool(pw)
    }), 201


@app.get("/api/download/<file_id>")
def download(file_id):
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "falta token"}), 401
    try:
        fid = verify_download_token(token, RETENTION_HOURS * 3600)
    except SignatureExpired:
        return jsonify({"error": "enlace expirado"}), 410
    except BadSignature:
        return jsonify({"error": "token inválido"}), 401
    if fid != file_id:
        return jsonify({"error": "token no coincide con el archivo"}), 401

    meta = load_meta(file_id)
    if not meta:
        return jsonify({"error": "archivo no encontrado"}), 404

    # Password si aplica
    if meta.get("pw_hash") is not None or REQUIRE_PASSWORD:
        supplied_pw = request.args.get("password") or request.headers.get("X-Download-Password")
        if not supplied_pw:
            return jsonify({"error": "se requiere contraseña"}), 401
        if meta.get("pw_hash") is None:
            return jsonify({"error": "descarga bloqueada por política; resube con contraseña"}), 401
        if not pw_verify(supplied_pw, meta["pw_salt"], meta["pw_iters"], meta["pw_hash"]):
            return jsonify({"error": "contraseña incorrecta"}), 403

    return send_from_directory(
        directory=FILES_DIR,
        path=meta["stored_name"],
        as_attachment=True,
        download_name=meta["original_name"]
    )


@app.get("/api/meta/<file_id>")
def meta_info(file_id):
    meta = load_meta(file_id)
    if not meta:
        return jsonify({"error": "no encontrado"}), 404
    created = datetime.utcfromtimestamp(meta["created_at"])
    return jsonify({
        **{k: meta[k] for k in ["id", "original_name", "size", "mime", "sha256", "created_at"]},
        "created_at_iso": created.isoformat() + "Z",
        "expires_at_iso": (created + timedelta(hours=RETENTION_HOURS)).isoformat() + "Z"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

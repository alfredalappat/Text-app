import os
import secrets
import sqlite3
from datetime import date, datetime

from flask import Flask, g, jsonify, request, session
from flask_socketio import SocketIO, join_room
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "static", "uploads")
DB_PATH = os.path.join(BASE, "app.db")
KEY_PATH = os.path.join(BASE, "secret.key")
os.makedirs(UPLOADS, exist_ok=True)

if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "w") as f:
        f.write(secrets.token_hex(32))
with open(KEY_PATH) as f:
    SECRET = f.read().strip()

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = SECRET
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB (profile photos only)
socketio = SocketIO(app, async_mode="threading")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash TEXT NOT NULL,
  photo TEXT NOT NULL,
  dob TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS likes(
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created TEXT NOT NULL
);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def err(msg, status=400, **extra):
    return jsonify(error=msg, **extra), status


def me_id():
    return session.get("uid")


def require_login():
    return me_id() is not None


def user_json(row):
    return {"id": row["id"], "username": row["username"], "photo": "/uploads/" + row["photo"]}


def age_of(dob_str):
    d = datetime.strptime(dob_str, "%Y-%m-%d").date()
    t = date.today()
    return t.year - d.year - ((t.month, t.day) < (d.month, d.day))


def posts_query(where="", params=(), order="p.id DESC", limit=None):
    sql = f"""
    SELECT p.id, p.body, p.created, u.id AS uid, u.username, u.photo,
      (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments,
      EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked
    FROM posts p JOIN users u ON u.id = p.user_id
    {where} ORDER BY {order}
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = db().execute(sql, (me_id(),) + tuple(params)).fetchall()
    return [
        {
            "id": r["id"], "body": r["body"], "created": r["created"],
            "author": {"id": r["uid"], "username": r["username"], "photo": "/uploads/" + r["photo"]},
            "likes": r["likes"], "comments": r["comments"], "liked": bool(r["liked"]),
        }
        for r in rows
    ]


# ---------- auth ----------
@app.post("/api/register")
def register():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    dob = (request.form.get("dob") or "").strip()
    photo = request.files.get("photo")

    if not (username and email and password and confirm and dob):
        return err("Please fill in all fields.")
    if "@" not in email or "." not in email.split("@")[-1]:
        return err("Enter a valid email address.")
    if password != confirm:
        return err("Passwords do not match.")
    if len(password) < 4:
        return err("Password must be at least 4 characters.")
    try:
        age = age_of(dob)
    except ValueError:
        return err("Enter a valid date of birth.")
    if age < 18:
        return err("You must be 18 or older to register.")
    if age > 120:
        return err("Enter a valid date of birth.")
    if not photo or not photo.filename:
        return err("Please choose a profile photo.")
    ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if ext not in ALLOWED_EXT:
        return err("Photo must be a png, jpg, gif or webp image.")

    d = db()
    if d.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return err("This email is already registered.")
    if d.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return err("This username is taken.")

    fname = secrets.token_hex(12) + "." + ext
    photo.save(os.path.join(UPLOADS, fname))
    cur = d.execute(
        "INSERT INTO users(username,email,pw_hash,photo,dob) VALUES(?,?,?,?,?)",
        (username, email, generate_password_hash(password), fname, dob),
    )
    d.commit()
    session["uid"] = cur.lastrowid
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return err("Enter your email and password.")
    row = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return err("This email is not registered.", 404, code="not_registered")
    if not check_password_hash(row["pw_hash"], password):
        return err("Wrong password.", 401)
    session["uid"] = row["id"]
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if not require_login():
        return err("Not logged in.", 401)
    r = db().execute("SELECT * FROM users WHERE id = ?", (me_id(),)).fetchone()
    if not r:
        session.clear()
        return err("Not logged in.", 401)
    return jsonify(id=r["id"], username=r["username"], email=r["email"], photo="/uploads/" + r["photo"])


# ---------- posts ----------
@app.get("/api/posts/random")
def random_posts():
    if not require_login():
        return err("Not logged in.", 401)
    return jsonify(posts_query(order="RANDOM()", limit=30))


@app.get("/api/posts/mine")
def my_posts():
    if not require_login():
        return err("Not logged in.", 401)
    return jsonify(posts_query("WHERE p.user_id = ?", (me_id(),)))


@app.post("/api/posts")
def create_post():
    if not require_login():
        return err("Not logged in.", 401)
    body = (request.get_json(silent=True) or {}).get("body", "")
    if not body.strip():
        return err("Write something first.")
    db().execute("INSERT INTO posts(user_id,body,created) VALUES(?,?,?)", (me_id(), body, now()))
    db().commit()
    return jsonify(ok=True)


@app.post("/api/posts/<int:pid>/like")
def toggle_like(pid):
    if not require_login():
        return err("Not logged in.", 401)
    d = db()
    if not d.execute("SELECT 1 FROM posts WHERE id = ?", (pid,)).fetchone():
        return err("Post not found.", 404)
    ex = d.execute("SELECT 1 FROM likes WHERE user_id=? AND post_id=?", (me_id(), pid)).fetchone()
    if ex:
        d.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (me_id(), pid))
    else:
        d.execute("INSERT INTO likes(user_id,post_id) VALUES(?,?)", (me_id(), pid))
    d.commit()
    n = d.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (pid,)).fetchone()[0]
    return jsonify(liked=not ex, likes=n)


@app.get("/api/posts/<int:pid>/comments")
def list_comments(pid):
    if not require_login():
        return err("Not logged in.", 401)
    rows = db().execute(
        """SELECT c.id, c.body, c.created, u.id AS uid, u.username, u.photo
           FROM comments c JOIN users u ON u.id = c.user_id
           WHERE c.post_id = ? ORDER BY c.id""",
        (pid,),
    ).fetchall()
    return jsonify([
        {"id": r["id"], "body": r["body"], "created": r["created"],
         "author": {"id": r["uid"], "username": r["username"], "photo": "/uploads/" + r["photo"]}}
        for r in rows
    ])


@app.post("/api/posts/<int:pid>/comments")
def add_comment(pid):
    if not require_login():
        return err("Not logged in.", 401)
    body = (request.get_json(silent=True) or {}).get("body", "")
    if not body.strip():
        return err("Write a comment first.")
    d = db()
    if not d.execute("SELECT 1 FROM posts WHERE id = ?", (pid,)).fetchone():
        return err("Post not found.", 404)
    d.execute("INSERT INTO comments(post_id,user_id,body,created) VALUES(?,?,?,?)", (pid, me_id(), body, now()))
    d.commit()
    n = d.execute("SELECT COUNT(*) FROM comments WHERE post_id=?", (pid,)).fetchone()[0]
    return jsonify(ok=True, comments=n)


@app.delete("/api/posts/<int:pid>")
def delete_post(pid):
    if not require_login():
        return err("Not logged in.", 401)
    d = db()
    row = d.execute("SELECT user_id FROM posts WHERE id = ?", (pid,)).fetchone()
    if not row:
        return err("Post not found.", 404)
    if row["user_id"] != me_id():
        return err("You can only delete your own posts.", 403)
    d.execute("DELETE FROM likes WHERE post_id = ?", (pid,))
    d.execute("DELETE FROM comments WHERE post_id = ?", (pid,))
    d.execute("DELETE FROM posts WHERE id = ?", (pid,))
    d.commit()
    return jsonify(ok=True)


# ---------- chats ----------
@app.get("/api/chats")
def chats():
    if not require_login():
        return err("Not logged in.", 401)
    me = me_id()
    rows = db().execute(
        """
        SELECT u.id, u.username, u.photo, m.body, m.created
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = :me THEN m.receiver_id ELSE m.sender_id END
        WHERE m.id IN (
          SELECT MAX(id) FROM messages
          WHERE sender_id = :me OR receiver_id = :me
          GROUP BY CASE WHEN sender_id = :me THEN receiver_id ELSE sender_id END
        )
        ORDER BY m.id DESC
        """,
        {"me": me},
    ).fetchall()
    return jsonify([
        {"user": {"id": r["id"], "username": r["username"], "photo": "/uploads/" + r["photo"]},
         "last": r["body"], "created": r["created"]}
        for r in rows
    ])


@app.get("/api/chats/<int:uid>")
def chat_messages(uid):
    if not require_login():
        return err("Not logged in.", 401)
    d = db()
    u = d.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not u:
        return err("User not found.", 404)
    rows = d.execute(
        """SELECT id, sender_id, body, created FROM messages
           WHERE (sender_id=:a AND receiver_id=:b) OR (sender_id=:b AND receiver_id=:a)
           ORDER BY id""",
        {"a": me_id(), "b": uid},
    ).fetchall()
    return jsonify(
        user=user_json(u),
        messages=[{"id": r["id"], "mine": r["sender_id"] == me_id(), "body": r["body"], "created": r["created"]} for r in rows],
    )


@app.post("/api/chats/<int:uid>")
def send_message(uid):
    if not require_login():
        return err("Not logged in.", 401)
    if uid == me_id():
        return err("You cannot message yourself.")
    d = db()
    if not d.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
        return err("User not found.", 404)
    body = (request.get_json(silent=True) or {}).get("body", "")
    if not body.strip():
        return err("Write a message first.")
    ts = now()
    cur = d.execute("INSERT INTO messages(sender_id,receiver_id,body,created) VALUES(?,?,?,?)", (me_id(), uid, body, ts))
    d.commit()
    payload = {"id": cur.lastrowid, "from": me_id(), "to": uid, "body": body, "created": ts}
    # push instantly to both people (every open tab/device of each user)
    socketio.emit("message", payload, to=f"user:{uid}")
    socketio.emit("message", payload, to=f"user:{me_id()}")
    return jsonify(ok=True)


@socketio.on("connect")
def on_connect():
    uid = session.get("uid")
    if uid is None:
        return False  # reject sockets from logged-out visitors
    join_room(f"user:{uid}")


@app.get("/")
def index():
    return app.send_static_file("index.html")


init_db()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), allow_unsafe_werkzeug=True)

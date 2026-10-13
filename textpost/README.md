# TextPost

A simple text-posting web app (Flask + SQLite + WebSockets, plain HTML/JS front end).

## Run locally
```
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000

## Deploy on Render
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn --worker-class gthread --threads 100 -w 1 app:app`
- Keep it to ONE worker (-w 1): live chat connections are kept in that process.
- Free plan: data (SQLite file, photos) is erased on restart/redeploy/spin-down.

## Features
- Login (email + password). Unregistered email -> message with a Register link.
- Register: username, photo, email, password, confirm password, date of birth (18+ only).
- No email/phone verification, no password reset.
- Bottom bar: Home (random posts), Chats, Post, Profile.
- Posts of any length. Like (toggle) and comment on every post.
- Chats are instant (WebSocket). Tap a username on a post to start a chat.
- Profile: name, photo, email, password (masked), your posts with like counts.
  Delete button on your own posts appears only here, with an in-app confirmation popup.

Data lives in app.db and static/uploads/ next to app.py. Delete them to reset.

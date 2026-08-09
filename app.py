import shutil
import os
import mysql.connector
import random
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

CHAR = [
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9','!','"','#',
    '$','%','&',"'",'(',')','+',',','-','.','/',':',
    ';','<','=','>','?','@','[','\\',']','^','_','`','{','|','}','~',' '
]

DESTINATION_FOLDER = r"C:\Users\squar\OneDrive\Desktop\encrypted_file"

def get_db():
    db = mysql.connector.connect(
        host="localhost", user="root",
        password="password", database="encry_registration"
    )
    cur = db.cursor(buffered=True)  # fixes "Unread result found" error
    return db, cur

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ── REGISTER ──────────────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name     = data.get('name', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400
    if '@' not in email:
        return jsonify({'success': False, 'message': 'Invalid email format.'}), 400

    idx = email.index('@')
    if '@gmail.com' not in email[idx:]:
        return jsonify({'success': False, 'message': 'Only Gmail addresses allowed (e.g. you@gmail.com).'}), 400

    db, cur = get_db()
    try:
        cur.execute("SELECT Email FROM data")
        existing = [r[0] for r in cur.fetchall()]
        if email in existing:
            return jsonify({'success': False, 'message': 'Email already exists. Use a different one.'}), 409
        cur.execute("INSERT INTO data (Name, Email, Password) VALUES (%s, %s, %s)", (name, email, password))
        db.commit()
        return jsonify({'success': True, 'message': f'Account created! Welcome, {name}.'})
    finally:
        cur.close(); db.close()

# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email    = data.get('email', '').strip()
    password = data.get('password', '').strip()

    db, cur = get_db()
    try:
        cur.execute("SELECT * FROM data WHERE Email = %s AND Password = %s", (email, password))
        result = cur.fetchone()
        if result:
            return jsonify({'success': True, 'name': result[1], 'email': result[2]})
        return jsonify({'success': False, 'message': 'Invalid email or password. Please try again.'}), 401
    finally:
        cur.close(); db.close()

# ── ENCRYPT ───────────────────────────────────────────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data      = request.json
    file_path = data.get('file_path', '').strip()

    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File not found. Check the path and try again.'}), 404

    file_name = os.path.basename(file_path).replace('.', '_').replace(' ', '_')
    db, cur = get_db()
    try:
        cur.execute("SHOW TABLES")
        tables = [t[0] for t in cur.fetchall()]
        if file_name in tables:
            return jsonify({'success': False, 'message': f"'{file_name}' is already encrypted in the database."}), 409

        cur.execute(f"""CREATE TABLE IF NOT EXISTS `{file_name}` (
            letter VARCHAR(10) PRIMARY KEY,
            Code VARCHAR(100) UNIQUE,
            updated_code VARCHAR(100) UNIQUE)""")
        db.commit()

        with open(file_path, 'r') as f:
            lines = f.readlines()

        seen = []
        cur.execute(f"SELECT updated_code FROM `{file_name}`")
        existing_codes = {r[0] for r in cur.fetchall()}

        for line in lines:
            for ch in line:
                if ch in CHAR and ch not in seen:
                    seen.append(ch)
                    while True:
                        new_code = ''.join(random.choices(CHAR, k=3))
                        if new_code not in existing_codes:
                            existing_codes.add(new_code)
                            break
                    cur.execute(
                        f"INSERT IGNORE INTO `{file_name}` (letter, Code, updated_code) VALUES (%s, %s, %s)",
                        (ch, new_code, new_code)
                    )
                    db.commit()

        cur.execute(f"SELECT letter, Code FROM `{file_name}`")
        mapping = {letter: code for letter, code in cur.fetchall()}

        enc_file = f"{file_name}_1.txt"
        with open(enc_file, 'w') as f:
            for line in lines:
                for ch in line:
                    if ch == '\n':
                        f.write('\n')
                    elif ch == ' ':
                        f.write('\n')
                    elif ch in mapping:
                        f.write(mapping[ch])

        os.makedirs(DESTINATION_FOLDER, exist_ok=True)
        dest = os.path.join(DESTINATION_FOLDER, os.path.basename(file_path))
        shutil.move(file_path.strip(), dest)

        sample = [{'char': ch if ch != ' ' else '(space)', 'code': cd} for ch, cd in list(mapping.items())[:12]]
        return jsonify({'success': True, 'file_name': file_name, 'encrypted_file': enc_file,
                        'total_chars': len(seen), 'moved_to': dest, 'sample_mapping': sample})
    finally:
        cur.close(); db.close()

# ── DECRYPT ───────────────────────────────────────────────────────────────────
@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data      = request.json
    file_name = data.get('file_name', '').strip()

    db, cur = get_db()
    try:
        cur.execute("SHOW TABLES")
        tables = [t[0] for t in cur.fetchall()]
        if file_name not in tables:
            return jsonify({'success': False, 'message': 'File not found in database.'}), 404

        enc_file = f"{file_name}_1.txt"
        if not os.path.exists(enc_file):
            return jsonify({'success': False, 'message': f'Encrypted file "{enc_file}" not found on disk.'}), 404

        cur.execute(f"SELECT letter, updated_code FROM `{file_name}`")
        decrypt_dict = {code: letter for letter, code in cur.fetchall()}

        with open(enc_file, 'r') as f:
            raw = f.read()

        words = raw.split()
        decrypted = ''
        unknown = 0
        for word in words:
            if word in decrypt_dict:
                decrypted += decrypt_dict[word]
            else:
                decrypted += '?'
                unknown += 1

        output_file = f"{file_name}_decrypted.txt"
        with open(output_file, 'w') as f:
            f.write(decrypted)

        return jsonify({'success': True, 'file_name': file_name, 'output_file': output_file,
                        'preview': decrypted[:400], 'unknown_codes': unknown})
    finally:
        cur.close(); db.close()

# ── REGENERATE KEYS ───────────────────────────────────────────────────────────
@app.route('/api/regenerate', methods=['POST'])
def regenerate():
    data      = request.json
    file_name = data.get('file_name', '').strip()

    db, cur = get_db()
    try:
        cur.execute("SHOW TABLES")
        tables = [t[0] for t in cur.fetchall()]
        if file_name not in tables:
            return jsonify({'success': False, 'message': 'Table not found in database.'}), 404

        cur.execute(f"SELECT letter FROM `{file_name}`")
        letters = [r[0] for r in cur.fetchall()]

        used_codes = set()
        new_mapping = {}
        for letter in letters:
            while True:
                code = ''.join(random.choices(CHAR, k=3))
                if code not in used_codes:
                    used_codes.add(code)
                    new_mapping[letter] = code
                    break

        for letter, code in new_mapping.items():
            cur.execute(f"UPDATE `{file_name}` SET updated_code = %s WHERE letter = %s", (code, letter))
        db.commit()

        sample = [{'char': ch if ch != ' ' else '(space)', 'code': cd} for ch, cd in list(new_mapping.items())[:12]]
        return jsonify({'success': True, 'file_name': file_name,
                        'keys_updated': len(letters), 'sample_mapping': sample})
    finally:
        cur.close(); db.close()

if __name__ == '__main__':
    import webbrowser, threading
    threading.Timer(1.2, lambda: webbrowser.open('http://127.0.0.1:5000')).start()
    app.run(host='127.0.0.1', debug=False, port=5000)

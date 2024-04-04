import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from jwt import encode, decode, algorithms
from jwcrypto import jwk

app = Flask(__name__)
app.config['DATABASE'] = 'totally_not_my_privateKeys.db'


def get_db_connection():
    if 'DATABASE' in app.config:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn
    else:
        raise Exception("Database not configured.")


def create_table():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        conn.commit()


def insert_key(private_key, expiration):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (private_key, expiration))
        conn.commit()


def get_valid_key(expired=False):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute('SELECT key FROM keys WHERE exp < ?', (datetime.utcnow().timestamp(),))
        else:
            cursor.execute('SELECT key FROM keys WHERE exp >= ?', (datetime.utcnow().timestamp(),))
        row = cursor.fetchone()
        if row:
            return row['key']
        return None


@app.route('/auth')
def authenticate():
    expired = request.args.get('expired', False)
    private_key = get_valid_key(expired=bool(expired))
    if private_key:
        token = encode({'some': 'payload'}, private_key, algorithm='RS256')
        return jsonify({'token': token.decode('utf-8')})
    else:
        return jsonify({'error': 'No valid key found'}), 404


@app.route('/.well-known/jwks.json')
def jwks():
    keys = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT key FROM keys WHERE exp >= ?', (datetime.utcnow().timestamp(),))
        rows = cursor.fetchall()
        for row in rows:
            private_key = jwk.JWK.from_pem(row['key'])
            keys.append(private_key.export(as_dict=True))
    return jsonify({'keys': keys})


def generate_key():
    # Generate private key (just for demonstration, you should generate your own)
    key = jwk.JWK.generate(kty='RSA', size=2048)
    return key.export()


if __name__ == '__main__':
    create_table()
    # Insert a key that expires now or less
    insert_key(generate_key(), (datetime.utcnow() - timedelta(minutes=1)).timestamp())
    # Insert a key that expires in 1 hour or more
    insert_key(generate_key(), (datetime.utcnow() + timedelta(hours=1)).timestamp())
    app.run(debug=True)

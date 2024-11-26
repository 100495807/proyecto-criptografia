from security import create_connection, sign_comment, verify_comment_signature

def add_comment(user_id, song_id, comment, private_key_pem):
    signature = sign_comment(private_key_pem, comment)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO comments (user_id, song_id, comment, signature) VALUES (?, ?, ?, ?)',
                   (user_id, song_id, comment, signature))
    conn.commit()
    conn.close()
    return True

def get_comments(song_id=None):
    conn = create_connection()
    cursor = conn.cursor()
    if song_id:
        cursor.execute('SELECT user_id, comment, signature FROM comments WHERE song_id = ?', (song_id,))
    else:
        cursor.execute('SELECT user_id, comment, signature FROM comments')
    comments = cursor.fetchall()
    conn.close()
    return comments

def verify_comment(user_id, comment, signature):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE id = ?', (user_id,))
    public_key_pem = cursor.fetchone()[0]
    conn.close()
    return verify_comment_signature(public_key_pem, comment, signature)
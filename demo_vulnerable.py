import sqlite3

def get_user_balance(user_id):
    db = sqlite3.connect('wallet.db')
    query = f"SELECT balance FROM users WHERE id='{user_id}'"
    result = db.execute(query)
    return result.fetchone()
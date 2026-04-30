import sqlite3
import os

def get_user_data(username):
    # 真实的 SQL 注入：直接拼接字符串
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)
    return cursor.fetchone()

def download_file(user_input_path):
    # 真实的路径穿越：直接读取路径
    with open(os.path.join("downloads", user_input_path), "r") as f:
        return f.read()
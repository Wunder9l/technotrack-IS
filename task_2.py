# -*- coding: utf-8 -*-
import MySQLdb


def get_connection():
    username = 'testuser'
    password = '1234'
    db = 'testdb'
    return MySQLdb.connect('localhost', username, password, db)


def user_add(username, password):
    conn = get_connection()
    conn.query("INSERT INTO users (username, password) VALUES ('{}', '{}')".format(username, password))
    conn.commit()
    conn.close()


def exploitable_user_find_by_name(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users where username like '%{}%'".format(username))

    # Получаем данные.
    rows = cursor.fetchall()
    for row in rows:
        print(row)

    # Разрываем подключение.
    conn.close()


def safe_user_find_by_name(username):
    conn = get_connection()
    cursor = conn.cursor()

    # prepared statement
    cursor.execute("SELECT * FROM users where username like %s", [username])
    # def is_symbol_allowed(s):
    #     allowed_symbols = ['@', '_', '-']
    #     o = ord(s)
    #     return (ord('a') <= o <= ord('z')) or (ord('0') <= o <= ord('9')) or s in allowed_symbols
    #
    # if all(map(is_symbol_allowed, username)):
    #     return exploitable_user_find_by_name(username)
    # else:
    #     print "Not valid username"


print 'dangerous:', exploitable_user_find_by_name("iki")
print 'dangerous:', exploitable_user_find_by_name("iki' or  user_id='1' or username='%123")
print "safe:", safe_user_find_by_name("iki' or  user_id='1' or username='%123")

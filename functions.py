import requests, urllib.parse, sqlite3

from flask import *
from functools import wraps

conn = sqlite3.connect('prefects.db', check_same_thread=False)
db = conn.cursor()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated_function


def apology(message, code=400):
    '''Send apology message to user for something that goes wrong'''

    def escape(s):
        '''
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        '''
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"), ("%", "~p"), ("#", "~h"), ("/", "~s"),
                         ("\"", "''")]:
            s = s.replace(old, new)
        return s

    return render_template('apology.html', top=code, bottom=escape(message)), code


def lookup(code, shift):
    '''Look up event info for event code.'''
    db.execute('SELECT * FROM events WHERE eventCode = ? and shift = ?', (code, shift))
    eventInfo = db.fetchall()

    info = {
        'name': eventInfo[0][0],
        'code': eventInfo[0][1],
        'shift': eventInfo[0][2],
        'value': eventInfo[0][3],
        'visible': eventInfo[0][4],
        'done': eventInfo[0][5]
    }

    return info


def checkPositionPermission(validPermissionLevel, redirectTo):
    def real_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            db.execute("SELECT position FROM users WHERE id = ?", (session['user_id'],))
            row = db.fetchone()
            position = row[0]

            if position == "Admin":
                print('a')
                return f(*args, **kwargs)
            elif position != validPermissionLevel:
                print('b')

                return redirect(url_for(redirectTo))
            else:
                print('c')
                return f(*args, **kwargs)

        return wrapper

    return real_decorator

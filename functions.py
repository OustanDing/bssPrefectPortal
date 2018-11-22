import requests, urllib.parse, sqlite3

from flask import *
from functools import wraps

conn = sqlite3.connect('/home/bssprefectportal/app/prefects.db', check_same_thread=False)
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
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"), ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
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

    db.execute("SELECT position FROM users WHERE id = ?", (session['user_id'],))
    position = db.fetchall()
    if postion =="Admin":
        return
    elif position != permissionLevele:
        return redirect(url_for(redirectTo))

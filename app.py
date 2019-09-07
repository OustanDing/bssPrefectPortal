import os, sqlite3, re, datetime

from flask import Flask, flash, redirect, render_template, request, session, url_for, send_from_directory
from functions import *
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from tempfile import mkdtemp
from operator import itemgetter
from datetime import datetime

# Configure application
app = Flask(__name__)

app.secret_key = 'ilikedogs'

# Templates auto-reload
app.config['TEMPLATES_AUTO_RELOAD'] = True


# Clear cache after
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response


# Use filesystem instead of signed cookies
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'

# Connecting to prefects.db
conn = sqlite3.connect('/home/bssprefectportal/app/prefects.db', check_same_thread=False)
db = conn.cursor()

# -----------------------------------------------------------------------------------------------------------------------------------------------------
# ADMIN STUFF
# -----------------------------------------------------------------------------------------------------------------------------------------------------

# HOMEPAGE (ADMIN)
@app.route('/indexa')
@login_required
@checkPositionPermission("Admin", "login")
def indexa():
    registered = 0
    execs = 0
    prefects = 0
    cert = 0
    eliexec = 0
    upcoming = 0
    completed = 0

    db.execute('SELECT * FROM users')
    users = db.fetchall()

    for user in users:
        registered += 1
        if user[15] == 'Executive':
            execs += 1
        elif user[15] == 'Prefect':
            prefects += 1
        if user[4] >= 4:
            cert += 1
        if user[4] >= 5:
            eliexec += 1

    info = {
        'registered': registered,
        'execs': execs,
        'prefects': prefects,
        'cert': cert,
        'eliexec': eliexec
    }

    return render_template('indexa.html', info=info)

# ------------------------------------------------------------------------------------------------------

# MANAGE EXECS
@app.route('/execsa')
@login_required
@checkPositionPermission('Admin', 'login')
def execsa():
    execs = []

    db.execute('SELECT * FROM users WHERE position == "Executive"')
    info = db.fetchall()

    for exec in info:
        execs.append({
            'id': exec[0],
            'username': exec[1],
            'name': exec[2],
            'credits': exec[4],
            'gender': exec[7],
            'grade': exec[5],
            'size': exec[10],
            'stuNum' : exec[6],
            'email': exec[14],
            'home': exec[12],
            'cell': exec[13],
            'dietary': exec[8],
            'status': exec[11]
            })

    execs.sort(key=itemgetter('name'))

    return render_template('execsa.html', execs=execs)

# EDIT EXECS
@app.route('/editexeca/<execId>', methods = ['GET', 'POST'])
@login_required
@checkPositionPermission('Admin', 'login')
def editexeca(execId):
    if request.method == 'GET':
        db.execute('SELECT * FROM users WHERE position = "Executive"')
        execlist = db.fetchall()

        execs = [{
            'name': exec[2],
            'id': exec[0]
        } for exec in execlist]

        db.execute('SELECT * FROM users WHERE id = ?', (execId ,))
        execInfo = db.fetchall()

        thisexec = {
            'id': execInfo[0][0],
            'name': execInfo[0][2],
            'username': execInfo[0][1],
            'grade': execInfo[0][5],
            'stuNum' : execInfo[0][6],
            'gender': execInfo[0][7],
            'dietary': execInfo[0][8],
            'size': execInfo[0][9],
            'status': execInfo[0][11],
            'home': execInfo[0][12],
            'cell': execInfo[0][13],
            'email': execInfo[0][14]
        }

        return render_template('editexeca.html', execs=execs, thisexec=thisexec,
                               visibility='visible')
    else:
        db.execute(
            'UPDATE users SET name = ?, username = ?, grade = ?, stuNum = ?, gender = ?, dietary = ?, size = ?, status = ?, home = ?, cell = ?, email = ? WHERE id = ?',
            (request.form.get('name'), request.form.get('username'), request.form.get('grade'),
             request.form.get('stuNum'), request.form.get('gender'), request.form.get('dietary'),
             request.form.get('size'), request.form.get('status'), request.form.get('home'), request.form.get('cell'),
             request.form.get('email'), execId))
        conn.commit()

        flash('Updated!')
        return redirect('/editexeca/' + execId)

# DELETE AN EXEC
@app.route('/deleteexeca/<prefectId>')
@login_required
@checkPositionPermission("Admin", "login")
def deleteExec(prefectId):
    db.execute('DELETE FROM users WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM signup WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM completed WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM requested WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM declined WHERE id = ?', (prefectId,))
    conn.commit()

    return redirect(url_for('execsa'))

# RESET EXEC/PREFECT PASSWORD
@app.route('/resetPassa/<Id>/<redirectaddress>')
@login_required
@checkPositionPermission("Admin", "login")
def resetPassa(Id, redirectaddress):
    db.execute('UPDATE users SET hash = ? WHERE id = ?', (
        generate_password_hash('1234'),
        Id
    ))
    conn.commit()

    flash('Password reset!')
    return redirect('/' + redirectaddress)

    '''
    if redirect == 'prefectsa':
        flash('Password reset!')
        return redirect(url_for('prefectsa'))
    else:
        flash('Password reset!')
        return redirect(url_for('execsa'))
    '''

# ADD EXEC
@app.route('/addexeca', methods=['GET', 'POST'])
@login_required
@checkPositionPermission('Admin', 'login')
def addexeca():
    if request.method == 'GET':
        return render_template('addexeca.html')

    else:
        db.execute('SELECT username FROM users')
        registered = db.fetchall()
        registeredUsers = []

        for username in registered:
            registeredUsers.append(username[0])

        # Check that name is not blank
        if not request.form.get('name'):
            flash('Name cannot be blank')
            return redirect(url_for('addexeca'))

        # Check that username is not blank
        elif not request.form.get('username'):
            flash('Username cannot be blank')
            return redirect(url_for('addexeca'))

        # Check that password is not blank
        elif not request.form.get('password'):
            flash('Password cannot be blank')
            return redirect(url_for('addexeca'))

        # Check that username is not already in system
        elif request.form.get('username') in registeredUsers:
            flash('Username already exists! Try a different username.')
            return redirect(url_for('addexeca'))

        # Check that password and confirmation match
        elif request.form.get('password') != request.form.get('confirm'):
            flash('Password and confirmation do not match')
            return redirect(url_for('addexeca'))

        db.execute('INSERT INTO users (username, name, hash, grade, leader, position) VALUES (?, ?, ?, ?, ?, ?)', (
            request.form.get('username'),
            request.form.get('name'),
            generate_password_hash(request.form.get('password')),
            request.form.get('grade'),
            request.form.get('name').split(' ')[0],
            'Executive'))
        conn.commit()

        flash('Registered!')
        return redirect(url_for('addexeca'))

# ------------------------------------------------------------------------------------------------------

# MANAGE PREFECTS (ALL)
@app.route('/prefectsa')
@login_required
@checkPositionPermission('Admin', 'login')
def prefectsa():
    # Get leaders
    db.execute('SELECT leader FROM users WHERE position = "Executive" AND id != ?', (session['user_id'],))
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    # Get data for all prefects
    db.execute('SELECT * FROM users WHERE id != ? AND position = "Prefect"', (session['user_id'],))
    members = db.fetchall()

    prefects = []

    for member in members:
        info = dict([
            ('id', member[0]),
            ('username', member[1]),
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum', member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    return render_template('prefectsa.html', prefects=prefects, currentGroup='all', leaders=leaders)

# MANAGE PREFECTS (SELECTED LEADER)
@app.route('/prefectsa/<leader>')
@login_required
@checkPositionPermission('Admin', 'login')
def prefectsa2(leader):
    # Get leaders
    db.execute('SELECT leader FROM users WHERE position = "Executive" AND id != ?', (session['user_id'],))
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    # Get data for all prefects
    db.execute('SELECT * FROM users WHERE id != ? AND position = "Prefect" AND leader = ?', (session['user_id'], leader))
    members = db.fetchall()

    prefects = []

    for member in members:
        info = dict([
            ('id', member[0]),
            ('username', member[1]),
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum', member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    return render_template('prefectsa.html', prefects=prefects, currentGroup=leader, leaders=leaders)

# EDIT PREFECT
# NAVIGATE TO CERTAIN PREFECT TO EDIT INFO (EXEC)
@app.route('/editprefecta/<prefectId>', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Admin", "login")
def editprefecta(prefectId):
    if request.method == 'GET':
        db.execute('SELECT * FROM users WHERE id = ?', (prefectId,))
        prefectInfo = db.fetchall()

        prefect = {
            'id': prefectInfo[0][0],
            'name': prefectInfo[0][2],
            'username': prefectInfo[0][1],
            'grade': prefectInfo[0][5],
            'stuNum': prefectInfo[0][6],
            'gender': prefectInfo[0][7],
            'dietary': prefectInfo[0][8],
            'leader': prefectInfo[0][9],
            'size': prefectInfo[0][10],
            'status': prefectInfo[0][11],
            'home': prefectInfo[0][12],
            'cell': prefectInfo[0][13],
            'email': prefectInfo[0][14]
        }

        db.execute('SELECT leader FROM users WHERE position = "Executive"')
        leaderData = db.fetchall()

        leaders = [leader[0] for leader in leaderData]

        return render_template('editprefecta.html', leaders=leaders, prefect=prefect)
    else:
        db.execute(
            'UPDATE users SET name = ?, username = ?, grade = ?, stuNum = ?, gender = ?, dietary = ?, leader = ?, size = ?, status = ?, home = ?, cell = ?, email = ? WHERE id = ?',
            (request.form.get('name'), request.form.get('username'), request.form.get('grade'),
             request.form.get('stuNum'), request.form.get('gender'), request.form.get('dietary'), request.form.get('leader'),
             request.form.get('size'), request.form.get('status'), request.form.get('home'), request.form.get('cell'),
             request.form.get('email'), prefectId))
        conn.commit()

        flash('Updated!')
        return redirect('/editprefecta/' + prefectId)

# DELETE A PREFECT
@app.route('/deleteprefecta/<prefectId>')
@login_required
@checkPositionPermission("Admin", "login")
def deletePrefecta(prefectId):
    db.execute('DELETE FROM users WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM signup WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM completed WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM requested WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM declined WHERE id = ?', (prefectId,))
    conn.commit()

    return redirect(url_for('prefectsa'))

# ADD PREFECT
@app.route('/addprefecta', methods=['GET', 'POST'])
@login_required
@checkPositionPermission('Admin', 'login')
def addprefecta():
    if request.method == 'GET':
        db.execute('SELECT leader FROM users WHERE position = "Executive"')
        leaderData = db.fetchall()

        leaders = [leader[0] for leader in leaderData]

        return render_template('addprefecta.html', leaders=leaders)

    else:
        db.execute('SELECT username FROM users')
        registered = db.fetchall()
        registeredUsers = []

        for username in registered:
            registeredUsers.append(username[0])

        # Check that name is not blank
        if not request.form.get('name'):
            flash('Name cannot be blank')
            return redirect(url_for('addprefecta'))

        # Check that username is not blank
        elif not request.form.get('username'):
            flash('Username cannot be blank')
            return redirect(url_for('addprefecta'))

        # Check that password is not blank
        elif not request.form.get('password'):
            flash('Password cannot be blank')
            return redirect(url_for('addprefecta'))

        # Check that username is not already in system
        elif request.form.get('username') in registeredUsers:
            flash('Username already exists! Try a different username.')
            return redirect(url_for('addprefecta'))

        # Check that password and confirmation match
        elif request.form.get('password') != request.form.get('confirm'):
            flash('Password and confirmation do not match')
            return redirect(url_for('addprefecta'))

        db.execute('INSERT INTO users (username, name, hash, grade, leader) VALUES (?, ?, ?, ?, ?)', (
            request.form.get('username'),
            request.form.get('name'),
            generate_password_hash(request.form.get('password')),
            request.form.get('grade'),
            request.form.get('leader')))
        conn.commit()

        flash('Registered!')
        return redirect(url_for('addprefecta'))

# EDIT EVENT COUNT (MAIN PAGE)
@app.route('/editCount/<prefectId>')
@login_required
@checkPositionPermission('Admin', 'login')
def editCount(prefectId):
    db.execute('SELECT * FROM users WHERE id = ?', (prefectId,))
    info = db.fetchone()

    db.execute('SELECT * FROM completed WHERE id = ?', (prefectId,))
    completedEvents = db.fetchall()

    db.execute('SELECT * FROM events WHERE done = "yes"')
    allEvents = db.fetchall()

    completed = []
    completedIds = []
    incomplete = []

    for event in completedEvents:
        if lookup(event[1], event[2])['done'] == 'yes':
            completed.append({
                'eventName': event[0],
                'eventCode': event[1],
                'shift': event[2],
                'value': event[3],
                'date': lookup(event[1], event[2])['date']
                })

        completedIds.append(event[1])

    completed = sorted(completed, key=itemgetter('date'), reverse=True)

    for event in allEvents:
        if event[1] not in completedIds:
            incomplete.append({
                'eventName': event[0],
                'eventCode': event[1],
                'shift': event[2],
                'value': event[3],
                'date': event[6]
                })
    incomplete = sorted(incomplete, key=itemgetter('date'), reverse=True)

    prefect = {
        'id': prefectId,
        'name': info[2],
        'credits': info[4],
        'leader': info[9]
    }

    return render_template('editcounta.html', prefect=prefect, incomplete=incomplete, completed=completed)

# ADD EVENT TO COMPLETED
@app.route('/addEvent/<prefectId>/<eventCode>/<shift>')
@login_required
@checkPositionPermission('Admin', 'login')
def addEvent(prefectId, eventCode, shift):
    db.execute('INSERT INTO completed (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)', (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], prefectId, None))
    db.execute('SELECT credits FROM users WHERE id = ?', (prefectId,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (currentCredits + lookup(eventCode, shift)['value'], prefectId))

    return redirect(url_for('editCount', prefectId=prefectId))

# REMOVE EVENT FROM COMPLETED
@app.route('/remEvent/<prefectId>/<eventCode>/<shift>')
@login_required
@checkPositionPermission('Admin', 'login')
def remEvent(prefectId, eventCode, shift):
    db.execute('DELETE FROM completed WHERE id = ? AND eventCode = ? AND shift = ?', (prefectId, eventCode, shift))
    db.execute('SELECT credits FROM users WHERE id = ?', (prefectId,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (currentCredits - lookup(eventCode, shift)['value'], prefectId))

    return redirect(url_for('editCount', prefectId=prefectId))

# ------------------------------------------------------------------------------------------------------

# EVENTS MAIN PAGE (EXEC)
@app.route('/eventsa', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Admin", "events")
def eventsa():
    if request.method == 'GET':
        db.execute('SELECT * FROM events')
        eventData = db.fetchall()

        visible = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'yes' and event[5] != 'yes'], key=itemgetter('date'), reverse=True)

        invisible = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] != 'yes'], key=itemgetter('date'), reverse=True)

        finished = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] == 'yes'], key=itemgetter('date'), reverse=True)

        totalVisible = len(visible)
        totalInvisible = len(invisible)
        totalFinished = len(finished)

        return render_template('eventsa.html', visibleEvents=visible, invisibleEvents=invisible,
                               finishedEvents=finished, totalvis=totalVisible, totalinvis=totalInvisible,
                               totalfinished=totalFinished)

    else:
        if not request.form.get('name'):
            flash('Event name cannot be blank')
            return redirect(url_for('eventsa'))

        elif not request.form.get('date'):
            flash('Date cannot be blank')
            return redirect(url_for('eventsa'))

        elif not request.form.get('shift1'):
            flash('Shift 1 value cannot be blank')
            return redirect(url_for('eventsa'))

        # Get new eventCode
        db.execute('SELECT eventCode FROM events')
        eventCodes = db.fetchall()
        codeData = [int(event[0]) for event in eventCodes]
        newCode = max(codeData) + 1

        if request.form.get('shift1') and request.form.get('shift2') and request.form.get('shift3'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'no', request.form.get('date'))
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift2'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no', request.form.get('date'))
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift3'):
            flash('Cannot input value for Both Shifts without value for Shift 2')
            return redirect(url_for('eventsa'))
        elif request.form.get('shift1'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                conn.commit()

        flash('Event added!')
        return redirect(url_for('eventsa'))

# HIDE AN EVENT
@app.route('/eventhidea/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Admin", "login")
def eventhidea(eventCode, shift):
    db.execute('UPDATE events SET visible = "no" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    return redirect(url_for('eventsa'))

# SHOW AN EVENT
@app.route('/eventshowa/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Admin", "login")
def eventshowa(eventCode, shift):
    db.execute('UPDATE events SET visible = "yes" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    return redirect(url_for('eventsa'))

# DELETE/REMOVE AN EVENT
@app.route('/eventremovea/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Admin", "login")
def eventremovea(eventCode, shift):
    db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    if shift == '1':
        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 2))
        eventShift2 = db.fetchall()

        if len(eventShift2) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            conn.commit()

        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
        eventShift3 = db.fetchall()

        if len(eventShift3) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            conn.commit()

    elif shift == '2':
        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
        eventShift3 = db.fetchall()

        if len(eventShift3) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            conn.commit()

    return redirect(url_for('eventsa'))

# MARK EVENT AS DONE
@app.route('/eventdonea/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Admin", "login")
def eventdonea(eventCode, shift):
    db.execute('UPDATE events SET visible = "no", done = "yes" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    '''
    db.execute('SELECT value FROM events WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    eventValue = db.fetchall()[0][0]

    db.execute('SELECT id FROM signup WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    granted = db.fetchall()
    grantedPrefects = [personId[0] for personId in granted]

    for prefectId in grantedPrefects:
        db.execute('SELECT credits FROM users WHERE id = ?', (prefectId,))
        currentCredits = db.fetchall()[0][0]
        db.execute('UPDATE users SET credits = ? WHERE id = ?', (currentCredits + eventValue, prefectId))
        db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, prefectId))
        db.execute('INSERT INTO completed (eventName, eventCode, shift, value, id) VALUES (?, ?, ?, ?, ?)', (lookup(eventCode, shift)['name'], eventCode, shift, eventValue, prefectId))
    conn.commit()
    '''

    return redirect(url_for('eventsa'))

# UNDO MARKING AN EVENT AS DONE
@app.route('/eventundonea/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Admin", "login")
def eventundonea(eventCode, shift):
    db.execute('UPDATE events SET done = "no" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    '''
    db.execute('SELECT value FROM events WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    eventValue = db.fetchall()[0][0]

    db.execute('SELECT id FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    granted = db.fetchall()
    grantedPrefects = [personId[0] for personId in granted]

    for prefectId in grantedPrefects:
        db.execute('SELECT credits FROM users WHERE id = ?', (prefectId,))
        currentCredits = db.fetchall()[0][0]
        db.execute('UPDATE users SET credits = ? WHERE id = ?', (currentCredits - eventValue, prefectId))
        db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, prefectId))
        db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id) VALUES (?, ?, ?, ?, ?)', (lookup(eventCode, shift)['name'], eventCode, shift, eventValue, prefectId))
    conn.commit()
    '''

    return redirect(url_for('eventsa'))

# ------------------------------------------------------------------------------------------------------

# VIEW/CHANGE FILES (EXEC)
@app.route('/filesa', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Admin", "files")
def filesa():
    if request.method == 'GET':
        db.execute('SELECT * FROM files')
        fileData = db.fetchall()

        visible = [{
            'name': file[0],
            'link': file[1],
            'id': file[2]
        } for file in fileData if file[3] == 'yes']

        invisible = [{
            'name': file[0],
            'link': file[1],
            'id': file[2]
        } for file in fileData if file[3] == 'no']

        totalVisible = len(visible)
        totalInvisible = len(invisible)

        return render_template('filesa.html', visibleFiles=visible, invisibleFiles=invisible, totalvis=totalVisible,
                               totalinvis=totalInvisible)

    else:
        if re.search(r'(?:.+\.)+.+', request.form.get('link')) == None:
            flash('Link is invalid. Please try again.')
            return redirect(url_for('filese'))

        elif not request.form.get('name'):
            flash('File name cannot be blank')
            return redirect(url_for('filese'))

        elif not request.form.get('link'):
            flash('File link cannot be blank')
            return redirect(url_for('filese'))

        if request.form.get('visible'):
            db.execute('INSERT INTO files (name, link, visible) VALUES (?, ?, ?)',
                       (request.form.get('name'), request.form.get('link'), 'yes'))
            conn.commit()

        else:
            db.execute('INSERT INTO files (name, link, visible) VALUES (?, ?, ?)',
                       (request.form.get('name'), request.form.get('link'), 'no'))
            conn.commit()

        return redirect(url_for('filesa'))

# HIDE A FILE
@app.route('/hidea/<fileId>')
@login_required
@checkPositionPermission("Admin", "login")
def hidea(fileId):
    db.execute('UPDATE files SET visible = "no" WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filesa'))

# SHOW A FILE
@app.route('/showa/<fileId>')
@login_required
@checkPositionPermission("Admin", "login")
def showa(fileId):
    db.execute('UPDATE files SET visible = "yes" WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filesa'))

# REMOVE A FILE
@app.route('/removea/<fileId>')
@login_required
@checkPositionPermission("Admin", "login")
def removea(fileId):
    db.execute('DELETE FROM files WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filesa'))

# ------------------------------------------------------------------------------------------------------

# CHANGE PASSWORD
@app.route('/changea', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Admin", "login")
def changea():
    '''Change password'''

    # check if information is sent
    if request.method == 'POST':
        if len(request.form.get('new')) < 8:
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('changee.html')
        if not re.search(r'\d', request.form.get('new')) and not re.search(r'\W', request.form.get('new')):
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('changee.html')

        db.execute("SELECT hash FROM users WHERE id = ?",
                   (session['user_id'],))
        password = db.fetchall()

        # check if password is not empty and matches current password
        if not request.form.get('current') or not check_password_hash(password[0][0], request.form.get("current")):
            flash('Current password is incorrect')
            return render_template('changee.html')
            # return apology('Current password is incorrect')

        # check if new password is not empty
        elif not request.form.get('new'):
            flash('Please enter a new password')
            return render_template('changee.html')
            # return apology('Please enter a new password')

        # check that new password and confirmation match
        elif request.form.get('new') != request.form.get('confirmation'):
            flash('Password and confirmation do not match')
            return render_template('changee.html')
            # return apology('Password and confirmation do not match')

        # update user's password in users database
        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   (generate_password_hash(request.form.get("new")),
                    session['user_id']))
        conn.commit()

        flash('Password changed!')  # notify of successful registration
        return redirect(url_for("indexa"))

    # if no information sent return change password page
    else:
        return render_template("changea.html")


# -----------------------------------------------------------------------------------------------------------------------------------------------------
# EXEC STUFF
# -----------------------------------------------------------------------------------------------------------------------------------------------------

# HOMEPAGE (EXEC)
@app.route('/indexe')
@login_required
@checkPositionPermission("Executive", "index")
def indexe():
    # Display user's dashboard
    # Get leaders
    db.execute('SELECT leader FROM users WHERE position = "Executive" AND id != ?', (session['user_id'],))
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    # Get current executive's data
    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    userGroup = creds[0][9]

    db.execute('SELECT * FROM users WHERE leader = ? AND id != ?', (userGroup, session['user_id']))
    members = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('position', creds[0][15]),
        ('firstname', creds[0][9])
    ])

    # Get current group
    db.execute('SELECT leader FROM users WHERE id = ?', (session['user_id'],))
    currentGroup = db.fetchall()[0][0]

    # Get data for current executive's prefect group
    prefects = []

    for member in members:
        info = dict([
            ('id', member[0]),
            ('username', member[1]),
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum', member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    total = {
        'male': 0,
        'female': 0,
        'eleven': 0,
        'twelve': 0,
        'malexs': 0,
        'males': 0,
        'malem': 0,
        'malel': 0,
        'malexl': 0,
        'femalexs': 0,
        'females': 0,
        'femalem': 0,
        'femalel': 0,
        'femalexl': 0,
        'new': 0,
        'returning': 0
    }

    for member in members:
        if member[6] == 'Male':
            total['male'] += 1
        elif member[6] == 'Female':
            total['female'] += 1

        if member[9] == 'XS' and member[6] == 'Male':
            total['malexs'] += 1
        elif member[9] == 'S' and member[6] == 'Male':
            total['males'] += 1
        elif member[9] == 'M' and member[6] == 'Male':
            total['malem'] += 1
        elif member[9] == 'L' and member[6] == 'Male':
            total['malel'] += 1
        elif member[9] == 'XL' and member[6] == 'Male':
            total['malexl'] += 1
        elif member[9] == 'XS' and member[6] == 'Female':
            total['femalexs'] += 1
        elif member[9] == 'S' and member[6] == 'Female':
            total['females'] += 1
        elif member[9] == 'M' and member[6] == 'Female':
            total['femalem'] += 1
        elif member[9] == 'L' and member[6] == 'Female':
            total['femalel'] += 1
        elif member[9] == 'XL' and member[6] == 'Female':
            total['femalexl'] += 1

        if member[5] == '11':
            total['eleven'] += 1
        elif member[5] == '12':
            total['twelve'] += 1

        if member[10] == 'New':
            total['new'] += 1
        elif member[10] == 'Returning':
            total['returning'] += 1

    return render_template('indexe.html', prefect=prefect, prefects=prefects, total=total, leaders=leaders, currentGroup=currentGroup)

# HOMEPAGE FOR ALL PREFECTS (EXEC)
@app.route('/indexe/all')
@login_required
@checkPositionPermission("Executive", "index")
def indexe2():
    # Display user's dashboard
    # Get leaders
    db.execute('SELECT leader FROM users WHERE position = "Executive" AND id != ?', (session['user_id'],))
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    # Get current executive's data
    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('position', creds[0][15]),
        ('firstname', creds[0][9])
    ])

    # Get current group ('all')
    currentGroup = 'all'

    # Get data for all prefects
    db.execute('SELECT * FROM users WHERE id != ? AND position = "Prefect"', (session['user_id'],))
    members = db.fetchall()

    prefects = []

    for member in members:
        info = dict([
            ('id', member[0]),
            ('username', member[1]),
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum' , member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    total = {
        'male': 0,
        'female': 0,
        'eleven': 0,
        'twelve': 0,
        'malexs': 0,
        'males': 0,
        'malem': 0,
        'malel': 0,
        'malexl': 0,
        'femalexs': 0,
        'females': 0,
        'femalem': 0,
        'femalel': 0,
        'femalexl': 0,
        'new': 0,
        'returning': 0
    }

    for member in members:
        if member[6] == 'Male':
            total['male'] += 1
        elif member[6] == 'Female':
            total['female'] += 1

        if member[9] == 'XS' and member[6] == 'Male':
            total['malexs'] += 1
        elif member[9] == 'S' and member[6] == 'Male':
            total['males'] += 1
        elif member[9] == 'M' and member[6] == 'Male':
            total['malem'] += 1
        elif member[9] == 'L' and member[6] == 'Male':
            total['malel'] += 1
        elif member[9] == 'XL' and member[6] == 'Male':
            total['malexl'] += 1
        elif member[9] == 'XS' and member[6] == 'Female':
            total['femalexs'] += 1
        elif member[9] == 'S' and member[6] == 'Female':
            total['females'] += 1
        elif member[9] == 'M' and member[6] == 'Female':
            total['femalem'] += 1
        elif member[9] == 'L' and member[6] == 'Female':
            total['femalel'] += 1
        elif member[9] == 'XL' and member[6] == 'Female':
            total['femalexl'] += 1

        if member[5] == '11':
            total['eleven'] += 1
        elif member[5] == '12':
            total['twelve'] += 1

        if member[10] == 'New':
            total['new'] += 1
        elif member[10] == 'Returning':
            total['returning'] += 1

    return render_template('indexe.html', prefect=prefect, prefects=prefects, total=total, leaders=leaders, currentGroup=currentGroup)

# HOMEPAGE FOR DIFFERENT GROUP (EXEC)
@app.route('/indexe/<leader>')
@login_required
@checkPositionPermission("Executive", "index")
def indexe3(leader):
    # Display user's dashboard
    # Get leaders
    db.execute('SELECT leader FROM users WHERE position = "Executive" AND id != ?', (session['user_id'],))
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    # Get current executive's data
    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('position', creds[0][15]),
        ('firstname', creds[0][9])
    ])

    # Get current group
    currentGroup = leader

    # Get data for current executive's prefect group
    db.execute('SELECT * FROM users WHERE leader = ? AND id != ? AND position = "Prefect"', (currentGroup, session['user_id']))
    members = db.fetchall()

    prefects = []

    for member in members:
        info = dict([
            ('id', member[0]),
            ('username', member[1]),
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum', member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    total = {
        'male': 0,
        'female': 0,
        'eleven': 0,
        'twelve': 0,
        'malexs': 0,
        'males': 0,
        'malem': 0,
        'malel': 0,
        'malexl': 0,
        'femalexs': 0,
        'females': 0,
        'femalem': 0,
        'femalel': 0,
        'femalexl': 0,
        'new': 0,
        'returning': 0
    }

    for member in members:
        if member[6] == 'Male':
            total['male'] += 1
        elif member[6] == 'Female':
            total['female'] += 1

        if member[9] == 'XS' and member[6] == 'Male':
            total['malexs'] += 1
        elif member[9] == 'S' and member[6] == 'Male':
            total['males'] += 1
        elif member[9] == 'M' and member[6] == 'Male':
            total['malem'] += 1
        elif member[9] == 'L' and member[6] == 'Male':
            total['malel'] += 1
        elif member[9] == 'XL' and member[6] == 'Male':
            total['malexl'] += 1
        elif member[9] == 'XS' and member[6] == 'Female':
            total['femalexs'] += 1
        elif member[9] == 'S' and member[6] == 'Female':
            total['females'] += 1
        elif member[9] == 'M' and member[6] == 'Female':
            total['femalem'] += 1
        elif member[9] == 'L' and member[6] == 'Female':
            total['femalel'] += 1
        elif member[9] == 'XL' and member[6] == 'Female':
            total['femalexl'] += 1

        if member[5] == '11':
            total['eleven'] += 1
        elif member[5] == '12':
            total['twelve'] += 1

        if member[10] == 'New':
            total['new'] += 1
        elif member[10] == 'Returning':
            total['returning'] += 1

    return render_template('indexe.html', prefect=prefect, prefects=prefects, total=total, leaders=leaders, currentGroup=currentGroup)

# EDIT PREFECT INFO MAIN PAGE (EXEC)
@app.route('/editprefecte')
@login_required
@checkPositionPermission("Executive", "index")
def editprefecte():
    db.execute('SELECT leader FROM users WHERE id = ?', (session['user_id'],))
    groupName = db.fetchall()[0][0]

    db.execute('SELECT * FROM users WHERE leader = ? AND position != "Executive"', (groupName,))
    groupPrefects = db.fetchall()

    prefects = [{
        'name': prefect[2],
        'id': prefect[0]
    } for prefect in groupPrefects]

    prefect = {
        'name': None,
        'grade': None,
        'stuNum': None,
        'gender': None,
        'dietary': None,
        'leader': None,
        'size': None,
        'status': None,
        'home': None,
        'cell': None,
        'email': None
    }

    db.execute('SELECT leader FROM users WHERE position = "Executive"')
    leaderData = db.fetchall()

    leaders = [leader[0] for leader in leaderData]

    return render_template('editprefecte.html', prefects=prefects, leaders=leaders, prefect=prefect,
                           visibility='hidden')

# NAVIGATE TO CERTAIN PREFECT TO EDIT INFO (EXEC)
@app.route('/editprefecte/<prefectId>', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "index")
def editPrefectInfo(prefectId):
    if request.method == 'GET':
        db.execute('SELECT leader FROM users WHERE id = ?', (session['user_id'],))
        groupName = db.fetchall()[0][0]

        db.execute('SELECT * FROM users WHERE leader = ? AND position != "Executive"', (groupName,))
        groupPrefects = db.fetchall()

        prefects = [{
            'name': prefect[2],
            'id': prefect[0]
        } for prefect in groupPrefects]

        db.execute('SELECT * FROM users WHERE id = ?', (prefectId,))
        prefectInfo = db.fetchall()

        prefect = {
            'id': prefectInfo[0][0],
            'name': prefectInfo[0][2],
            'username': prefectInfo[0][1],
            'grade': prefectInfo[0][5],
            'stuNum': prefectInfo[0][6],
            'gender': prefectInfo[0][7],
            'dietary': prefectInfo[0][8],
            'leader': prefectInfo[0][9],
            'size': prefectInfo[0][10],
            'status': prefectInfo[0][11],
            'home': prefectInfo[0][12],
            'cell': prefectInfo[0][13],
            'email': prefectInfo[0][14]
        }

        db.execute('SELECT leader FROM users WHERE position = "Executive"')
        leaderData = db.fetchall()

        leaders = [leader[0] for leader in leaderData]

        return render_template('editprefecte.html', prefects=prefects, leaders=leaders, prefect=prefect,
                               visibility='visible')
    else:
        db.execute(
            'UPDATE users SET name = ?, username = ?, grade = ?, stuNum = ?, gender = ?, dietary = ?, leader = ?, size = ?, status = ?, home = ?, cell = ?, email = ? WHERE id = ?',
            (request.form.get('name'), request.form.get('username'), request.form.get('grade'),
             request.form.get('stuNum'), request.form.get('gender'), request.form.get('dietary'), request.form.get('leader'),
             request.form.get('size'), request.form.get('status'), request.form.get('home'), request.form.get('cell'),
             request.form.get('email'), prefectId))
        conn.commit()

        flash('Updated!')
        return redirect('/editprefecte/' + prefectId)

# DELETE A PREFECT (EXEC)
@app.route('/deleteprefecte/<prefectId>')
@login_required
@checkPositionPermission("Executive", "index")
def deletePrefect(prefectId):
    db.execute('DELETE FROM users WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM signup WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM completed WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM requested WHERE id = ?', (prefectId,))
    db.execute('DELETE FROM declined WHERE id = ?', (prefectId,))
    conn.commit()

    return redirect(url_for('indexe'))

# RESET PREFECT PASSWORD (EXEC)
@app.route('/resetPass/<prefectId>')
@login_required
@checkPositionPermission("Executive", "index")
def resetPass(prefectId):
    db.execute('UPDATE users SET hash = ? WHERE id = ?', (
        generate_password_hash('1234'),
        prefectId
    ))
    conn.commit()

    flash('Password reset!')
    return redirect(url_for('indexe'))

# ------------------------------------------------------------------------------------------------------

# EVENTS MAIN PAGE (EXEC)
@app.route('/eventse', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "events")
def eventse():
    if request.method == 'GET':
        db.execute('SELECT * FROM events')
        eventData = db.fetchall()

        visible = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'yes' and event[5] != 'yes'], key=itemgetter('date'), reverse=True)

        invisible = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] != 'yes'], key=itemgetter('date'), reverse=True)

        finished = sorted([{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] == 'yes'], key=itemgetter('date'), reverse=True)

        totalVisible = len(visible)
        totalInvisible = len(invisible)
        totalFinished = len(finished)

        return render_template('eventse.html', visibleEvents=visible, invisibleEvents=invisible,
                               finishedEvents=finished, totalvis=totalVisible, totalinvis=totalInvisible,
                               totalfinished=totalFinished)

    else:
        if not request.form.get('name'):
            flash('Event name cannot be blank')
            return redirect(url_for('eventse'))

        elif not request.form.get('date'):
            flash('Date cannot be blank')
            return redirect(url_for('eventse'))

        elif not request.form.get('shift1'):
            flash('Shift 1 value cannot be blank')
            return redirect(url_for('eventse'))

        # Get new eventCode
        db.execute('SELECT eventCode FROM events')
        eventCodes = db.fetchall()
        codeData = [int(event[0]) for event in eventCodes]
        newCode = max(codeData) + 1

        if request.form.get('shift1') and request.form.get('shift2') and request.form.get('shift3'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'no', request.form.get('date'))
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift2'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no', request.form.get('date'))
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift3'):
            flash('Cannot input value for Both Shifts without value for Shift 2')
            return redirect(url_for('eventse'))
        elif request.form.get('shift1'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes', request.form.get('date'))
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible, eventDate) VALUES (?, ?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no', request.form.get('date'))
                           )
                conn.commit()

        flash('Event added!')
        return redirect(url_for('eventse'))

# HIDE AN EVENT
@app.route('/eventhide/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Executive", "index")
def eventhide(eventCode, shift):
    db.execute('UPDATE events SET visible = "no" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    return redirect(url_for('eventse'))

# SHOW AN EVENT
@app.route('/eventshow/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Executive", "index")
def eventshow(eventCode, shift):
    db.execute('UPDATE events SET visible = "yes" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    return redirect(url_for('eventse'))

# DELETE/REMOVE AN EVENT
@app.route('/eventremove/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Executive", "index")
def eventremove(eventCode, shift):
    db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    if shift == '1':
        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 2))
        eventShift2 = db.fetchall()

        if len(eventShift2) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, 2))
            conn.commit()

        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
        eventShift3 = db.fetchall()

        if len(eventShift3) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            conn.commit()

    elif shift == '2':
        db.execute('SELECT * FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
        eventShift3 = db.fetchall()

        if len(eventShift3) != 0:
            db.execute('DELETE FROM events WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, 3))
            conn.commit()

    return redirect(url_for('eventse'))

# MARK EVENT AS DONE
@app.route('/eventdone/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Executive", "index")
def eventdone(eventCode, shift):
    db.execute('UPDATE events SET visible = "no", done = "yes" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    return redirect(url_for('eventse'))

# UNDO MARKING AN EVENT AS DONE
@app.route('/eventundone/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Executive", "index")
def eventundone(eventCode, shift):
    db.execute('UPDATE events SET done = "no" WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    conn.commit()

    '''
    db.execute('SELECT value FROM events WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    eventValue = db.fetchall()[0][0]

    db.execute('SELECT id FROM completed WHERE eventCode = ? AND shift = ?', (eventCode, shift))
    granted = db.fetchall()
    grantedPrefects = [personId[0] for personId in granted]

    for prefectId in grantedPrefects:
        db.execute('SELECT credits FROM users WHERE id = ?', (prefectId,))
        currentCredits = db.fetchall()[0][0]
        db.execute('UPDATE users SET credits = ? WHERE id = ?', (currentCredits - eventValue, prefectId))
        db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, prefectId))
        db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id) VALUES (?, ?, ?, ?, ?)', (lookup(eventCode, shift)['name'], eventCode, shift, eventValue, prefectId))
    conn.commit()
    '''

    return redirect(url_for('eventse'))

# ------------------------------------------------------------------------------------------------------

# HOMEPAGE FOR SELECTING WHICH TABLE TO VIEW
@app.route('/approvee')
@login_required
@checkPositionPermission("Executive", "index")
def approvee():
    return render_template('approvee.html', currentaddress=None)

# SHOW SIGNUP TABLE, SORT BY TIME
@app.route('/requestede')
@login_required
@checkPositionPermission("Executive", "index")
def requestede():
    requested = []
    totalreq = 0

    db.execute('SELECT * FROM requested')
    pendingRequests = db.fetchall()

    for request in pendingRequests:
        if lookup(request[1], request[2])['done'] == 'no':
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            requested.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits': prefectCredits,
                'shift': request[2],
                'value': request[3],
                'id': request[4],
                'time': request[5]
            })
            totalreq += 1

    requested = sorted(requested, key=itemgetter('time'))

    return render_template('requestede.html', currentaddress='requestede', currentaddress2='byTime', totalreq=totalreq, requested=requested)

# SHOW SIGNUP TABLE, SORT BY EVENT COUNT
@app.route('/requestede/byEvents')
@login_required
@checkPositionPermission("Executive", "index")
def requestedeByEvents():
    requested = []
    totalreq = 0

    db.execute('SELECT * FROM requested')
    pendingRequests = db.fetchall()

    for request in pendingRequests:
        if lookup(request[1], request[2])['done'] == 'no':
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            requested.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits': prefectCredits,
                'shift': request[2],
                'value': request[3],
                'id': request[4],
                'time': request[5]
            })
            totalreq += 1

    requested = sorted(requested, key=itemgetter('credits', 'time'))

    return render_template('requestede.html', currentaddress='requestede', currentaddress2='byEvent', totalreq=totalreq, requested=requested)

# SHOW APPROVED SIGNUPS TABLE
@app.route('/approvede')
@login_required
@checkPositionPermission("Executive", "index")
def approvede():
    approved = []
    totalapp = 0

    db.execute('SELECT * FROM signup')
    approvedRequests = db.fetchall()

    for request in approvedRequests:
        if lookup(request[1], request[2])['done'] == 'no':
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            approved.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits': prefectCredits,
                'shift': request[2],
                'value': request[3],
                'id': request[4],
                'time': request[6]
            })
            totalapp += 1

    approved = sorted(approved, key=itemgetter('prefect'))

    return render_template('approvede.html', currentaddress='approvede', totalapp=totalapp, approved=approved)

# SHOW TABLE OF PREFECTS WHO HAVE COMPLETED SHIFT
@app.route('/confirmede')
@login_required
@checkPositionPermission("Executive", "index")
def confirmede():
    confirmed = []
    totalcon = 0

    db.execute('SELECT * FROM completed')
    confirmedRequests = db.fetchall()

    for request in confirmedRequests:
        if lookup(request[1], request[2])['done'] == 'no':
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            confirmed.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits': prefectCredits,
                'shift': request[2],
                'value': request[3],
                'id': request[4],
                'time': request[5]
            })
            totalcon += 1

    confirmed = sorted(confirmed, key=itemgetter('prefect'))

    return render_template('confirmede.html', currentaddress='confirmede', totalcon=totalcon, confirmed=confirmed)

# SHOW TABLE OF PREFECTS WHO HAVE NOT BEEN SELECTED
@app.route('/declinede')
@login_required
@checkPositionPermission("Executive", "index")
def declinede():
    declined = []
    totaldec = 0

    db.execute('SELECT * FROM declined')
    declinedRequests = db.fetchall()

    for request in declinedRequests:
        if lookup(request[1], request[2])['done'] == 'no':
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            declined.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits': prefectCredits,
                'shift': request[2],
                'value': request[3],
                'id': request[4],
                'time': request[5]
            })
            totaldec += 1

    declined = sorted(declined, key=itemgetter('prefect'))

    return render_template('declinede.html', currentaddress='declinede', totaldec=totaldec, declined=declined)

# APPROVE A SIGNUP (MOVE FROM REQUESTED TO SIGNUP)
@app.route('/approve/<eventCode>/<shift>/<id>')
@login_required
def approve(eventCode, shift, id):
    db.execute('SELECT * FROM requested WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('requestede'))

# APPROVE A SIGNUP (MOVE FROM DECLINED TO SIGNUP)
@app.route('/approvefromdeclined/<eventCode>/<shift>/<id>')
@login_required
def approvefromdeclined(eventCode, shift, id):
    db.execute('SELECT * FROM declined WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('declinede'))

# UNAPPROVE A SIGNUP (MOVE FROM SIGNUP TO DECLINED)
@app.route('/unapprove/<eventCode>/<shift>/<id>')
@login_required
def unapprove(eventCode, shift, id):
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][6]

    db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO requested (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('approvede'))

# DECLINE A SIGNUP (MOVE FROM REQUESTED TO DECLINED)
@app.route('/decline/<eventCode>/<shift>/<id>')
@login_required
def decline(eventCode, shift, id):
    db.execute('SELECT * FROM requested WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM requested WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO declined (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('requestede'))

# DECLINE A SIGNUP (MOVE FROM SIGNUP TO DECLINED)
@app.route('/declinefromapproved/<eventCode>/<shift>/<id>')
@login_required
def declinefromapproved(eventCode, shift, id):
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][6]

    db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO declined (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('approvede'))

# UNDECLINE A SIGNUP (MOVE FROM DECLINED TO REQUESTED)
@app.route('/undecline/<eventCode>/<shift>/<id>')
@login_required
def undecline(eventCode, shift, id):
    db.execute('SELECT * FROM declined WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM declined WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO requested (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    conn.commit()

    return redirect(url_for('declinede'))

# CONFIRM A SIGNUP/CHECK OUT PREFECT (MOVE FROM SIGNUP TO COMPLETED)
@app.route('/confirm/<eventCode>/<shift>/<id>')
@login_required
def confirm(eventCode, shift, id):
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][6]

    db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO completed (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    db.execute('SELECT credits FROM users WHERE id = ?', (id,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (
        currentCredits + lookup(eventCode, shift)['value'],
        id
    ))
    conn.commit()

    return redirect(url_for('approvede'))

# UNCONFIRM A SIGNUP (MOVE FROM COMPLETED TO SIGNUP)
@app.route('/unconfirm/<eventCode>/<shift>/<id>')
@login_required
def unconfirm(eventCode, shift, id):
    db.execute('SELECT * FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    db.execute('SELECT credits FROM users WHERE id = ?', (id,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (
        currentCredits - lookup(eventCode, shift)['value'],
        id
    ))
    conn.commit()

    return redirect(url_for('confirmede'))

# ------------------------------------------------------------------------------------------------------

# CHECKIN/OUT MAIN PAGE
@app.route('/checke')
@login_required
@checkPositionPermission("Executive", "index")
def checke():
    events = []

    db.execute('SELECT * FROM events WHERE done = "no"')
    activeEvents = db.fetchall()

    for event in activeEvents:
        tempdict = {
            'title': event[0],
            'id': event[1]
        }
        if tempdict not in events:
            events.append(tempdict)

    currentEvent = {
        'title': None,
        'id': None
    }

    return render_template('checke.html', events=events, currentEvent=currentEvent, visibility='hidden')

# OPEN PREFECTS FOR SELECTED EVENT
@app.route('/checke/<eventId>')
@login_required
@checkPositionPermission("Executive", "index")
def checkeventee(eventId):
    # Retrieve options
    events = []

    db.execute('SELECT * FROM events WHERE done = "no"')
    activeEvents = db.fetchall()

    for event in activeEvents:
        tempdict = {
            'title': event[0],
            'id': event[1]
        }
        if tempdict not in events:
            events.append(tempdict)

    # Current event
    db.execute('SELECT * FROM events WHERE eventCode = ?', (eventId,))
    currentEventInfo = db.fetchall()[0]

    currentEvent = {
        'title': currentEventInfo[0],
        'id': currentEventInfo[1]
    }

    # Not checked in
    notIn = []
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND checkin = "no"', (eventId,))
    notChecked = db.fetchall()

    for request in notChecked:
        db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
        prefectName = db.fetchall()[0][0]
        db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
        prefectGroup = db.fetchall()[0][0]

        notIn.append({
            'name': prefectName,
            'group': prefectGroup,
            'shift': request[2],
            'id': request[4]
        })

        notIn = sorted(notIn, key=itemgetter('shift', 'name'))

    # Checked in
    In = []
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND checkin = "yes"', (eventId,))
    checked = db.fetchall()

    for request in checked:
        db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
        prefectName = db.fetchall()[0][0]
        db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
        prefectGroup = db.fetchall()[0][0]

        In.append({
            'name': prefectName,
            'group': prefectGroup,
            'shift': request[2],
            'id': request[4]
        })

        In = sorted(In, key=itemgetter('shift', 'name'))

    # Checked out
    Out = []
    db.execute('SELECT * FROM completed WHERE eventCode = ?', (eventId,))
    checkedout = db.fetchall()

    for request in checkedout:
        db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
        prefectName = db.fetchall()[0][0]
        db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
        prefectGroup = db.fetchall()[0][0]

        Out.append({
            'name': prefectName,
            'group': prefectGroup,
            'shift': request[2],
            'id': request[4]
        })

        Out = sorted(Out, key=itemgetter('shift', 'name'))

    return render_template('checke.html', events=events, currentEvent=currentEvent, notIn=notIn, In=In, Out=Out,
                           visibility='visible')

# CHECK IN A PREFECT
@app.route('/checkin/<eventId>/<prefectId>')
@login_required
@checkPositionPermission("Executive", "index")
def checkin(eventId, prefectId):
    db.execute('UPDATE signup SET checkin = "yes" WHERE eventCode = ? AND id = ?', (eventId, prefectId))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventId))

# CHECK IN EVERYONE
@app.route('/checkallin/<eventId>')
@login_required
@checkPositionPermission("Executive", "index")
def checkallin(eventId):
    db.execute('UPDATE signup SET checkin = "yes" WHERE eventCode = ?', (eventId,))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventId))

# UNDO CHECKING IN A PREFECT (TURN CHECKIN VALUE FROM YES TO NO)
@app.route('/uncheckin/<eventId>/<prefectId>')
@login_required
@checkPositionPermission("Executive", "index")
def uncheckin(eventId, prefectId):
    db.execute('UPDATE signup SET checkin = "no" WHERE eventCode = ? AND id = ?', (eventId, prefectId))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventId))

# UNCHECK IN EVERYONE
@app.route('/uncheckallin/<eventId>')
@login_required
@checkPositionPermission("Executive", "index")
def uncheckallin(eventId):
    db.execute('UPDATE signup SET checkin = "no" WHERE eventCode = ?', (eventId,))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventId))

# CHECK OUT A PREFECT
@app.route('/checkout/<eventCode>/<shift>/<id>')
@login_required
@checkPositionPermission("Executive", "index")
def checkout(eventCode, shift, id):
    db.execute('SELECT * FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][6]

    db.execute('DELETE FROM signup WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO completed (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    db.execute('SELECT credits FROM users WHERE id = ?', (id,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (
        currentCredits + lookup(eventCode, shift)['value'],
        id
    ))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventCode))

# CHECK OUT EVERYONE
@app.route('/checkallout/<eventCode>')
@login_required
@checkPositionPermission("Executive", "index")
def checkallout(eventCode):
    tocheckout = []

    db.execute('SELECT * FROM signup')
    selected = db.fetchall()

    for selection in selected:
        if int(selection[1]) == int(eventCode):
            tocheckout.append(selection)

    db.execute('DELETE FROM signup WHERE eventCode = ?', (eventCode,))
    for prefect in tocheckout:
        db.execute('INSERT INTO completed (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
                   (lookup(eventCode, prefect[2])['name'], eventCode, prefect[2], lookup(eventCode, prefect[2])['value'], prefect[4], prefect[6]))
        db.execute('SELECT credits FROM users WHERE id = ?', (prefect[4],))
        currentCredits = db.fetchone()[0]
        db.execute('UPDATE users SET credits = ? WHERE id = ?', (
            currentCredits + lookup(eventCode, prefect[2])['value'],
            prefect[4]))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventCode))

# CHECK A PREFECT BACK IN (FROM BEING CHECKED OUT AKA UNDO CHECKOUT)
@app.route('/checkbackin/<eventCode>/<shift>/<id>')
@login_required
@checkPositionPermission("Executive", "index")
def checkbackin(eventCode, shift, id):
    db.execute('SELECT * FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    db.execute('SELECT credits FROM users WHERE id = ?', (id,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (
        currentCredits - lookup(eventCode, shift)['value'],
        id
    ))
    db.execute('UPDATE signup SET checkin = "yes" WHERE id = ?', (id,))

    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventCode))

# CHECK EVERYONE BACK IN
@app.route('/checkbackinall/<eventCode>')
@login_required
@checkPositionPermission("Executive", "index")
def checkbackinall(eventCode):

    db.execute('SELECT * FROM completed WHERE eventCode = ?', (eventCode,))
    selected = db.fetchall()

    db.execute('DELETE FROM completed WHERE eventCode = ?', (eventCode,))
    for prefect in selected:
        db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, checkin, signuptime) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (lookup(eventCode, prefect[2])['name'], eventCode, prefect[2], lookup(eventCode, prefect[2])['value'], prefect[4], "yes", prefect[5]))
        db.execute('SELECT credits FROM users WHERE id = ?', (prefect[4],))
        currentCredits = db.fetchone()[0]
        db.execute('UPDATE users SET credits = ? WHERE id = ?', (
            currentCredits - lookup(eventCode, prefect[2])['value'],
            prefect[4]))
    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventCode))

# MARK A PREFECT NOT CHECKED IN FROM CHECKED OUT (MOVE FROM BEING CHECKED OUT TO NOT EVEN BEING CHECKED IN)
@app.route('/uncheckinfromcheckout/<eventCode>/<shift>/<id>')
@login_required
@checkPositionPermission("Executive", "index")
def uncheckinfromcheckout(eventCode, shift, id):
    db.execute('SELECT * FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    timestamp = db.fetchall()[0][5]

    db.execute('DELETE FROM completed WHERE eventCode = ? AND shift = ? AND id = ?', (eventCode, shift, id))
    db.execute('INSERT INTO signup (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)',
               (lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], id, timestamp))
    db.execute('SELECT credits FROM users WHERE id = ?', (id,))
    currentCredits = db.fetchone()[0]
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (
        currentCredits - lookup(eventCode, shift)['value'],
        id
    ))
    db.execute('UPDATE signup SET checkin = "no" WHERE id = ? AND eventCode = ? AND shift = ?', (id, eventCode, shift))

    conn.commit()

    return redirect(url_for('checkeventee', eventId=eventCode))

# ------------------------------------------------------------------------------------------------------

# VIEW/CHANGE FILES (EXEC)
@app.route('/filese', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "files")
def filese():
    if request.method == 'GET':
        db.execute('SELECT * FROM files')
        fileData = db.fetchall()

        visible = [{
            'name': file[0],
            'link': file[1],
            'id': file[2]
        } for file in fileData if file[3] == 'yes']

        invisible = [{
            'name': file[0],
            'link': file[1],
            'id': file[2]
        } for file in fileData if file[3] == 'no']

        totalVisible = len(visible)
        totalInvisible = len(invisible)

        return render_template('filese.html', visibleFiles=visible, invisibleFiles=invisible, totalvis=totalVisible,
                               totalinvis=totalInvisible)

    else:
        if re.search(r'(?:.+\.)+.+', request.form.get('link')) == None:
            flash('Link is invalid. Please try again.')
            return redirect(url_for('filese'))

        elif not request.form.get('name'):
            flash('File name cannot be blank')
            return redirect(url_for('filese'))

        elif not request.form.get('link'):
            flash('File link cannot be blank')
            return redirect(url_for('filese'))

        if request.form.get('visible'):
            db.execute('INSERT INTO files (name, link, visible) VALUES (?, ?, ?)',
                       (request.form.get('name'), request.form.get('link'), 'yes'))
            conn.commit()

        else:
            db.execute('INSERT INTO files (name, link, visible) VALUES (?, ?, ?)',
                       (request.form.get('name'), request.form.get('link'), 'no'))
            conn.commit()

        return redirect(url_for('filese'))

# HIDE A FILE
@app.route('/hide/<fileId>')
@login_required
@checkPositionPermission("Executive", "index")
def hide(fileId):
    db.execute('UPDATE files SET visible = "no" WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filese'))

# SHOW A FILE
@app.route('/show/<fileId>')
@login_required
@checkPositionPermission("Executive", "index")
def show(fileId):
    db.execute('UPDATE files SET visible = "yes" WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filese'))

# REMOVE A FILE
@app.route('/remove/<fileId>')
@login_required
@checkPositionPermission("Executive", "index")
def remove(fileId):
    db.execute('DELETE FROM files WHERE id = ?', (fileId,))
    conn.commit()

    return redirect(url_for('filese'))

# ------------------------------------------------------------------------------------------------------

# VIEW PROFILE (EXEC)
@app.route('/profilee')
@login_required
@checkPositionPermission("Executive", "profile")
def profilee():
    '''Display user information'''

    # retrieve user information from database
    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('grade', creds[0][5]),
        ('stuNum', creds[0][6]),
        ('gender', creds[0][7]),
        ('dietary', creds[0][8]),
        ('group', creds[0][9]),
        ('size', creds[0][10]),
        ('status', creds[0][11]),
        ('home', creds[0][12]),
        ('cell', creds[0][13]),
        ('email', creds[0][14])
    ])

    return render_template('profilee.html', prefect=prefect)

# EDIT PROFILE (EXEC)
@app.route('/edite', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "edit")
def edite():
    if request.method == 'GET':
        # return user information from database
        db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        creds = db.fetchall()

        if creds[0][15] == 'Prefect':
            return redirect(url_for('edit'))

        prefect = dict([
            ('name', creds[0][2]),
            ('grade', creds[0][5]),
            ('stuNum', creds[0][6]),
            ('gender', creds[0][7]),
            ('dietary', creds[0][8]),
            ('group', creds[0][9]),
            ('size', creds[0][10]),
            ('status', creds[0][11]),
            ('home', creds[0][12]),
            ('cell', creds[0][13]),
            ('email', creds[0][14])
        ])

        return render_template('edite.html', prefect=prefect)

    else:
        # return user information from database
        db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        creds = db.fetchall()

        prefect = dict([
            ('name', creds[0][2]),
            ('grade', creds[0][5]),
            ('stuNum', creds[0][6]),
            ('gender', creds[0][7]),
            ('dietary', creds[0][8]),
            ('group', creds[0][9]),
            ('size', creds[0][10]),
            ('status', creds[0][11]),
            ('home', creds[0][12]),
            ('cell', creds[0][13]),
            ('email', creds[0][14])
        ])

        inputted = {
            'grade': request.form.get('grade'),
            'stuNum' : request.form.get('stuNum'),
            'gender': request.form.get('gender'),
            'dietary': request.form.get('dietary'),
            'size': request.form.get('size'),
            'status': request.form.get('status'),
            'home': request.form.get('home'),
            'cell': request.form.get('cell'),
            'email': request.form.get('email')
        }

        if not request.form.get('cell') or not request.form.get('email'):
            flash('Fields were left empty. Please try again.')
            return render_template('edite.html', prefect=prefect)
            # return redirect(url_for('edit'))

        elif re.search(r'[^@]+@[^@]+\.[^@]+', request.form.get('email')) == None:
            flash('Email is invalid. Please try again.')
            return render_template('edite.html', prefect=prefect)

        db.execute(
            'UPDATE users SET grade = ?, stuNum = ?, gender = ?, dietary = ?, size = ?, status = ?, home = ?, cell = ?, email = ? WHERE id = ?',
            (inputted['grade'], inputted['stuNum'], inputted['gender'], inputted['dietary'], inputted['size'], inputted['status'],
             inputted['home'], inputted['cell'], inputted['email'], session['user_id']))
        conn.commit()

        flash('Updated!')
        return redirect(url_for('profilee'))

# ------------------------------------------------------------------------------------------------------

# CHANGE PASSWORD (EXEC ACCESS)
@app.route('/changee', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "index")
def changee():
    '''Change password'''

    # check if information is sent
    if request.method == 'POST':
        if len(request.form.get('new')) < 8:
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('changee.html')
        if not re.search(r'\d', request.form.get('new')) and not re.search(r'\W', request.form.get('new')):
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('changee.html')

        db.execute("SELECT hash FROM users WHERE id = ?",
                   (session['user_id'],))
        password = db.fetchall()

        # check if password is not empty and matches current password
        if not request.form.get('current') or not check_password_hash(password[0][0], request.form.get("current")):
            flash('Current password is incorrect')
            return render_template('changee.html')
            # return apology('Current password is incorrect')

        # check if new password is not empty
        elif not request.form.get('new'):
            flash('Please enter a new password')
            return render_template('changee.html')
            # return apology('Please enter a new password')

        # check that new password and confirmation match
        elif request.form.get('new') != request.form.get('confirmation'):
            flash('Password and confirmation do not match')
            return render_template('changee.html')
            # return apology('Password and confirmation do not match')

        # update user's password in users database
        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   (generate_password_hash(request.form.get("new")),
                    session['user_id']))
        conn.commit()

        flash('Password changed!')  # notify of successful registration
        return redirect(url_for("indexe"))

    # if no information sent return change password page
    else:
        return render_template("changee.html")

# ------------------------------------------------------------------------------------------------------

# ADD PREFECT (EXEC)
@app.route('/adde', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Executive", "index")
def adde():
    if request.method == 'GET':
        db.execute('SELECT leader FROM users WHERE position = "Executive"')
        leaderData = db.fetchall()

        leaders = [leader[0] for leader in leaderData]

        db.execute('SELECT leader FROM users WHERE id = ?', (session['user_id'],))
        currentGroup = db.fetchall()[0][0]

        return render_template('adde.html', leaders=leaders, currentGroup=currentGroup)

    else:
        db.execute('SELECT username FROM users')
        registered = db.fetchall()
        registeredUsers = []

        for username in registered:
            registeredUsers.append(username[0])

        # Check that name is not blank
        if not request.form.get('name'):
            flash('Name cannot be blank')
            return redirect(url_for('adde'))

        # Check that username is not blank
        elif not request.form.get('username'):
            flash('Username cannot be blank')
            return redirect(url_for('adde'))

        # Check that password is not blank
        elif not request.form.get('password'):
            flash('Password cannot be blank')
            return redirect(url_for('adde'))

        # Check that username is not already in system
        elif request.form.get('username') in registeredUsers:
            flash('Username already exists! Try a different username.')
            return redirect(url_for('adde'))

        # Check that password and confirmation match
        elif request.form.get('password') != request.form.get('confirm'):
            flash('Password and confirmation do not match')
            return redirect(url_for('adde'))

        db.execute('INSERT INTO users (username, name, hash, grade, leader) VALUES (?, ?, ?, ?, ?)', (
            request.form.get('username'),
            request.form.get('name'),
            generate_password_hash(request.form.get('password')),
            request.form.get('grade'),
            request.form.get('leader')))
        conn.commit()

        flash('Registered!')
        return redirect(url_for('adde'))

'''
# HOMEPAGE (EXEC)
@app.route('/indexe')
@login_required
@checkPositionPermission("Executive", "index")
def indexe():
    Display user dashboard

    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    userGroup = creds[0][9]

    db.execute('SELECT * FROM users WHERE leader = ? AND id != ?', (userGroup, session['user_id']))
    members = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('position', creds[0][15])
    ])

    prefects = []

    for member in members:
        info = dict([
            ('name', member[2]),
            ('credits', member[4]),
            ('gender', member[7]),
            ('grade', member[5]),
            ('size', member[10]),
            ('stuNum', member[6]),
            ('email', member[14]),
            ('home', member[12]),
            ('cell', member[13]),
            ('dietary', member[8]),
            ('status', member[11])
        ])

        db.execute("SELECT * FROM completed WHERE id = ?", (member[0],))
        completed = db.fetchall()

        db.execute("SELECT * FROM signup WHERE id = ?", (member[0],))
        upcoming = db.fetchall()

        info['completed'] = [(event[0], event[2], event[3]) for event in completed]
        info['upcoming'] = [(event[0], event[2], event[3]) for event in upcoming]

        prefects.append(info)

    prefects = sorted(prefects, key=itemgetter('name'))

    total = {
        'male': 0,
        'female': 0,
        'eleven': 0,
        'twelve': 0,
        'xs': 0,
        's': 0,
        'm': 0,
        'l': 0,
        'xl': 0,
        'new': 0,
        'returning': 0
    }

    for member in members:
        if member[6] == 'Male':
            total['male'] += 1
        elif member[6] == 'Female':
            total['female'] += 1

        if member[9] == 'XS':
            total['xs'] += 1
        elif member[9] == 'S':
            total['s'] += 1
        elif member[9] == 'M':
            total['m'] += 1
        elif member[9] == 'L':
            total['l'] += 1
        elif member[9] == 'XL':
            total['xl'] += 1

        if member[5] == '11':
            total['eleven'] += 1
        elif member[5] == '12':
            total['twelve'] += 1

        if member[10] == 'New':
            total['new'] += 1
        elif member[10] == 'Returning':
            total['returning'] += 1

    return render_template('indexe.html', prefect=prefect, prefects=prefects, total=total)
'''

# -----------------------------------------------------------------------------------------------------------------------------------------------------
# PREFECT STUFF
# -----------------------------------------------------------------------------------------------------------------------------------------------------

# HOMEPAGE (PREFECT)
@app.route('/')
@login_required
@checkPositionPermission("Prefect", "indexe")
def index():
    ''' Display user dashboard '''

    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    db.execute("SELECT * FROM completed WHERE id = ?", (session['user_id'],))
    events = db.fetchall()

    db.execute("SELECT * FROM signup WHERE id = ?", (session['user_id'],))
    future = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('credits', float(creds[0][4])),
        ('events', [(event[0], event[2], event[3]) for event in events]),
        ('leader', creds[0][9]),
        ('registered', [(event[0], event[2], lookup(event[1], event[2])['value']) for event in future]),
        ('position', creds[0][15])
    ])

    return render_template('index.html', prefect=prefect)

# VIEW EVENTS (PREFECT)
@app.route('/events')
@login_required
@checkPositionPermission("Prefect", "eventse")
def events():
    # Get user's registered events
    db.execute('SELECT * FROM signup WHERE id = ?', (session['user_id'],))
    registeredEvents = db.fetchall()

    registered = [{
        'name': event[0],
        'shift': event[2],
        'value': event[3],
        'code': event[1]
    } for event in registeredEvents if lookup(event[1], event[2])['done'] == 'no']

    db.execute('SELECT * FROM requested WHERE id = ?', (session['user_id'],))
    requestedEvents = db.fetchall()

    requested = [{
        'name': event[0],
        'shift': event[2],
        'value': event[3],
        'code': event[1]
    } for event in requestedEvents if lookup(event[1], event[2])['done'] == 'no' and lookup(event[1], event[2])['visible'] == 'yes']

    # Get completed events
    db.execute('SELECT * FROM completed WHERE id = ?', (session['user_id'],))
    completedEvents = db.fetchall()

    completed = [{
        'name': event[0],
        'shift': event[2],
        'value': event[3]
    } for event in completedEvents]

    # Get available events
    db.execute('SELECT * FROM events WHERE visible = "yes"')
    availableEvents = db.fetchall()

    available = [{
        'name': event[0],
        'shift': event[2],
        'value': event[3],
        'code': event[1]
    } for event in availableEvents if
        event[1] not in [event[1] for event in registeredEvents] and event[1] not in [event[1] for event in requestedEvents] and event[
            1] not in [event[1] for event in completedEvents]]

    total = 0

    for event in completedEvents:
        total += float(event[3])

    return render_template('events.html', registered=registered, requested=requested, available=available,
                           completed=completed, total=total)

# SIGNUP FOR AN EVENT (PREFECT)
@app.route('/signup/<eventCode>/<shift>')
@login_required
@checkPositionPermission("Prefect", "eventse")
def signup(eventCode, shift):
    # Add to user's registered events
    db.execute('INSERT INTO requested (eventName, eventCode, shift, value, id, signuptime) VALUES (?, ?, ?, ?, ?, ?)', (
        lookup(eventCode, shift)['name'], eventCode, shift, lookup(eventCode, shift)['value'], session['user_id'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

    return redirect(url_for('events'))

# WITHDRAW EVENT SIGNUP (PREFECT)
@app.route('/withdraw/<eventCode>')
@login_required
def withdraw(eventCode):
    # Remove from user's registered events
    db.execute('DELETE FROM requested WHERE id = ? AND eventCode = ?', (session['user_id'], eventCode))
    conn.commit()

    return redirect(url_for('events'))

# VIEW FILES (PREFECT)
@app.route('/files')
@login_required
@checkPositionPermission("Prefect", "filese")
def files():
    db.execute('SELECT * FROM files')
    fileData = db.fetchall()

    fileDict = [{
        'name': file[0],
        'link': file[1]
    } for file in fileData if file[3] == 'yes']

    return render_template('files.html', files=fileDict)

# CONTACT INFO FOR PREFECTS
@app.route('/contact')
@login_required
@checkPositionPermission("Prefect", "indexe")
def contact():
    execs = []

    db.execute('SELECT * FROM users WHERE position = "Executive"')
    info = db.fetchall()

    for exec in info:
        if exec[0] < 12 :
            execs.append({
                'name': exec[2],
                'email': exec[13],
                'cell': exec[12]
                })

    return render_template('contact.html', execs=execs)

# VIEW PROFILE (PREFECT)
@app.route('/profile')
@login_required
@checkPositionPermission("Prefect", "profilee")
def profile():
    '''Display user information'''

    # retrieve user information from database
    db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    creds = db.fetchall()

    prefect = dict([
        ('name', creds[0][2]),
        ('grade', creds[0][5]),
        ('stuNum', creds[0][6]),
        ('gender', creds[0][7]),
        ('dietary', creds[0][8]),
        ('group', creds[0][9]),
        ('size', creds[0][10]),
        ('status', creds[0][11]),
        ('home', creds[0][12]),
        ('cell', creds[0][13]),
        ('email', creds[0][14])
    ])

    return render_template('profile.html', prefect=prefect)

# EDIT PROFILE (PREFECT)
@app.route('/edit', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Prefect", "edite")
def edit():
    if request.method == 'GET':
        # return user information from database
        db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        creds = db.fetchall()

        prefect = dict([
            ('name', creds[0][2]),
            ('grade', creds[0][5]),
            ('stuNum', creds[0][6]),
            ('gender', creds[0][7]),
            ('dietary', creds[0][8]),
            ('group', creds[0][9]),
            ('size', creds[0][10]),
            ('status', creds[0][11]),
            ('home', creds[0][12]),
            ('cell', creds[0][13]),
            ('email', creds[0][14])
        ])

        return render_template('edit.html', prefect=prefect)

    else:
        # return user information from database
        db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        creds = db.fetchall()

        prefect = dict([
            ('name', creds[0][2]),
            ('grade', creds[0][5]),
            ('stuNum', creds[0][6]),
            ('gender', creds[0][7]),
            ('dietary', creds[0][8]),
            ('group', creds[0][9]),
            ('size', creds[0][10]),
            ('status', creds[0][11]),
            ('home', creds[0][12]),
            ('cell', creds[0][13]),
            ('email', creds[0][14])
        ])

        inputted = {
            'grade': request.form.get('grade'),
            'stuNum': request.form.get('stuNum'),
            'gender': request.form.get('gender'),
            'dietary': request.form.get('dietary'),
            'size': request.form.get('size'),
            'status': request.form.get('status'),
            'home': request.form.get('home'),
            'cell': request.form.get('cell'),
            'email': request.form.get('email')
        }

        if not request.form.get('cell') or not request.form.get('email'):
            flash('Fields were left empty. Please try again.')
            return render_template('edit.html', prefect=prefect)
            # return redirect(url_for('edit'))

        elif re.search(r'[^@]+@[^@]+\.[^@]+', request.form.get('email')) == None:
            flash('Email is invalid. Please try again.')
            return render_template('edit.html', prefect=prefect)

        db.execute(
            'UPDATE users SET grade = ?, stuNum = ?, gender = ?, dietary = ?, size = ?, status = ?, home = ?, cell = ?, email = ? WHERE id = ?',
            (inputted['grade'], inputted['stuNum'], inputted['gender'], inputted['dietary'], inputted['size'], inputted['status'],
             inputted['home'], inputted['cell'], inputted['email'], session['user_id']))
        conn.commit()

        flash('Updated!')
        return redirect(url_for('profile'))

# CHANGE PASSWORD (PREFECT ACCESS)
@app.route('/change', methods=['GET', 'POST'])
@login_required
@checkPositionPermission("Prefect", "changee")
def change():
    '''Change password'''

    # check if information is sent
    if request.method == 'POST':
        if len(request.form.get('new')) < 8:
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('change.html')
        if not re.search(r'\d', request.form.get('new')) and not re.search(r'\W', request.form.get('new')):
            flash('Password must be at least 8 characters long and contain at least 1 number or special character')
            return render_template('change.html')

        db.execute("SELECT hash FROM users WHERE id = ?",
                   (session['user_id'],))
        password = db.fetchall()

        # check if password is not empty and matches current password
        if not request.form.get('current') or not check_password_hash(password[0][0], request.form.get("current")):
            flash('Current password is incorrect')
            return render_template('change.html')
            # return apology('Current password is incorrect')

        # check if new password is not empty
        elif not request.form.get('new'):
            flash('Please enter a new password')
            return render_template('change.html')
            # return apology('Please enter a new password')

        # check that new password and confirmation match
        elif request.form.get('new') != request.form.get('confirmation'):
            flash('Password and confirmation do not match')
            return render_template('change.html')
            # return apology('Password and confirmation do not match')

        # update user's password in users database
        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   (generate_password_hash(request.form.get("new")),
                    session['user_id']))
        conn.commit()

        flash('Password changed!')  # notify of successful registration
        return redirect(url_for("index"))

    # if no information sent return change password page
    else:
        return render_template("change.html")

# -----------------------------------------------------------------------------------------------------------------------------------------------------
# LOGIN AND LOGOUT
# -----------------------------------------------------------------------------------------------------------------------------------------------------

# LOGIN PAGE
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Log user in'''

    # Forget current user id
    session.clear()

    # Request via POST
    if request.method == "POST":

        # Make sure username is not empty
        if not request.form.get('username'):
            flash('Username cannot be blank')
            return render_template('login.html')
            # return apology('Username cannot be blank', 403)

        # Make sure password is not empty
        elif not request.form.get('password'):
            flash('Password cannot be blank')
            return render_template('login.html')
            # return apology('Password cannot be blank', 403)

        # Query database for username
        db.execute('SELECT * FROM users WHERE username = ?', (request.form.get('username'),))
        rows = db.fetchall()

        # Check that username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][3], request.form.get('password')):
            flash('Invalid username and/or password')
            return render_template('login.html')
            # return apology('Invalid username and/or password', 403)

        session['user_id'] = rows[0][0]

        if rows[0][15] == 'Prefect':
            return redirect('/')
        elif rows[0][15] == 'Executive':
            return redirect('/indexe')
        elif rows[0][15] == 'Admin':
            return redirect('/indexa')

    else:
        return render_template('login.html')

# LOGOUT PAGE
@app.route('/logout')
@login_required
def logout():
    '''Log user out'''

    # Forget user_id
    session.clear()

    return redirect('/')

# THIS SHOULD NOT EXIST
'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    Register user

    # Check that information is sent
    if request.method == 'POST':
        registered = db.execute('SELECT username FROM users')

        # Check that username is not blank
        if not request.form.get('username'):
            flash('Username cannot be blank')
            return render_template('register.html')
            # return apology('Username cannot be blank')

        # Check that password is not blank
        elif not request.form.get('password'):
            flash('Password cannot be blank')
            return render_template('register.html')
            # return apology('Password cannot be blank')

        # Check that password and confirmation match
        elif request.form.get('password') != request.form.get('confirm'):
            flash('Password and confirmation do not match')
            return render_template('register.html')
            # return apology('Password and confirmation do not match')

        # Add new user to database
        result = db.execute('INSERT INTO users (name, username, hash) VALUES (?, ?, ?)', (
            request.form.get('name'),
            request.form.get('username'),
            generate_password_hash(request.form.get('password'))))
        conn.commit()

        # If user cannot be added (id must be unique) then refuse
        if not result:
            flash('Account already exists')
            return render_template('register.html')
            # return apology('Account already exists')

        # Get user's information based on username
        db.execute('SELECT * from users WHERE username = ?',
                   (request.form.get('username'),))
        info = db.fetchall()

        # Get user's id
        session['user_id'] = info[0][0]

        flash('Registered!')  # Notify of successful registration
        return redirect(url_for('index'))

    # If not POST method then return to registration page
    else:
        return render_template('register.html')



@app.route('/viewe')
@checkPositionPermission("Executive","index")
def viewe():

    confirmed = []
    active = []

    db.execute('SELECT * FROM events WHERE visible = "yes" AND done = "no"')
    activeEvents = db.fetchall()

    for event in activeEvents:
        if (event[0], event[1]) not in active:
            active.append((event[0], event[1]))

    for event in active:
        db.execute('SELECT * FROM signup WHERE eventCode = ?', (event[1],))
        approved = db.fetchall()

        approvedPrefects = []

        for request in approved:
            db.execute('SELECT name FROM users WHERE id = ?', (request[4],))
            prefectName = db.fetchall()[0][0]
            db.execute('SELECT leader FROM users WHERE id = ?', (request[4],))
            prefectGroup = db.fetchall()[0][0]
            db.execute('SELECT credits FROM users WHERE id = ?', (request[4],))
            prefectCredits = db.fetchall()[0][0]
            db.execute('SELECT email FROM users WHERE id = ?', (request[4],))
            prefectEmail = db.fetchall()[0][0]
            db.execute('SELECT home FROM users WHERE id = ?', (request[4],))
            prefectHome = db.fetchall()[0][0]
            db.execute('SELECT cell FROM users WHERE id = ?', (request[4],))
            prefectCell = db.fetchall()[0][0]
            db.execute('SELECT dietary FROM users WHERE id = ?', (request[4],))
            prefectDietary = db.fetchall()[0][0]
            approvedPrefects.append({
                'eventName': request[0],
                'eventCode': request[1],
                'prefect': prefectName,
                'group': prefectGroup,
                'credits':  prefectCredits,
                'email': prefectEmail,
                'home': prefectHome,
                'cell': prefectCell,
                'dietary': prefectDietary,
                'shift': request[2],
                'value': request[3],
                'id': request[4]
                })

            approvedPrefects = sorted(approvedPrefects, key = itemgetter('shift', 'prefect'))

        confirmed.append({
            'title': event[0],
            'signups': approvedPrefects
            })

    return render_template('viewe.html', confirmed = confirmed)
'''


def errorhandler(e):
    '''Handle error'''
    return apology(e.name, e.code)


if __name__ == '__main__':
    app.run(debug=True)

for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

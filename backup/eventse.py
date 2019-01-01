if request.method == 'GET':
        db.execute('SELECT * FROM events')
        eventData = db.fetchall()

        visible = [{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'yes' and event[5] != 'yes']

        invisible = [{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] != 'yes']

        finished = [{
            'eventName': event[0],
            'eventCode': event[1],
            'shift': event[2],
            'value': event[3],
            'date': event[6]
        } for event in eventData if event[4] == 'no' and event[5] == 'yes']

        totalVisible = len(visible)
        totalInvisible = len(invisible)
        totalFinished = len(finished)

        return render_template('eventsa.html', visibleEvents=visible, invisibleEvents=invisible,
                               finishedEvents=finished, totalvis=totalVisible, totalinvis=totalInvisible,
                               totalfinished=totalFinished)

    else:
        if not request.form.get('name'):
            flash('Event name cannot be blank')
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
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'yes')
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 3,
                            float(request.form.get('shift1')) + float(request.form.get('shift2')), 'no')
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift2'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'yes')
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no')
                           )
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 2, request.form.get('shift2'), 'no')
                           )
                conn.commit()
        elif request.form.get('shift1') and request.form.get('shift3'):
            flash('Cannot input value for Both Shifts without value for Shift 2')
            return redirect(url_for('eventse'))
        elif request.form.get('shift1'):
            if request.form.get('visible'):
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'yes')
                           )
                conn.commit()
            else:
                db.execute('INSERT INTO events (eventName, eventCode, shift, value, visible) VALUES (?, ?, ?, ?, ?)',
                           (request.form.get('name'), newCode, 1, request.form.get('shift1'), 'no')
                           )
                conn.commit()

        flash('Event added!')
        return redirect(url_for('eventsa'))
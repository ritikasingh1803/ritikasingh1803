#import modules from flask for templates, request, route management, session management etc.
from flask import Flask, render_template, request, redirect, url_for, session
#import Bcrypt for hashing passwords before storing them in database
from flask_bcrypt import Bcrypt
#import pymysql, MySQL client to connect to database
from flask import send_from_directory
import pymysql.cursors
#import re module for regular expression matching for verifying user input
import re
#cd /opt/lampp
from werkzeug.utils import secure_filename
import os
app = Flask(__name__)

#configure app for HTTP security
app.config.update(
    DEBUG=True,
    SECRET_KEY="secret_sauce",
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

# Connect to the database
connection = pymysql.connect(host='localhost',
                             user='root',
                             password='',
                             database='test3',
                             cursorclass=pymysql.cursors.DictCursor)

#Create bcrypt object
bcrypt = Bcrypt(app)

#Create app routes and declare modules to perform actions on those requests.

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    if 'loggedin' in session:
        return render_template('home.html', account=session['name'])
    return render_template('/site/index.html')

@app.route("/about")
def about():
    if 'loggedin' in session:
        return render_template('home.html', account=session['name'])
    return render_template('/site/about_us.html')

@app.route("/contact")
def contact():
    if 'loggedin' in session:
        return render_template('home.html', account=session['name'])
    return render_template('/site/contact_us.html')

@app.route("/services")
def services():
    if 'loggedin' in session:
        return render_template('home.html', account=session['name'])
    return render_template('/site/services.html')


@app.route("/eval")
def eval():
    if 'loggedin' in session:
        quizz_id = request.args.get('quizzID')
        with connection.cursor() as cursor:
            #Read all the saved Quizz
            sql = "SELECT * FROM `quizz` WHERE `user_id` = %s AND `quizz_id` = %s"
            cursor.execute(sql,[session['id'], quizz_id])
            quizz = cursor.fetchone()
            #calculate depression score severity
            if quizz['d_score']<5:
                quizz['d_score_label'] = 'Normal'
            elif quizz['d_score']<7:
                quizz['d_score_label'] = 'Mild'
            elif quizz['d_score']<11:
                quizz['d_score_label'] = 'Moderate'
            elif quizz['d_score']<14:
                quizz['d_score_label'] = 'Severe'
            else:
                quizz['d_score_label'] = 'Extremely Severe'
            #calculate anxity score severity
            if quizz['a_score']<4:
                quizz['a_score_label'] = 'Normal'
            elif quizz['a_score']<6:
                quizz['a_score_label'] = 'Mild'
            elif quizz['a_score']<8:
                quizz['a_score_label'] = 'Moderate'
            elif quizz['a_score']<10:
                quizz['a_score_label'] = 'Severe'
            else:
                quizz['a_score_label'] = 'Extremely Severe'

            #calculate stress score severity
            if quizz['s_score']<8:
                quizz['s_score_label'] = 'Normal'
            elif quizz['s_score']<10:
                quizz['s_score_label'] = 'Mild'
            elif quizz['s_score']<13:
                quizz['s_score_label'] = 'Moderate'
            elif quizz['s_score']<17:
                quizz['s_score_label'] = 'Severe'
            else:
                quizz['s_score_label'] = 'Extremely Severe'

            print(quizz)
        return render_template('eval.html', quizz=quizz, account=session['name'])
    return redirect(url_for('login'))

@app.route("/evaluations")
def evaluations():
    if 'loggedin' in session:
        with connection.cursor() as cursor:
            #Read all the saved Quizz
            sql = "SELECT `quizz_id`, `total_score`, `d_score`, `a_score`, `s_score`, `time` FROM `quizz` WHERE `user_id` = %s"
            cursor.execute(sql,[session['id']])
            quizz = cursor.fetchall()
            # print(quizz)
        return render_template('evaluations.html', quizz=quizz, account=session['name'])
    return redirect(url_for('login'))

@app.route("/games")
def games():
    if 'loggedin' in session:
        return render_template('games.html', account=session['name'])
    return redirect(url_for('login'))


@app.route("/booknow")
def booknow():
    if 'loggedin' in session:
        return render_template('booknow.html', account=session['name'])
    return redirect(url_for('login'))

@app.route('/book-appointment', methods=['GET', 'POST'])
def book_appointment():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        location = request.form['location']
        age = int(request.form['age'])
        user_id = session.get('id')
        with connection.cursor() as cursor:
            sql = "INSERT INTO appointments (name, email, phone_number, location, age, user_id) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (name, email, phone_number, location, age, user_id))
            connection.commit()
        
        
    
    return render_template('thankyou.html')




@app.route("/prescription2")
def prescription2():
    if 'loggedin' in session:
        user_id = session['id']
        with connection.cursor() as cursor:
            sql = """
                    SELECT p.prescription_file 
                    FROM prescriptions p 
                    JOIN appointments a ON p.appointment_id = a.id 
                    WHERE a.user_id = %s
                """
            cursor.execute(sql, (user_id,))
            prescription2 = cursor.fetchall()
        return render_template('prescription.html', prescription2=prescription2,account=session['name'])
    return redirect(url_for('login'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route("/quiz")
def quiz():
    if 'loggedin' in session:
        return render_template('quiz.html', account=session['name'])
    return redirect(url_for('login'))

@app.route("/resources")
def resources():
    if 'loggedin' in session:
    
    
        with connection.cursor() as cursor:
            #Read all the saved Quizz
            sql = "SELECT `quizz_id`, `total_score`, `d_score`, `a_score`, `s_score`, `time` FROM `quizz` WHERE `user_id` = %s ORDER BY `time` DESC LIMIT 1"
            cursor.execute(sql,[session['id']])
    latest_quizz = cursor.fetchone()
    total_score = latest_quizz['total_score']
    score_category = None
    if total_score < 14:
        score_category = 'low'
    elif total_score >= 14 and total_score < 24:
        score_category = 'medium'
    else:
        score_category = 'high'
    with connection.cursor() as cursor:
            sql = "SELECT link FROM `resources` WHERE `score_category` = %s"
            cursor.execute(sql, [score_category])
            youtube_links = [row['link'] for row in cursor.fetchall()]
    
    
    
    return render_template('resources.html', account=session['name'],youtube_links=youtube_links,score=total_score)
    return redirect(url_for('login'))

#doctor dashboard
@app.route("/doctors")
def doctors():
    if 'loggedin2' in session:
        with connection.cursor() as cursor:
            # Read all the evaluation data for all users
            sql = """
                SELECT q.`user_id`, u.`name` AS user_name, q.`total_score`, q.`d_score`, q.`a_score`, q.`s_score`, q.`time`
                FROM `quizz` q
                JOIN `users` u ON q.`user_id` = u.`user_id` ORDER BY q.`time` DESC
            """
            cursor.execute(sql)
            quizz = cursor.fetchall()
        return render_template('/admin/doctors.html', quizz=quizz,account=session['name'])
    return redirect(url_for('login2'))


@app.route("/booking")
def booking():
    if 'loggedin2' in session:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM appointments"
            cursor.execute(sql)
            appointments = cursor.fetchall()
        return render_template('/admin/booking.html',  appointments=appointments,account=session['name'])
    return redirect(url_for('login2'))

#admin prescriptions
@app.route("/prescriptions", methods=['GET', 'POST'])
def prescriptions():
    if 'loggedin2' in session:
        if request.method == 'POST':
            # Handle updating the prescription file
            appointment_id = request.form['appointment_id']
            prescription_file = request.files['prescription']
            if prescription_file:
                filename = secure_filename(prescription_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                prescription_file.save(filepath)
                
                # Update the prescription record in the database
                with connection.cursor() as cursor:
                    sql = "UPDATE prescriptions SET prescription_file = %s WHERE appointment_id = %s"
                    cursor.execute(sql, (filename, appointment_id))
                    connection.commit()
                
                # Redirect back to prescription page
                return redirect(url_for('prescriptions'))
        
        # Fetch all prescriptions
        with connection.cursor() as cursor:
            sql = "SELECT * FROM prescriptions"
            cursor.execute(sql)
            prescriptions = cursor.fetchall()
        return render_template('/admin/prescription.html',  prescriptions=prescriptions,account=session['name'])
    return redirect(url_for('login2'))

@app.route('/upload-prescription/<int:appointment_id>', methods=['POST'])
def upload_prescription(appointment_id):
    if 'loggedin2' in session:
        if request.method == 'POST':
            prescription_file = request.files['prescription']
            if prescription_file:
                filename = secure_filename(prescription_file.filename)
                # Save the prescription file to the uploads folder
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                prescription_file.save(filepath)
                
                # Insert the prescription record into the database
                with connection.cursor() as cursor:
                    sql = "INSERT INTO prescriptions (appointment_id, prescription_file) VALUES (%s, %s)"
                    cursor.execute(sql, (appointment_id, filename))
                    connection.commit()
                
                # Redirect back to doctor dashboard
                return redirect(url_for('doctors'))
    
    return redirect(url_for('doctors'))


@app.route('/submitQuiz/', methods=['GET', 'POST'])
def submitQuiz():
    # Output message if something goes wrong...
    msg = ''
    if request.method == 'POST':
        #calculate depression score
        d_score = int(request.form['q3'])+int(request.form['q5'])+int(request.form['q10'])+int(request.form['q13'])+int(request.form['q16'])+int(request.form['q17'])+int(request.form['q21'])

        #calculate Anxiety score
        a_score = int(request.form['q2'])+int(request.form['q4'])+int(request.form['q7'])+int(request.form['q9'])+int(request.form['q15'])+int(request.form['q19'])+int(request.form['q20'])

        #calculate Stress score
        s_score = int(request.form['q1'])+int(request.form['q6'])+int(request.form['q8'])+int(request.form['q11'])+int(request.form['q12'])+int(request.form['q14'])+int(request.form['q18'])

        #calculate total score
        total_score = d_score + a_score + s_score
        # print(d_score, a_score, s_score)
        with connection.cursor() as cursor:
            sql = "INSERT INTO `quizz` (`user_id`,`q1`,`q2`,`q3`,`q4`,`q5`,`q6`,`q7`,`q8`,`q9`,`q10`,`q11`,`q12`,`q13`,`q14`,`q15`,`q16`,`q17`,`q18`,`q19`,`q20`,`q21`,`total_score`,`d_score`,`a_score`,`s_score`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            cursor.execute(sql,[session['id'], request.form['q1'],request.form['q2'],request.form['q3'],request.form['q4'],request.form['q5'],request.form['q6'],request.form['q7'],request.form['q8'],request.form['q9'],request.form['q10'],request.form['q11'],request.form['q12'],request.form['q13'],request.form['q14'],request.form['q15'],request.form['q16'],request.form['q17'],request.form['q18'],request.form['q19'],request.form['q20'],request.form['q21'],total_score, d_score, a_score, s_score])
        connection.commit()
        msg = 'form received'

    return render_template('quiz.html', msg=msg)


#doctor login
@app.route('/login2/', methods=['GET', 'POST'])
def login2():
    # Output message if something goes wrong...
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        # Create variables for easy access
        email = request.form['email']
        password = request.form['password']
        

        # Check if account exists using MySQL
        with connection.cursor() as cursor:
            # Read a single record
            sql = "SELECT `doctor_id`, `email`, `password` FROM `doctors` WHERE `email`=%s"
            cursor.execute(sql, [email])
            account = cursor.fetchone()
        # If account exists in accounts table in out database
        
        if account:
            # Create session data, we can access this data in other routes
            # login_user(account)
            if bcrypt.check_password_hash(account['password'], password):
                session['loggedin2'] = True
                session['id'] = account['doctor_id']
               # session['name'] = account['name']
                session['email'] = account['email']
                # Redirect to home page
                return redirect(url_for('doctors'))
        else:
            # Account doesnt exist or email/password incorrect
            msg = 'Incorrect Email/password!'
    return render_template('/admin/login.html', msg=msg)



#user login
@app.route('/login/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        # Create variables for easy access
        email = request.form['email']
        password = request.form['password']
        

        # Check if account exists using MySQL
        with connection.cursor() as cursor:
            # Read a single record
            sql = "SELECT `user_id`, `name`, `email`, `password` FROM `users` WHERE `email`=%s"
            cursor.execute(sql, [email])
            account = cursor.fetchone()
            print(account)

        # If account exists in accounts table in out database
        
        if account:
            # Create session data, we can access this data in other routes
            # login_user(account)
            if bcrypt.check_password_hash(account['password'], password):
                session['loggedin'] = True
                session['id'] = account['user_id']
                session['name'] = account['name']
                session['email'] = account['email']
                # Redirect to home page
                return redirect(url_for('home'))
        else:
            # Account doesnt exist or email/password incorrect
            msg = 'Incorrect Email/password!'
    return render_template('login.html', msg=msg)

@app.route('/logout')
# @login_required
def logout():
    if 'loggedin' in session:
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/dlogout')
# @login_required
def dlogout():
    if 'loggedin2' in session:
        session.pop('loggedin2', None)
        session.pop('id', None)
        session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login2'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "name", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        name = request.form['name']
        password = request.form['password']
        mobile = request.form['mobile']
        email = request.form['email']
        age = request.form['age']
        gender = request.form['gender']
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', name):
            msg = 'Name must contain only characters and numbers!'
        elif not re.match(r'^\d{10}$', mobile):
            msg = 'Invalid mobile number!'
        elif not name or not password or not email:
            msg = 'Please fill out the form!'
        
        else:
            # hash password
            hashed_password = bcrypt.generate_password_hash(
                password).decode('utf8')
            with connection.cursor() as cursor:
                # Read a single record
                sql = "SELECT `user_id`, `email` FROM `users` WHERE `email`=%s"
                cursor.execute(sql, [email])
                account = cursor.fetchone()
            # If account exists show error and validation checks
            if account:
                msg = 'Account already exists!'
            else:
                # Account doesnt exists and the form data is valid, now insert new account into accounts table
                with connection.cursor() as cursor:
                    # Create a new record
                    sql = "INSERT INTO `users` (`name`, `email`, `password`, `mobile`, `age`, `gender`) VALUES (%s,%s,%s,%s,%s,%s)"
                    cursor.execute(sql,[name,email,hashed_password, mobile, age, gender])
                # connection is not autocommit by default. So you must commit to save
                # your changes.
                connection.commit()
                msg = 'You have successfully registered!'
                return render_template('login.html', msg=msg)
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
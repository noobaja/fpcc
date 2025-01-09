from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from flask import make_response
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from datetime import timedelta, datetime
from email_validator import validate_email, EmailNotValidError
import os
import random
import string
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fpcc'
#app.permanent_session_lifetime = timedelta(minutes=1)

dbconnection = mysql.connector.connect(
    user='root',
    password='',
    host='localhost',
    database='fpcc',
)

if dbconnection.is_connected():
    print('Connection to database successfully.')

# Helper function to execute database queries
def query_db(query, args=(), one=False):
    cursor = dbconnection.cursor(dictionary=True)
    cursor.execute(query, args)
    rv = cursor.fetchall()
    dbconnection.commit()
    cursor.close()
    return (rv[0] if rv else None) if one else rv

# Initialize Flask-Mail
mail = Mail(app)

# Set up email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your mail server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'mukhlisnurarif.13@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'wzju uxnl hbtu wcbg'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'mukhlisnurarif.13@gmail.com'  # Replace with your email
app.config['MAIL_DEBUG'] = True

mail = Mail(app)


# Function to send verification email (simulation)
def send_verification_email(email, token):
    try:
        link_verify = url_for('verify_email', token=token, _external=True)
        msg = Message("Email Verification", recipients=[email])
        msg.body = f"To verify your email, click the following link: {link_verify}\n\nIf you did not register, please ignore this email."
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to send link reset (simulation)
def send_link_reset(email, token):
    try:
        link_reset = url_for('reset_password', token=token, _external=True)
        msg = Message("Password Reset Requests", recipients=[email])
        msg.body = f"To Reset Your Password, Click The Following Link: {link_reset}\n\nIf You Did Not Request This, Please Ignore This Email."
        mail.send(msg)
    except Exception as e:
        print(f"Error Sending email: {e}")

# Function to generate token verifivation
def generate_token_verifivation():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    
# Function to clean expired token
def clean_expired_token():
    while True:
        time.sleep(60) # Run cleanup every 60 seconds
        try:
            cursor = dbconnection.cursor()
            cursor.execute('UPDATE users SET reset_token=NULL WHERE token_expiry < %s', (datetime.now(),))
            dbconnection.commit()
        except mysql.connector.Error as err:
            print(f"Error during token cleanup: {err}")
        finally:
            cursor.close()
            
# Start the cleanup proccess is a separate thread
cleanup_thread = threading.Thread(target=clean_expired_token, daemon=True)
cleanup_thread.start()
        
# Form Signup
class SignupForm(FlaskForm):
    nama_lengkap = StringField('Nama Lengkap', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Signup')


class ScheduleForm(FlaskForm):
    MK = StringField('Mata Kuliah', validators=[DataRequired()])
    DL = StringField('Deadline', validators=[DataRequired()])
    isi = TextAreaField('Isi Tugas', validators=[DataRequired()])
    submit = SubmitField('Tambah Tugas')

# In-memory storage for messages (can be replaced with a database)
messages = []


@app.route('/')
def index():
    if 'user.id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user.id' in session and session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif 'user.id' in session and session.get('role') == 'user':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = dbconnection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['hash_password'], password):
            if not user['email_verified']:
                flash("Please verify your email before logging in.", 'error')
                return redirect(url_for('login'))

            session.permanent = True
            session['user.id'] = user['user_id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password!", 'error')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
def logout():
    # Clear all session data
    session.pop('user.id', None)  # Remove 'user.id' from session if exists
    session.pop('role', None)  # Remove 'role' from session if exists
    session.clear()  # Clear all session data

    # Optionally, you can set the session's permanent flag to False for security
    session.permanent = False

    # Redirect to the login page with a success message
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi data input
        if not email or not password or not nama_lengkap or not confirm_password:
            flash("All fields are required!", "error")
            return redirect(url_for('signup'))

        # Validasi format email
        try:
            validate_email(email)
        except EmailNotValidError:
            flash("Invalid email format!", "error")
            return redirect(url_for('signup'))
        
        # Validasi password
        if password != confirm_password:
            flash("Password do not match!", "error")
            return redirect(url_for('signup'))
        
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
            flash("Password must be at least 8 characters long and include at least one uppercase letter and one number.", "error")
            return redirect(url_for('signup'))

        cursor = dbconnection.cursor(dictionary=True)
        cursor.execute('SELECT email FROM users WHERE email=%s', (email,))
        if cursor.fetchone():
            flash("Email already registered!", "error")
            return redirect(url_for('signup'))

        # Hash password sebelum disimpan ke database
        hash_password = generate_password_hash(password)
        verification_token = generate_token_verifivation()


        cursor.execute('INSERT INTO users (nama_lengkap, email, hash_password, verification_token) VALUES (%s, %s, %s, %s)',
                        (nama_lengkap, email, hash_password, verification_token))
        dbconnection.commit()

        # Send email verification
        send_verification_email(email, verification_token)
        flash('Signup successful! Please verify your email!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    # Check token in database
    cursor = dbconnection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE verification_token=%s', (token,))
    user = cursor.fetchone()

    if user:
        # Update user status to verified
        cursor.execute('UPDATE users SET email_verified=TRUE, verification_token=NULL WHERE user_id=%s', (user['user_id'],))
        dbconnection.commit()
        flash('Email verified! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid token!', 'error')
        return redirect(url_for('signup'))


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        cursor = None

        try:
            cursor = dbconnection.cursor(dictionary=True)
            cursor.execute('SELECT user_id FROM users WHERE email=%s', (email,))
            user = cursor.fetchone()

            if user:
                token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
                token_expiry = datetime.now() + timedelta(minutes=15)
                
                # Simpan token dan waktu kedaluwarsa ke database
                cursor.execute('UPDATE users SET reset_token=%s, token_expiry=%s WHERE email=%s', (token, token_expiry, email))
                dbconnection.commit()
                
                # Kirim email reset password
                send_link_reset(email, token)
                flash('A reset password link has been sent to your email.', 'success')
                return redirect(url_for('forgot_password'))
                
            else:
                flash('Email not found!', 'error')
                return redirect(url_for('forgot_password'))

        except mysql.connector.Error as err:
            flash(f"Error: {err}", 'error')
            return redirect(url_for('forgot_password'))
        
        finally:
            if cursor:
                cursor.close()
            if dbconnection and dbconnection.is_connected():
                dbconnection.close()

    return render_template('forgotpassword.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cursor = None
    try:
        # Verifikasi token di database
        cursor = dbconnection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE reset_token=%s AND token_expiry > %s', (token, datetime.now()))
        user = cursor.fetchone()

        if not user:
            flash('Invalid or expired token. Please request a new password reset.', 'error')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Validasi input password dan konfirmasi
            if not password or not confirm_password:
                flash("All fields are required.", 'error')
                return redirect(url_for('reset_password', token=token))

            if password != confirm_password:
                flash("Passwords do not match!", 'error')
                return redirect(url_for('reset_password', token=token))

            # Validasi kekuatan password
            if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
                flash("Password must be at least 8 characters long, include at least one uppercase letter and one number.", 'error')
                return redirect(url_for('reset_password', token=token))

            # Hash new password before storing it
            hash_password = generate_password_hash(password)

            # Update password, clear token and expiry
            cursor.execute(
                'UPDATE users SET hash_password=%s, reset_token=NULL, token_expiry=NULL WHERE reset_token=%s',
                (hash_password, token)
            )
            dbconnection.commit()

            flash('Password has been reset successfully!', 'success')
            return redirect(url_for('login'))

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'error')
        return redirect(url_for('reset_password', token=token))
    finally:
        if cursor:
            cursor.close()

    return render_template('reset_password.html', token=token)


@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user.id' in session and session.get('role') == 'admin':
        try:
            cursor = dbconnection.cursor(dictionary=True)

            # Count users with role 'user'
            cursor.execute('SELECT COUNT(*) AS user_counts FROM users WHERE role = %s AND email_verified = 1', ('user',))
            user_counts = cursor.fetchone().get('user_counts', 0)

            # Get data for all tasks from users with role 'user'
            cursor.execute('''
                           SELECT users.user_id, users.nama_lengkap, users.email, COUNT(schedules.schedule_id) AS task_count FROM users
                           LEFT JOIN schedules ON users.user_id = schedules.user_id
                           WHERE users.role = %s AND users.email_verified = 1
                           GROUP BY users.user_id
                           ''', ('user', ))
            user_tasks = cursor.fetchall()

        except mysql.connector.Error as err:
            flash(f"Error fetching admin data: {err}", 'error')
            user_counts = 0
            user_tasks = []

        finally:
            if cursor:
                cursor.close()

        return render_template('admin_dashboard.html', user_counts=user_counts, user_tasks=user_tasks)

    else:
        return redirect(url_for('login'))
    

@app.route('/admin-users')
def admin_users():
    if 'user.id' in session and session.get('role') == 'admin':
        try:
            cursor = dbconnection.cursor(dictionary=True)

            # Get data for all tasks from users with role 'user'
            cursor.execute('''
                           SELECT users.user_id, users.nama_lengkap, users.email FROM users
                           WHERE users.role = %s AND users.email_verified = 1
                           GROUP BY users.user_id
                           ''', ('user', ))
            user_tasks = cursor.fetchall()

        except mysql.connector.Error as err:
            flash(f"Error fetching admin data: {err}", 'error')
            user_tasks = []

        finally:
            if cursor:
                cursor.close()

        return render_template('admin_users.html', user_tasks=user_tasks)

    else:
        return redirect(url_for('login'))
    

@app.route('/dashboard')
def dashboard():
    if 'user.id' in session and session.get('role') == 'user':
        user_id = session['user.id'] # Ambil ID pengguna dari sesi

        try:
            cursor = dbconnection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM schedules WHERE user_id = %s ORDER BY DL', (user_id,))
            tasks = cursor.fetchall()

        except mysql.connector.Error as err:
            tasks = []
            flash(f"Error fetching tasks: {err}", 'error')

        finally:
            if cursor:
                cursor.close()

        return render_template('dashboard.html', tasks=tasks)
    else:
        if 'user.id' in session and session.get('role') == 'admin':
            flash('Admin is not allowed to access the page.', 'error')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('You are not logged in.', 'error')

        return redirect(url_for('login'))
    

@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if 'user.id' in session and session.get('role') == 'user':
        form = ScheduleForm()

        if request.method == 'POST':
            if form.validate_on_submit():
                MK = form.MK.data
                DL_raw = form.DL.data
                isi = form.isi.data
                user_id = session['user.id'] # Get user id session

                try:
                    # Convert DL to datetime python
                    DL = datetime.strptime(DL_raw, '%Y-%m-%dT%H:%M')

                    # Insert to database
                    cursor = dbconnection.cursor(dictionary=True)
                    query = 'INSERT INTO schedules (MK, DL, isi, user_id) VALUES (%s, %s, %s, %s)'
                    print(f"Executing query: {query} with values: {MK}, {DL}, {isi}")
                    cursor.execute(query, (MK, DL, isi, user_id))
                    dbconnection.commit()
                    print("Data committed successfully")
                    flash('Tugas Berhasil Ditambahkan!', 'success')
                    return redirect(url_for('schedule'))
                except mysql.connector.Error as err:
                    print(f"Error: {err}")
                    flash(f"Database Error: {err}", 'error')
                except ValueError as ve:
                    print(f"Value Error: {ve}")
                    flash(f"Invalid date format: {DL_raw}", 'error')
                finally:
                    if cursor:
                        cursor.close()
            else:
                print("Form is not valid:", form.errors)

        # Fetch tasks from the database
        try:
            cursor = dbconnection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM schedules ORDER BY DL')
            tasks = cursor.fetchall()
        except mysql.connector.Error as err:
            tasks = []
            flash(f"Error fetching tasks: {err}", 'error')
        finally:
            if cursor:
                cursor.close()

        return render_template('schedule.html', form=form, tasks=tasks)
    else:
        flash('Admin is not allowed to access the page.', 'error')
        return redirect(url_for('login'))

    
@app.route('/assignments')
def assignments():
    if 'user.id' in session and session.get('role') == 'user':
        user_id = session['user.id'] # Get session user.id

        try:
            cursor = dbconnection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM schedules WHERE user_id = %s ORDER BY DL', (user_id,))
            tasks = cursor.fetchall()

        except mysql.connector.Error as err:
            tasks = []
            flash(f"Error fetching assignments: {err}", 'error')
            
        finally:
            if cursor:
                cursor.close()
                
        return render_template('assignments.html', tasks=tasks)
    else:
        flash('Admin is not allowed to access the page.', 'error')
        return redirect(url_for('login'))
    

@app.route('/discussion', methods=['GET', 'POST'])
def discussion():
    if 'user.id' in session and session.get('role') == 'user':
        user_id = session['user.id']
        username = session.get('username', 'Anonymous')

        if request.method == 'POST':
            # Handle text messages
            if 'message' in request.form:
                text_message = request.form['message']
                if text_message.strip():
                    query_db(
                        'INSERT INTO messages (user_id, message, timestamp) VALUES (%s, %s, %s)',
                        (user_id, text_message, datetime.now())
                    )
                else:
                    flash('Message cannot be empty.', 'error')

            return redirect(url_for('discussion'))

        # Fetch messages from the database with user details and identify current user's messages
        messages = query_db('''
                            SELECT messages.message, messages.timestamp, users.nama_lengkap,
                            CASE WHEN messages.user_id = %s THEN TRUE ELSE FALSE END AS is_current_user
                            FROM messages
                            JOIN users ON messages.user_id = users.user_id
                            ORDER BY messages.timestamp ASC
                            ''', (user_id,))
        return render_template('discussion.html', messages=messages)

    else:
        flash('Admin is not allowed to access the page.', 'error')
        return redirect(url_for('login'))
    

@app.route('/delete-tasks/<int:schedule_id>', methods=['GET'])
def delete_tasks(schedule_id):
    if 'user.id' in session and session.get('role') == 'user':
        user_id = session['user.id']

        # Validate task ID
        task = query_db('SELECT * FROM schedules WHERE schedule_id = %s AND user_id = %s', (schedule_id, user_id))
        if not task:
            flash('Task not found or unauthorized access.', 'error')
            return redirect(url_for('assignments'))  # Correct Route

        # Delete task from the database
        query_db('DELETE FROM schedules WHERE schedule_id = %s', (schedule_id,))  # Correct Table
        flash('Task deleted successfully.', 'success')
        return redirect(url_for('assignments'))
    else:
        flash('Admin is not allowed to access the page.', 'error')
        return redirect(url_for('login'))
    

@app.route('/delete-user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    if 'user.id' in session and session.get('role') == 'admin':

        try:
            cursor = dbconnection.cursor(dictionary=True)
            # Validate user ID
            cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
            user = cursor.fetchone()

            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('admin_dashboard'))
        
            # Delete user from the database
            cursor.execute('DELETE FROM users WHERE user_id = %s', (user_id,))
            dbconnection.commit()
            flash('User deleted successfully.', 'success')
        
        except mysql.connector.Error as err:
            flash(f'Error deleting user: {err}', 'error')

        finally:
            if cursor:
                cursor.close()

        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('login'))
    

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

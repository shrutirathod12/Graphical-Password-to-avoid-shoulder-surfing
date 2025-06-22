from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_migrate import Migrate
from datetime import datetime
import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import random
import logging

load_dotenv()
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///major_project2.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Required for flashing messages
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')


db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Admin
admin = Admin(app, name='Database Admin', template_mode='bootstrap3')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.String(10), nullable=False)  # Format: YYYY-MM-DD
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    security_pin = db.Column(db.String(64), nullable=False)  # Hashed PIN stored securely
    color_auth_complete = db.Column(db.Boolean, default=False)
    color_rgb = db.Column(db.Integer, nullable=True)  # Example: RGB stored as an integer
    image1 = db.Column(db.String(150), nullable=True)
    image1_x = db.Column(db.Integer, nullable=True)
    image1_y = db.Column(db.Integer, nullable=True)
    image2 = db.Column(db.String(150), nullable=True)
    image2_x = db.Column(db.Integer, nullable=True)
    image2_y = db.Column(db.Integer, nullable=True)
    image_auth_complete = db.Column(db.Boolean, default=False)
    max_trial_counter = db.Column(db.Integer, default=0)  # Tracks login attempts
    is_blocked = db.Column(db.Boolean, default=False)  # Flag to block users after too many failed attempts

class EvaluationMatrix(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_attempt = db.Column(db.Integer, nullable=False)
    login_time = db.Column(db.Float, nullable=False)
    phase1_success = db.Column(db.Boolean, nullable=False)
    phase2_success = db.Column(db.Boolean, nullable=False)
    phase3_success = db.Column(db.Boolean, nullable=False)
    total_success = db.Column(db.Boolean, nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False)
    reset_requests = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

admin.add_view(ModelView(User, db.session))


@app.route('/')
def index():
    return render_template('index.html')

@app.route("/help")
def help():
    return render_template("help.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            start_time = datetime.utcnow()

            # ✅ Set phase1_success to True before database insertion
            session['phase1_success'] = True  
            session['phase2_success'] = session.get('phase2_success', False)
            session['phase3_success'] = session.get('phase3_success', False)

            # Debugging: Print session values
            print("Session Values Before Insert:", session['phase1_success'], session['phase2_success'], session['phase3_success'])

            # Check if previous attempts exist
            last_attempt = EvaluationMatrix.query.filter_by(user_id=user.id).order_by(EvaluationMatrix.login_attempt.desc()).first()
            login_attempt = last_attempt.login_attempt + 1 if last_attempt else 1

            # Fetch phase success from session variables
            phase1_success = session['phase1_success']
            phase2_success = session['phase2_success']
            phase3_success = session['phase3_success']
            
            total_success = phase1_success and phase2_success and phase3_success
            failed_attempts = 0 if total_success else 1
            reset_requests = 0  

            # ✅ Save the correct phase1_success value to the database
            new_attempt = EvaluationMatrix(
                user_id=user.id,
                login_attempt=login_attempt,
                login_time=(datetime.utcnow() - start_time).total_seconds(),
                phase1_success=phase1_success,  # ✅ Correctly updated
                phase2_success=phase2_success,
                phase3_success=phase3_success,
                total_success=total_success,
                failed_attempts=failed_attempts,
                reset_requests=reset_requests
            )
            db.session.add(new_attempt)
            db.session.commit()

            flash('Login successful!', 'success')
            return redirect(url_for('color_auth_complete'))
        
        else:
            # ❌ Do NOT set session['phase1_success'] to False permanently
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


def generate_security_pin(full_name, dob):
    try:
        first_two_letters = full_name[:2].upper()
        dob_parts = dob.split('-')
        if len(dob_parts) == 3:
            dob_ddmm = dob_parts[2] + dob_parts[1]
            return first_two_letters + dob_ddmm  # Example: "JO1506"
        else:
            return None
    except Exception:
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        full_name = request.form.get('full_name').strip()
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()
        dob = request.form.get('dob').strip()
        security_question = request.form.get('security_question').strip()
        security_answer = request.form.get('security_answer').strip()

        if not all([email, password, confirm_password, dob, full_name, security_question, security_answer]):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('register'))

        security_pin = generate_security_pin(full_name, dob)
        if not security_pin:
            flash('Invalid date of birth format.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(
                email=email,
                full_name=full_name,
                password=generate_password_hash(password),
                dob=dob,
                security_pin=generate_password_hash(security_pin),  # Hashing the PIN
                security_question=security_question,
                security_answer=generate_password_hash(security_answer)
            )
            db.session.add(new_user)
            db.session.commit()

            session['Submission_success'] = True
            session['email'] = email
            flash(f'Registration successful! ', 'success')
            return redirect(url_for('color_based_password'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error during registration: {e}', 'error')

    return render_template('register.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('forgot_password_security.html', 
                                   security_question=user.security_question, email=user.email)
        else:
            flash('Email not found. Please register first.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/verify-security-answer', methods=['POST'])
def verify_security_answer():
    email = request.form['email']
    security_answer = request.form['security_answer']
    
    # Ensure the email and answer are provided
    if not email or not security_answer:
        flash('Please provide both email and security answer.', 'error')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        if check_password_hash(user.security_answer, security_answer):
            # Proceed to password reset if the answer is correct
            return render_template('reset_password.html', email=user.email)
        else:
            flash('Incorrect security answer. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
    else:
        flash('Email not found. Please try again.', 'error')
        return redirect(url_for('forgot_password'))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']  # You are already passing email from template
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('reset_password', email=email))

    user = User.query.filter_by(email=email).first()

    if user:
        # Hash the new password and update the database
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Password reset successful! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    else:
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
        
import hashlib

@app.route('/color_based_password', methods=['GET', 'POST'])
def color_based_password():
    # Check if the user is in the session
    if 'email' not in session:
        flash('Please complete the textual password phase first.', 'error')
        return redirect(url_for('register'))  # Redirect to registration if not logged in

    # Fetch the logged-in user from the database
    user = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        # Retrieve the RGB color from the form
        color_rgb = request.form.get('color_rgb', '').strip()

        # Validate that the color was selected
        if not color_rgb:
            flash('Please select a color.', 'error')
            return redirect(url_for('color_based_password'))

        try:
            # Hash the RGB color using SHA-256
            hashed_color = hashlib.sha256(color_rgb.encode()).hexdigest()

            # Save the hashed RGB color to the database
            if user:
                user.color_rgb = hashed_color  # Store the hashed RGB color in the database
                db.session.commit()
                flash('Color-based password phase completed successfully!', 'success')

                # Mark this phase as completed in the session
                session['color_based_password'] = True
                return redirect(url_for('image_based_auth'))
            else:
                flash('User not found.', 'error')
                return redirect(url_for('color_based_password'))

        except Exception as e:            # Rollback the session in case of an error
            db.session.rollback()
            flash(f'Error setting color-based password: {str(e)}', 'error')
            return redirect(url_for('color_based_password'))

    return render_template('color_based_password.html')

@app.route('/forgot_Color', methods=['GET', 'POST'])
def forgot_Color():
    if request.method == 'POST':
        entered_pin = request.form.get('security_pin')
        user = User.query.filter_by(email=session.get('email')).first()

        if user and check_password_hash(user.security_pin, entered_pin):
            session['reset_allowed'] = True
            return redirect(url_for('reset_color_selection'))  # Redirect to reset page
        
        flash('Incorrect PIN. Try again.', 'danger')
    
    return render_template('forgot_Color.html')


@app.route('/verify_pin', methods=['POST'])
def verify_pin():
    email = request.form.get('email')
    entered_pin = request.form.get('security_pin')

    # Check if user exists
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.security_pin, entered_pin):
        flash('PIN verification successful!', 'success')
        return redirect(url_for('reset_color_selection', email=email))  # Redirect to password reset or next step
    else:
        flash('Invalid PIN. Please try again.', 'error')
        return redirect(url_for('forgot_Color'))

@app.route('/verify_pin_image', methods=['POST'])
def verify_pin_image():
    email = request.form.get('email')
    entered_pin = request.form.get('security_pin')

    # Check if user exists
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.security_pin, entered_pin):
        flash('PIN verification successful!', 'success')
        return redirect(url_for('reset_image_selection', email=email))  # Redirect to password reset or next step
    else:
        flash('Invalid PIN. Please try again.', 'error')
        return redirect(url_for('forgot_image'))
import hashlib

@app.route('/reset_color_selection', methods=['GET', 'POST'])
def reset_color_selection():
    if not session.get('reset_allowed'):
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session.get('email')).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        selected_color = request.form.get('color_rgb')  # <-- Make sure this matches the form
        if selected_color:
            hashed_color = hashlib.sha256(selected_color.encode()).hexdigest()
            user.color_rgb = hashed_color  # <-- Save the hashed value
            db.session.commit()
            session.pop('reset_allowed', None)
            flash("Color password reset successfully!", "success")
            return redirect(url_for('color_auth_complete'))
        else:
            flash("Please select a color!", "error")

    return render_template('reset_color_selection.html')
  # Use the existing color selection page

from werkzeug.security import check_password_hash

@app.route('/color_auth_complete', methods=['GET', 'POST'])
def color_auth_complete():
    # Check if the user is in the session
    if 'email' not in session:
        flash('Please complete the textual password phase first.', 'error')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Fetch the logged-in user from the database
    user = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        # Retrieve the RGB color from the form
        color_rgb = request.form.get('color_rgb', '').strip()

        # Validate that the color was selected
        if not color_rgb:
            flash('Please select a color.', 'error')
            return redirect(url_for('color_auth_complete'))  # Redirect to the same page

        try:
            # Hash the RGB color using SHA-256
            hashed_color = hashlib.sha256(color_rgb.encode()).hexdigest()

            # Check if the entered color matches the stored hashed color
            if user and user.color_rgb == hashed_color:
                flash('Color-based password phase completed successfully!', 'success')
                session['phase2_success'] = True

                # Mark this phase as completed in the session
                session['color_auth_complete'] = True
                return redirect(url_for('image_auth_complete'))  # Proceed to the image-based auth phase
            else:
                flash('Incorrect color-based password. Please try again.', 'error')
                session['phase2_success'] = False
                return redirect(url_for('color_auth_complete'))  # Redirect to the same page

        except Exception as e:
            # Handle any errors during the authentication process
            flash(f'Error during authentication: {str(e)}', 'error')
            return redirect(url_for('color_auth_complete'))  # Redirect to the same page

    return render_template('color_auth_complete.html')  # The template for color-based authentication

@app.route('/image_based_auth', methods=['GET', 'POST'])
def image_based_auth():
    if 'email' not in session:
        flash('Please register or log in first.', 'error')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=session['email']).first()
    image_list = ['image1.jpeg', 'image2.jpeg', 'image3.jpeg', 'image4.jpeg', 'image5.jpeg',
                  'image6.jpeg', 'image7.jpeg', 'image8.jpeg', 'image9.jpeg', 'image10.jpeg',
                  'image11.jpeg', 'image12.jpeg', 'image13.jpeg', 'image14.jpeg', 'image15.jpeg',
                  'image16.jpeg', 'image17.jpeg', 'image18.jpeg', 'image19.jpeg', 'image20.jpeg',
                  'image21.jpeg', 'image22.jpeg', 'image23.jpeg', 'image24.jpeg', 'image25.jpeg']

    if request.method == 'POST':
        selected_images = request.form.getlist('selected_images')
        coordinates = request.form.get('image_coordinates', '').split('|')  # Retrieve coordinates as "x,y"

        if len(selected_images) != 2 or len(coordinates) != 2:
            flash('Please select exactly 2 images.', 'error')
        else:
            # Parse coordinates
            x1, y1 = map(int, coordinates[0].split(','))
            x2, y2 = map(int, coordinates[1].split(','))

            # Save selected images and their coordinates
            user.image1 = selected_images[0]
            user.image1_x = x1
            user.image1_y = y1
            user.image2 = selected_images[1]
            user.image2_x = x2
            user.image2_y = y2

            try:
                db.session.commit()
                flash('Images and coordinates saved successfully.', 'success')
            except Exception as e:
                flash(f'Error saving images: {str(e)}', 'error')
                db.session.rollback()

            return redirect(url_for('login'))  # Redirect to login page

    return render_template('image_based_auth.html', images=image_list)

@app.route('/image_auth_complete', methods=['GET', 'POST'])
def image_auth_complete():
    if 'email' not in session:
        flash('Please register or log in first.', 'error')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('register'))

    # Generate and store shuffled grid once during GET
    if request.method == 'GET':
        image_list = [f'image{i}.jpeg' for i in range(1, 26)]
        shuffled_images = random.sample(image_list, len(image_list))
        session['shuffled_images'] = shuffled_images  # Store in session

    shuffled_images = session.get('shuffled_images', [])

    if request.method == 'POST':
        selected_images = request.form.getlist('selected_images')
        current_max_trial = user.max_trial_counter

        if len(selected_images) != 2:
            flash('Please select exactly 2 images.', 'error')
        else:
            try:
                is_authenticated, updated_max_trial = validate_image_password(
                    user.id, selected_images, shuffled_images, current_max_trial
                )
            except ValueError as e:
                flash('Authentication error. Please try again.', 'error')
                return redirect(url_for('image_auth_complete'))

            user.max_trial_counter = updated_max_trial
            db.session.commit()

            if is_authenticated:
                session['phase3_success'] = True
                flash('Authentication Successful!', 'success')
                user.image_auth_complete = True
                db.session.commit()
                return redirect(url_for('welcome'))
            else:
                session['phase3_success'] = False
                remaining_attempts = 3 - updated_max_trial
                flash(f'Authentication Failed. {remaining_attempts} attempts left.', 'error')

    return render_template('image_auth_complete.html', images=shuffled_images)

@app.route('/forgot_image', methods=['GET', 'POST'])
def forgot_image():
    if 'email' not in session:
        flash('Session expired. Please enter your email again.', 'warning')
        return redirect(url_for('forgot_password'))  # Redirect to email entry page

    if request.method == 'POST':
        entered_pin = request.form.get('security_pin')
        user = User.query.filter_by(email=session.get('email')).first()

        if user and check_password_hash(user.security_pin, entered_pin):
            session['reset_image_allowed'] = True  # Grant permission to reset image
            return redirect(url_for('reset_image_selection'))  # Redirect to image selection page
        
        flash('Incorrect PIN. Try again.', 'danger')
    
    return render_template('forgot_image.html')

@app.route('/reset_image_selection', methods=['GET', 'POST'])
def reset_image_selection():
    if not session.get('reset_image_allowed'):  
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))  # Prevent direct access

    user = User.query.filter_by(email=session.get('email')).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=session['email']).first()
    image_list = ['image1.jpeg', 'image2.jpeg', 'image3.jpeg', 'image4.jpeg', 'image5.jpeg',
                  'image6.jpeg', 'image7.jpeg', 'image8.jpeg', 'image9.jpeg', 'image10.jpeg',
                  'image11.jpeg', 'image12.jpeg', 'image13.jpeg', 'image14.jpeg', 'image15.jpeg',
                  'image16.jpeg', 'image17.jpeg', 'image18.jpeg', 'image19.jpeg', 'image20.jpeg',
                  'image21.jpeg', 'image22.jpeg', 'image23.jpeg', 'image24.jpeg', 'image25.jpeg']


    if request.method == 'POST':
        selected_images = request.form.getlist('selected_images')  # Get new image choices
        coordinates = request.form.get('image_coordinates', '').split('|')  # Retrieve coordinates

        if len(selected_images) != 2 or len(coordinates) != 2:
            flash('Please select exactly 2 images with coordinates.', 'error')
        else:
            # Parse new coordinates
            x1, y1 = map(int, coordinates[0].split(','))
            x2, y2 = map(int, coordinates[1].split(','))

            # Update images and their coordinates
            user.image1 = selected_images[0]
            user.image1_x = x1
            user.image1_y = y1
            user.image2 = selected_images[1]
            user.image2_x = x2
            user.image2_y = y2

            try:
                db.session.commit()
                flash("Image-based password reset successfully!", "success")
                session.pop('reset_image_allowed', None)  # Remove reset permission
                return redirect(url_for('image_auth_complete'))  # Redirect to logi
            except Exception as e:
                flash(f"Error updating images: {str(e)}", "danger")
                db.session.rollback()

    return render_template('reset_image_selection.html', images=image_list)  # Show all images


def block_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_blocked = True  # Assuming you have an `is_blocked` field in your User model
        db.session.commit()

def validate_image_password(user_id, selected_images, shuffled_images, max_trial_counter):
    # 1. Get user data
    user = User.query.get(user_id)
    if not user:
        return False, max_trial_counter

    # 2. Get registered image coordinates
    registered_coords = []
    try:
        for img in [user.image1, user.image2]:
            idx = shuffled_images.index(img)
            x, y = divmod(idx, 5)  # 5-column grid
            registered_coords.append((x, y))
    except ValueError:
        return False, max_trial_counter + 1

    # 3. Coordinate calculations
    X1, Y1 = registered_coords[0]
    X2, Y2 = registered_coords[1]

    if Y1 > Y2 and X2 > X1 or Y1 < Y2 and X1 < X2:  # Scenario A
        passX1, passY1 = X2, Y1
        passX2, passY2 = X1, Y2
    elif Y1 == Y2:  # Scenario C (Same row)
        passX1, passX2 = (X1 + 1) % 5, (X2 + 1) % 5
        passY1, passY2 = Y1, Y2
    elif X1 == X2:  # Scenario B (Same column)
        passY1, passY2 = (Y1 + 1) % 5, (Y2 + 1) % 5
        passX1, passX2 = X1, X2
    else:
        passX1, passY1 = X2, Y1
        passX2, passY2 = X1, Y2

    # 4. Get expected images from transformed coordinates
    expected_images = {
        shuffled_images[passX1 * 5 + passY1],
        shuffled_images[passX2 * 5 + passY2]
    }

    # 5. Allow authentication if at least ONE selected image matches
    if any(img in expected_images for img in selected_images):
        return True, 0  # Reset trial counter on success
    else:
        max_trial_counter += 1
        if max_trial_counter >= 3:
            block_user(user_id)  # Implement user blocking if needed
        return False, min(max_trial_counter, 3)


@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    # Fetch the first user's details for demonstration
    user = User.query.first()
    if not user:
        return "No users found in the database!"
    
    # Pass user details to the template
    user_details = {
        "email": user.email,
        
    }
    return render_template('welcome.html', user=user_details)

@app.route('/logout')
def logout():
    # Handle logout logic here (e.g., clear session)
    return "Logged out successfully!"


@app.route('/users')
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/usability_stats')
def usability_stats():
    total_logins = EvaluationMatrix.query.count()
    avg_login_time = db.session.query(db.func.avg(EvaluationMatrix.login_time)).scalar()
    success_rate = db.session.query(db.func.count(EvaluationMatrix.id)).filter(EvaluationMatrix.total_success == True).scalar()
    failed_logins = db.session.query(db.func.sum(EvaluationMatrix.failed_attempts)).scalar()
    reset_requests = db.session.query(db.func.sum(EvaluationMatrix.reset_requests)).scalar()

    stats = {
        "Total Logins": total_logins,
        "Average Login Time (seconds)": avg_login_time if avg_login_time else 0,
        "Success Rate (%)": (success_rate / total_logins * 100) if total_logins else 0,
        "Failed Logins": failed_logins if failed_logins else 0,
        "Reset Requests": reset_requests if reset_requests else 0
    }
    return jsonify(stats)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
       
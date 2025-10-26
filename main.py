                ######----------------------------------------------------------------------------------------------######
                ######--------------------------------------Craig Ratchford-----------------------------------------######
                ######-----------------------------------------SWA Project------------------------------------------######
                #####------------------------------------Personnel Manegmant sysytem--------------------------------######
                ######----------------------------------------------------------------------------------------------######
##Imports
from datetime import timedelta
from _sqlite3 import Error
from flask import Flask, render_template, request, url_for, flash, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time,db_Setup,os,secrets,requests
from flask_wtf.csrf import CSRFProtect, validate_csrf

# Databases
user_DB = "Users.db"
equip_DB = "Equipment.db"
task_DB = "Tasks.db"
login_records = "History.db"

# Initialize Flask app
app = Flask(__name__)
app.config['ENV'] = "Development"
app.config['DEBUG'] = True
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))# Set the secret key for session management
csrf = CSRFProtect(app)  # Enable CSRF protection to prevent Cross-Site Request Forgery attacks

app.config['SESSION_COOKIE_SECURE'] = True  # Ensures the cookie is sent only over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript from accessing cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Restricts cross-site cookies

limiter = Limiter(get_remote_address,app=app,storage_uri="memory://")# Configure Flask-Limiter
app.permanent_session_lifetime = timedelta(seconds=120)  # Session expires after 120 seconds
SESSION_TIMEOUT = 120  # 120 seconds


# This would never be hard coded here, set in an .env file or set in environment variables
SECRET_KEY = '6LcooP0qAAAAABeFsSy5JwP56mrOoFYMc8lYB573'  #backend "secret/private key"for captcha

@app.before_request
def check_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)  # Generate a random CSRF token
        csrf_token = request.form.get('csrf_token')
        #print("CSRF Token in session:", session.get('_csrf_token'))  # Debugging

# Make CSRF token available in Jinja templates
app.jinja_env.globals['csrf_token'] = lambda: session.get('_csrf_token')

# This prevents redirect loops, check if the user is already on the login page
def is_login_page():
    return request.endpoint == 'login'


@app.before_request
def check_session_timeout():
    # Skip session expiry check if the user is on the login page
    if is_login_page():
        return

    # Check if session has expired
    if 'last_activity' in session:
        now = time.time()
        last_activity = session['last_activity']
        if now - last_activity > SESSION_TIMEOUT:
            flash("Session has expired. Please log in again.", "error")
            session.clear()  # Clear the session
            # Only redirect if we are not already on the login page
            if not is_login_page():
                return redirect(url_for('login'))  # Redirect to login page

    session['last_activity'] = time.time()  # Update last activity time

#login attempt limiter
@app.errorhandler(429)
def ratelimit_error(e):
    # Flash a message without redirecting if we are on the login page
    if is_login_page():
        flash("Too many login attempts. Please wait a minute before trying again.", "error")
        return render_template("login.html")  # Simply stay on the login page and show the message

    # If not on login page, still redirect to login (although this will rarely be hit due to earlier checks)
    flash("Too many login attempts. Please wait a minute before trying again.", "error")
    return redirect(url_for('login'))  # Redirect to login page

# Route for the home page, redirecting to login
@app.route('/')
def home():
    print("Home route - Redirecting to login") #debugging purposes
    return redirect(url_for('login'))  # Redirect to login

# Route for login page
@app.route('/login')
@limiter.limit("2 per minute")  # Limits login attempts
def login():
    print("Login route - Rendering login page") #debugging purposes
    return render_template("login.html")

# Route to handle login action
@app.route('/userinput', methods=['POST'])
def loginAction():

    recaptcha_response = request.form.get('g-recaptcha-response')  # Retrieve the reCAPTCHA response from the submitted form.

    if not recaptcha_response:
        flash("You must confirm you are not a robot", "error") # alert user if capcha is not conducted
        return redirect(url_for('login'))# Prevents access without completing CAPTCHA verification.

        # return "reCAPTCHA verification failed. Please try again.", 400
        # (Optional) Instead of redirecting, an error message could be returned with a 400 Bad Request response.

    # Verify reCAPTCHA response with Google
    verify_url = "https://www.google.com/recaptcha/api/siteverify"# Google’s reCAPTCHA verification endpoint.

    data = {
        'secret': SECRET_KEY,  # The secret key for verifying reCAPTCHA (obtained from Google).
        'response': recaptcha_response  # The user's reCAPTCHA response.
    }

    # Send a POST request to Google's reCAPTCHA verification API with the secret key and user response.
    response = requests.post(verify_url, data=data)


    result = response.json()# Convert the API response to a JSON object for easier processing.

    if result.get('success'): # if succes allow user to proceed with login in

        armyNo = request.form.get("armyno")
        password = request.form.get("password")

        print(f"Login action - ArmyNo: {armyNo}, Password: {password}")  #debugging purposes

        connection = None
        try:
            connection = db_Setup.create_connection(user_DB) # confirming connection
            if connection:
                pw = db_Setup.check_password(user_DB, armyNo, password) # valid connection, compare pw with stored pw

                if pw: # if pw is correct
                    session.clear()  # Clear old session to prevent session fixation
                    session['armyNo'] = armyNo # Store armyNo in the session
                    user_role = db_Setup.check_role(user_DB, armyNo) #ensuring valid role
                    session['role'] = user_role  # Store role in the session
                    session['session_token'] = secrets.token_hex(32) # Generate a new session token for security

                    session['last_activity'] = time.time()# Set session's last activity time to now

                    db_Setup.log_user_login(login_records,armyNo,user_role)

                    if user_role == 'Admin': # RBAC notifying if user is admin
                        flash("Login successful! Welcome User: 12345<br><br>This account is an administrator account", "success")

                    else:
                        flash(f"Login successful! Welcome User: {armyNo}", "success")

                    print(f"Login success for ArmyNo: {armyNo}")#debugging purposes

                    return redirect(url_for('homepage'))  # Redirect to homepage
                else:
                    print("Invalid credentials")#debugging purposes
                    flash("Invalid credentials. Please try again.", "error")

                    return redirect(url_for('login'))

        except Exception as e:
            print(f"An error occurred: {e}")#debugging purposes
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('login'))
        finally:
            if connection:
                connection.close()  # Ensure the connection is always closed
    else:
        flash("You must confrim you are not a robot", "error")
        return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    print("Forgot password route was accessed!")  # Debugging print
    if request.method == 'POST':
        print("POST request received")
        army_no = request.form.get('armyno')
        print(f"Received Army No: {army_no}")

        flash("If the Army Number exists, instructions have been sent to reset the password.", "info")
        return redirect(url_for('login'))

    return render_template('resetPW.html')


# Route for the homepage
@app.route('/homepage')
def homepage():
    armyNo = session.get('armyNo')  # Get armyNo from session

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session

    print(f"Homepage route - Logged in as ArmyNo: {armyNo}")  #debugging purposes
    return render_template('homepage.html', armyNo=armyNo)

# Route for homepage action buttons (view profile, assignment, etc.)
@app.route('/homepageAction', methods=['POST'])
def homepage_action():
    action = request.form.get('action')
    armyNo = session.get('armyNo')  # Get armyNo from session

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session

    print(f"Homepage action - Action: {action}, ArmyNo: {armyNo}")  #debugging purposes

    if action == 'view_profile':
        return redirect(url_for('profile'))  # Redirect to profile page
    elif action == 'assignment':
        return redirect(url_for('assignment'))  # Redirect to assignment page
    elif action == 'equipment':
        return redirect(url_for('equipment'))  # Redirect to equipment page
    elif action == 'history':
        return redirect(url_for('history'))  # Redirect to history page


    return redirect(url_for('homepage'))  # Default redirect if action is unknown

@app.route('/logout', methods=['POST'], endpoint='logout_route')
def logout():
    session.clear()# Clear the session
    flash("You have logged out successfully.", "info") # Flash a message to notify the user
    return redirect(url_for('login'))# Redirect to the login page


@app.route('/profile', methods=['GET', 'POST'])
def profile():

    armyNo = session.get('armyNo')  # Get armyNo from session

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session

    userInfo = db_Setup.get_user_info('Users.db', armyNo)# Get user info from the database

    if request.method == 'POST':
        if request.form.get('action') == 'delete_user':
            db_Setup.delete_user(user_DB,request.form.get('armyN'))#call delete user function and send armyNo as a parameter
        else:
            # Get updated data from the form
            rank = request.form.get('rank')
            surname = request.form.get('surname')
            role = request.form.get('role')
            contact = request.form.get('contact')
            bio = request.form.get('bio')

            # Update user info in the database
            db_Setup.update_user_info('Users.db', armyNo, rank, surname, role, contact, bio)
            flash("User information updated successfully.", "success")
            return redirect(url_for('profile'))  # Redirect to the profile page to see the updated info

    return render_template('profile.html', userInfo=userInfo)


@app.route('/view_users', methods =['GET'])
def view_users():
    users =db_Setup.view_stock(user_DB,'USERS')
    return render_template('viewusers.html', users=users)

# Route for assignment page
@app.route('/assignment')
def assignment():
    armyNo = session.get('armyNo')  # Get armyNo from session

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session

    print(f"Assignment route - ArmyNo: {armyNo}")  # Debugging
    return render_template('assignment.html', armyNo=armyNo)

# Route to handle task creation
@app.route('/create_task', methods=['POST'])
def create_task():
    #retrieving data from the form
    number = request.form.get('tasknum')
    description = request.form['description']
    equipment = request.form['equipment']
    bodys = request.form['bodys']
    creater = request.form['creater']

    db_Setup.insertask(task_DB,number,description,equipment,bodys,creater)#calling inserttask function passing data as parameters

    return render_template('assignment.html')


@app.route('/view_tasks',methods=['GET'])
def view_tasks():
    tasks = db_Setup.view_stock(task_DB,'TASKS')
    return render_template('viewtasks.html',tasks=tasks)

# Route for equipment page
@app.route('/equipment')
def equipment():
    armyNo = session.get('armyNo')  # Get armyNo from session
    print(f"Equipment route - ArmyNo: {armyNo}")  # Debugging
    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session


    return render_template('equipment.html', armyNo=armyNo)

# Route for equipment page
@app.route('/history',methods=['GET'])
def history():
    history = db_Setup.view_history(login_records)
    print(f"history route -")  # Debugging
    #print(history)
    return render_template('loginHistory.html', history=history)


@app.route('/EquipmentAction', methods=['POST'])
def EquipmentAction():

    action = request.form.get('action')
    print(f"route for equipment action with action {action}")# Debugging
    if action == 'commit':
        #retrieve data from form
        sn = request.form.get('serial_number')
        stockName = request.form.get('stock_name')
        stockQuantity = request.form.get('quantity')
        reason = request.form.get('reason')

        # Create a new order item
        order= {
            'sn': sn,
            'stockName': stockName,
            'stockQuantity': stockQuantity,
            'reason': reason,

        }
        # Add new order item to session if it exists, otherwise create an empty list
        if 'order' in session:
            session['order'].append(order)

        else:
            session['order'] = [order]

        return redirect(url_for('equipment'))

    elif action == 'view_order':

        if not 'order':
            flash("No items in your order.", "warning")
            return redirect(url_for('equipment'))


        sn = request.form.get('serial_number')
        stockName = request.form.get('stock_name')
        stockQuantity = request.form.get('quantity')
        reason = request.form.get('reason')

        order = {
            'sn': sn,
            'stockName': stockName,
            'stockQuantity': stockQuantity,
            'reason': reason,
        }
        if 'order' in session:
            session['order'].append(order)
        else:
            session['order'] = [order]

        # Once the order is complete, process it and clear the session
        if 'order' in session:
            order1 = session.get('order', None)  # Get the order from session, default to None if not found
            # Here you can process the order, e.g., save it to the database
            print(order1)
            #session.pop('order', None)  # Clear the order session after placing the order
            return render_template('order.html', order=order1)

    elif action == 'view_stock':
        equip = db_Setup.view_stock(equip_DB,'EQUIPMENT')
        return render_template('viewStock.html', equipment_data=equip)

    elif action == 'update_stock':
        return redirect(url_for('/orderAction'))

    elif action == 'delete_stock':
        return redirect(url_for('/deleteStockAction'))

    else:
        flash("Invalid action.", "error")
        return redirect(url_for('equipment'))  # Return to the equipment page if action is invalid

@app.route('/orderAction',methods=['POST'])
def orderAction():
    action = request.form.get('action')

    if action == 'place_order':

        print("order placed",action)# Debugging

        placed_order = session.get('order', [])  # Get the order list, default to empty list

        if placed_order:
            for item in placed_order:
                sn = item['sn']
                stockName = item['stockName']
                stockQuantity = item['stockQuantity']
                reason = item['reason']

                db_Setup.stock_order(equip_DB,sn,stockQuantity,stockName)
    else:
        print("error in placing order contact administrator")# Debugging

    return redirect(url_for('equipment'))  # Return to the equipment page if action is invalid


@app.route('/stock')
def stock():
    print("stock route")# Debugging
    return render_template('order.html')

@app.route('/stockAction',methods=['POST'])
def stockAction():
    armyNo = session.get('armyNo')  # Get armyNo from session
    print("action in stock is", request.form.get('action'))# Debugging
    if request.method == 'POST':
        #retrieving dta from form
        sn = request.form.get('serialNo')
        item = request.form.get('item')
        serv = request.form.get('serviceability')
        total = request.form.get('totalQuantity')
        avail = request.form.get('availability')
        comm = request.form.get('comment')

        db_Setup.insert_stock(equip_DB,sn,item,serv,total,avail,comm)#calling funtion to insert new stock

        flash("stock entered", "error")
        return redirect(url_for('equipment'))

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session


@app.route('/updateStockAction', methods=['POST'])
def updateStockAction():
    sn = request.form.get('serialNum')
    stockName = request.form.get('stock')
    serviceability = request.form.get('service')
    noOfUnits = request.form.get('totalQuantity')
    comment = request.form.get('comment')
    #print(f'update stock route sn is {sn} name: {stockName} service: {serviceability} numebr: {noOfUnits} comment: {comment}')# Debugging

    if db_Setup.update_equipment(equip_DB,sn,stockName,serviceability,noOfUnits,comment):
        flash(f"update made to {stockName} was succesful", "success")
    return redirect(url_for('equipment'))


@app.route('/deleteStockAction', methods=['POST'])
def deleteStockAction():
    print("delte stock route")# Debugging
    sn = request.form.get('serialN')
    connection = None
    try:
        connection = db_Setup.create_connection(equip_DB)
        if connection:
            cursor = connection.cursor()

            # Delete the stock based on SerialNo
            cursor.execute("DELETE FROM EQUIPMENT WHERE SerialNo = ?", (sn,))
            connection.commit()

            if cursor.rowcount > 0:
                flash(f"Stock with S/N: {sn} deleted successfully!","success")
                print(f"Stock with S/N: {sn} deleted successfully!")# Debugging
            else:
                flash(f"No stock found with S/N {sn}.","error")
                print(f"No stock found with S/N {sn}.")# Debugging

        return redirect(url_for('equipment'))

    except Error as e:
        print(f"Error deleting stock: {e}")# Debugging
        return redirect(url_for('equipment'))  # Redirect even in case of an error

    finally:
        if connection:
            connection.close()

# Route for create user page
@app.route('/createUser', methods=['GET', 'POST'])
def create_user():
    armyNo = session.get('armyNo')  # Get armyNo from session

    if not armyNo:
        flash("You need to log in first.", "error")
        return redirect(url_for('login'))  # Redirect to login if no armyNo in session

    if request.method == 'POST':
        #retriveing data from form
        p = request.form.get('password')
        password = db_Setup.hash_password(p)
        armyNo = request.form.get('armyNo')  # Get armyNo from the form (hidden field)
        rank = request.form.get('rank')
        surname = request.form.get('surname')
        role = request.form.get('role')
        contact = request.form.get('contact')
        bio = request.form.get('bio')

        print(f"Creating new user - ArmyNo: {armyNo}, Rank: {rank}, Surname: {surname}, Role: {role}, Contact: {contact}, Bio: {bio}")  # Debugging

        if not db_Setup.create_new_user(user_DB, armyNo, password, rank, surname, role, contact, bio):
            # Redirect or render another page after the form submission
            flash(f"User {armyNo} created successfully ", "success")
            print(f"Create user page - ArmyNo: {armyNo}")  # Debugging
            return redirect(url_for('profile'))  # After creating the user, redirect to their profile
    flash(f"User {armyNo} created successfully ", "success")
    print(f"Create user page - ArmyNo: {armyNo}")  # Debugging
    return render_template('profile.html')  # This renders the form when the page is loaded via GET


@app.route('/change_password', methods=['POST'])
def change_password():
    armyNo = session.get('armyNo')  # Get armyNo from session
    print(f"change password route route - Logged in as ArmyNo: {armyNo}")  # Debugging
    if 'armyNo' not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for('login'))

    army_no = session['armyNo']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    print("current pw : " + current_password)# Debugging

    # Check if the current password matches the one in the database
    if not db_Setup.check_password(user_DB,armyNo,current_password):
        flash("Incorrect current password!", "error")
        return redirect(url_for('profile'))

    # Ensure new password and confirmation match
    if new_password != confirm_password:
        flash("New passwords do not match!", "error")
        return redirect(url_for('profile'))

    # Ensure password meets the criteria
    if len(new_password) < 10 or not any(c.isupper() for c in new_password) or not any(c.islower() for c in new_password):
        flash("New password must be at least 10 characters long and contain both uppercase & lowercase letters!", "error")
        return redirect(url_for('profile'))

    # Hash the new password and update in the database

    if db_Setup.update_user_password(user_DB,army_no, new_password):# Update password in DB
        flash("Password successfully changed!", "success")
        return redirect(url_for('profile'))
    else:
        flash("Password change error changed!", "error")
        return redirect(url_for('profile'))


# Main function to run the Flask app
if __name__ == '__main__':
    ##---------------------------------------------##
    ##--All functions used to set up at the start--##
    ##---------------------------------------------##

    # db_Setup.create_userdatabase(user_DB)
    #db_Setup.create_equipmentDataBase(equip_DB)
    #db_Setup.create_taskdatabase(task_DB)
    #db_Setup.insertdata(user_DB)
    #db_Setup.delete_user(user_DB,12345)
    # print(db_Setup.check_database_integrity(user_DB))
    #pw = db_Setup.hash_password('admin')
    #db_Setup.create_new_user(user_DB,12345,pw,'Cpl','Ratchford','Admin','123456789','First Admin')
    #db_Setup.create_access_record(login_records)
    app.run(debug=True, port=5005)

from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash
from opcua import Client, ua
import os
import json
import yaml
from flask_socketio import SocketIO
from opcua import Client
import threading
import time
import plotly
import json
import pyodbc
from werkzeug.utils import redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, ValidationError
import bcrypt
from datetime import datetime
from cryptography.fernet import Fernet


app = Flask(__name__)
app.secret_key = 'xyzsdfg'
socketio = SocketIO(app)

SECRET_KEY = Fernet.generate_key()  # Save this securely, use the same key across app runs
cipher = Fernet(SECRET_KEY)

# Database configuration
DB_SERVER = 'DESKTOP-BSC7DMC\SQLEXPRESS'
DB_DATABASE = 'tse_data'
DB_USER = 'sa'
DB_PASSWORD = 'tiger'

# Connection string
connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_DATABASE};UID={DB_USER};PWD={DB_PASSWORD}'

# Function to create a connection
def create_connection():
    while True:
        try:
            conn = pyodbc.connect(connection_string)
            return conn
        except pyodbc.Error as e:
            print(f"Error connecting to database: {e}")
        
        except Exception as e:
            print(f"Unexpected error during connection: {e}")
            return None  # Handle other exceptions as needed

# Connect to the database
def connect_to_db():
    conn_str = 'DRIVER={SQL Server};SERVER=' + DB_SERVER + ';DATABASE=' + DB_DATABASE + ';UID=' + DB_USER + ';PWD=' + DB_PASSWORD
    return pyodbc.connect(conn_str)

# Define allowed submodules per role
ROLE_SUBMODULES = {
    "Operator": ["Set Point"],
    "Manager": ["Set Point", "Digital Input", "Digital Output", "Analog Input", "Analog Output", 
                 "Preset Values", "Timer", "Controllers", "UPSS"],
    "Tse": ["Set Point", "Digital Input", "Digital Output", "Analog Input", "Analog Output", 
             "Preset Values", "Timer", "Controllers", "UPSS", "Pump Min Set"]
}

def validate_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    
    for table in ["Operator", "Manager", "Tse"]:
        cursor.execute(f"SELECT * FROM {table} WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and user[1] == username:  # Ensure username matches case-sensitively
            try:
                if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                    session['role'] = table  # Store the role in the session
                    session['username'] = username
                    return table  # Return the role as the table name
            except ValueError as e:
                print(f"Error validating password for user '{username}' in table '{table}': {e}")
                continue
    return None

# OPC UA server URL
OPC_UA_URL = "opc.tcp://192.168.0.18:4840"

# Create an OPC UA client instance
client = Client(OPC_UA_URL)

# Global variable to hold the latest values
latest_values = {}

# Load Node IDs from the YAML file
def load_node_ids():
    yaml_path = os.path.join(os.path.dirname(__file__), "nodeid.yaml")
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
        return data.get("node_ids", {})

def read_values_periodically():
    global latest_values
    while True:
        try:
            client.connect()  # Connect to the OPC UA server
            
            # Load Node IDs from YAML file
            node_ids = load_node_ids()
            
            for name, node_id in node_ids.items():
                try:
                    node = client.get_node(node_id)
                    latest_values[name] = node.get_value()  # Read the value
                except Exception as e:
                    print(f"Error reading node {name}: {e}")
            
            # Emit the latest values to all connected clients
            socketio.emit('update', latest_values)
            
            socketio.emit('gauge_update', {
                "Random": latest_values.get("Random", 0),
                "Counter": latest_values.get("Counter", 0),
                "Sawtooth": latest_values.get("Sawtooth", 0)
            })
            
            client.disconnect()  # Disconnect from the server
            time.sleep(1)  # Wait for 1 second before the next read
        except Exception as e:
            print(f"Error reading values: {str(e)}")
            time.sleep(1)  # Wait before retrying in case of error

@app.route('/write', methods=['POST'])
def write():
    data = request.get_json()  # Generic payload with setting names as keys
    try:
        client.connect()  # Connect to the OPC UA server
        node_ids = load_node_ids()  # Load all node IDs (mapping of setting names to node IDs)

        for setting, value in data.items():
            if setting in node_ids and value is not None:
                node = client.get_node(node_ids[setting])
                node_data_type = node.get_data_type_as_variant_type()  # Dynamically get the node's data type

                # Map the data type and convert value accordingly
                if node_data_type == ua.VariantType.Boolean:
                    dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
                elif node_data_type == ua.VariantType.Int32:
                    dv = ua.DataValue(ua.Variant(int(value), ua.VariantType.Int32))
                elif node_data_type == ua.VariantType.Float:
                    dv = ua.DataValue(ua.Variant(float(value), ua.VariantType.Float))
                else:
                    raise ValueError(f"Unsupported data type for {setting}: {node_data_type}")

                node.set_value(dv)  # Write the value to the OPC UA node

        client.disconnect()  # Disconnect from the server
        return jsonify({"success": True}), 200

    except Exception as e:
        print(f"Error writing settings: {e}")
        return jsonify({"success": False, "error": str(e)}), 500



# Load alarms and node mappings
with open("alarms.yaml") as f:
    alarms_data = yaml.safe_load(f)["alarms"]

active_alarms = []

@app.route("/alarms")
def get_alarms():
    # Generate mock active alarms for demonstration
    global active_alarms
    active_alarms = [
        {
            "alarm": alarms_data[node]["alarm"],
            "name": alarms_data[node]["name"],
            "message": alarms_data[node]["message"],
            "code": alarms_data[node]["code"],
            "severity": alarms_data[node]["severity"],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            # "status": "Active",
        }
        for node in alarms_data
        if node.endswith("TRIP")  # Simulating active alarms
    ]
    return jsonify(active_alarms)


@app.route('/alarmslist')
def alarmslist():
    departments = load_data()
    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]
    return render_template('iot/alarmslist.html', departments=departments,allowed_submodules=allowed_submodules)  # Render the HTML template



# @app.route('/')
# def home():
#     departments = load_data()
#     return render_template('iot/dashboard.html', departments=departments)  # Render the HTML template

# @app.route('/alarms')
# def alarms():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_setpoint.html', msg=msg)  # Render the HTML template

@app.route('/setpoint')
def setpoint():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_setpoint.html', msg=msg)  # Render the HTML template

@app.route('/di')
def di():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_di.html', msg=msg)  # Render the HTML template

@app.route('/do')
def do():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_do.html', msg=msg)  # Render the HTML template

@app.route('/ai')
def ai():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_ai.html', msg=msg)  # Render the HTML template

@app.route('/ao')
def ao():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_ao.html', msg=msg)  # Render the HTML template

@app.route('/pv')
def pv():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_pv.html', msg=msg)  # Render the HTML template

@app.route('/ti')
def ti():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_ti.html', msg=msg)  # Render the HTML template

@app.route('/co')
def co():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_co.html', msg=msg)  # Render the HTML template

@app.route('/up')
def up():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_up.html', msg=msg)  # Render the HTML template

@app.route('/pu')
def pu():
    msg = {"payload": latest_values}
    return render_template('Settings/spinning2_pu.html', msg=msg)  # Render the HTML template

@app.route('/')
def home():
    departments = load_data()
    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]
    return render_template('iot/dashboard.html', departments=departments,allowed_submodules=allowed_submodules)  # Render the HTML template

# @app.route('/dashboard')
# def dashboard():
#     if 'userloggedin' not in session:
#         return redirect(url_for('user_login'))
#     allowed_submodules = session.get('allowed_submodules', [])
#     return render_template('iot/dashboard.html', allowed_submodules=allowed_submodules)

@app.route('/dashboard')
def dashboard():
    # Remove duplicates while preserving order
    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]
    return render_template('iot/dashboard.html', allowed_submodules=allowed_submodules)

# Function to load the data from the YAML file
def load_data():
    yaml_path = os.path.join(os.path.dirname(__file__), "input.yaml")
    with open(yaml_path, "r") as f:
        return yaml.safe_load(f)



# Inject submodules and client name into templates for consistent access
@app.context_processor
def inject_context():
    data = load_data()
    allowed_submodules = session.get('allowed_submodules', [])
    
    # Only pass the dashboard_name if 'Dashboard' is present in the YAML file
    dashboard_name = data.get("Dashboard")  # This will be None if 'Dashboard' is not in the YAML
    
    return {
        'submodules': data["submodules"],
        'client_name': data.get("client_name", "Default Client Name"),  # Fallback to default
        'allowed_submodules': allowed_submodules,
        'dashboard_name': dashboard_name  # Pass None or actual value
    }


# @app.route('/<submodule>')
# def render_submodule(submodule):
#     # Load the submodule to template mapping
#     submodules = load_data()["submodules"]

#     # Find the template associated with the submodule
#     template_name = submodules.get(submodule)
#     if template_name:
#         template_path = os.path.join("templates", "iot", template_name)
#         if os.path.exists(template_path):
#             # Pass the latest values from the OPC UA server (or other data)
#             msg = {"payload": latest_values}  # Replace latest_values with your data
#             return render_template(f"iot/{template_name}", msg=msg, allowed_submodules=session.get('allowed_submodules', []))

#     return "Page not found", 404


@app.route('/<submodule>')
def render_submodule(submodule):
    # Load the submodule to template mapping
    submodules = load_data()["submodules"]

    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]

    session['allowed_submodules'] = allowed_submodules

    # Find the template associated with the submodule
    template_name = submodules.get(submodule)
    if template_name:
        template_path = os.path.join("templates", "iot", template_name)
        if os.path.exists(template_path):
            # Pass the latest values from the OPC UA server (or other data)
            msg = {"payload": latest_values}  # Replace latest_values with your data
            return render_template(f"iot/{template_name}", msg=msg, allowed_submodules=allowed_submodules)

    return "Page not found", 404

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_role = validate_user(username, password)
        if user_role:
            session['userloggedin'] = True
            session['username'] = username
            session['role'] = user_role
            session['allowed_submodules'] = ROLE_SUBMODULES[user_role]
            session['last_login'] = datetime.now().strftime('%d/%m/%Y %H:%M:%S')  # Store current timestamp
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials, please try again.", 'danger')
    return render_template('User management/userlogin.html')

@app.route('/index')
def index():
    msg = {'payload': 0}
    return render_template('iot/index.html', msg=msg)  # Render the HTML template

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Determine table based on the role
        table = None
        if role == 'Operator':
            table = 'Operator'
        elif role == 'Manager':
            table = 'Manager'
        elif role == 'Tse':
            table = 'Tse'

        if table:
            try:
                conn = create_connection()
                cursor = conn.cursor()
                # Encrypt the password before storing it
                encrypted_password = cipher.encrypt(password.encode('utf-8'))
                # cursor.execute(f"INSERT INTO {table} (username, password) VALUES (?, ?)", (username, hashed_password))
                cursor.execute(f"INSERT INTO {table} (username, password) VALUES (?, ?)", (username, encrypted_password))
                conn.commit()
                flash(f"User added successfully to {table}.", 'success')
            except Exception as e:
                flash(f"Error adding user: {e}", 'danger')
            finally:
                conn.close()

    return render_template('iot/add_user.html')


@app.route('/user_management')
def user_management():
    conn = create_connection()
    cursor = conn.cursor()
    
    users = []
    for table in ["Operator", "Manager", "Tse"]:
        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()
        for row in rows:
            try:
                decrypted_password = cipher.decrypt(row[2].encode('utf-8')).decode('utf-8')
            except Exception as e:
                decrypted_password = "Error decrypting"  # Handle decryption errors
                
            users.append({
                "username": row[1],
                "password": decrypted_password,  # Decrypted password
                "role": table[:-1]  # Remove the trailing "r" for display
            })
    conn.close()
    return render_template('iot/user_management.html', users=users)



@app.route('/edit_user', methods=['POST'])
def edit_user():
    username = request.form['username']
    new_password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
    new_role = request.form['role']
    
    conn = create_connection()
    cursor = conn.cursor()

    # Delete user from old table
    for table in ["Operator", "Manager", "Tse"]:
        cursor.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
        conn.commit()

    # Insert user into the new role table
    new_table = new_role + "r"
    cursor.execute(f"INSERT INTO {new_table} (username, password) VALUES (?, ?)", (username, new_password))
    conn.commit()
    conn.close()

    flash("User updated successfully.", "success")
    return redirect(url_for('user_management'))


@app.route('/delete_user', methods=['POST'])
def delete_user():
    username = request.form['username']
    conn = create_connection()
    cursor = conn.cursor()

    for table in ["Operator", "Manager", "Tse"]:
        cursor.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
        conn.commit()
    conn.close()

    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management'))


    
@app.route('/logout')
def logout():
    # Clear user session data
    session.pop('userloggedin', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('allowed_submodules', None)
    return redirect(url_for('home'))  # Redirect to login page after logout

if __name__ == '__main__':
    # Start the background thread to read values periodically
    thread = threading.Thread(target=read_values_periodically)
    thread.daemon = True  # Daemonize thread
    thread.start()
    app.run(host="127.0.0.1", port=7005)
    socketio.run(app, host='127.0.0.1', port=7005, debug=True)
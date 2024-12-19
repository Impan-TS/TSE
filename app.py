from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash, send_file
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
from threading import Thread
from flask_socketio import SocketIO, emit

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
OPC_UA_URL = "opc.tcp://127.0.0.1:4840"

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
                "Temperature": latest_values.get("Temperature", 0),
                "Humidity": latest_values.get("Humidity", 0)
            })
            
            client.disconnect()  # Disconnect from the server
            time.sleep(1)  # Wait for 1 second before the next read
        except Exception as e:
            print(f"Error reading values: {str(e)}")
            time.sleep(1)  # Wait before retrying in case of error


# Load alarms from YAML
def load_alarms():
    yaml_path = os.path.join(os.path.dirname(__file__), "alarms.yaml")
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
        return data.get("alarms", {})



# def read_values_periodically():
#     global latest_values
#     while True:
#         try:
#             client.connect()  # Connect to the OPC UA server
            
#             # Load Node IDs from YAML file
#             node_ids = load_node_ids()
            
#             for name, node_id in node_ids.items():
#                 try:
#                     node = client.get_node(node_id)
#                     latest_values[name] = node.get_value()  # Read the value
#                 except Exception as e:
#                     print(f"Error reading node {name}: {e}")
            
#             # Emit the latest values to all connected clients
#             socketio.emit('update', {
#                 'temperature': latest_values.get('Temperature', 0),
#                 'humidity': latest_values.get('Humidity', 0)
#             })
            
#             socketio.emit('gauge_update', {
#                 'temperature': latest_values.get('Temperature', 0),
#                 'humidity': latest_values.get('Humidity', 0)
#             })
            
#             client.disconnect()  # Disconnect from the server
#             time.sleep(1)  # Wait for 1 second before the next read
#         except Exception as e:
#             print(f"Error reading values: {str(e)}")
#             time.sleep(1)  # Wait before retrying in case of error



# @app.route('/write', methods=['POST'])
# def write():
#     data = request.get_json()
#     if not data:
#         return jsonify({"success": False, "error": "No data provided"}), 400

#     opcua_client = Client("opc.tcp://127.0.0.1:4840")  # Replace with your OPC UA server URL

#     try:
#         opcua_client.connect()  # Ensure connection is established

#         for nodeid, value in data.items():
#             node = opcua_client.get_node(nodeid)
#             node_data_type = node.get_data_type_as_variant_type()

#             if node_data_type == ua.VariantType.Boolean:
#                 dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
#             elif node_data_type == ua.VariantType.Int32:
#                 dv = ua.DataValue(ua.Variant(int(value), ua.VariantType.Int32))
#             elif node_data_type == ua.VariantType.Float:
#                 dv = ua.DataValue(ua.Variant(float(value), ua.VariantType.Float))
#             else:
#                 raise ValueError(f"Unsupported data type for node {nodeid}: {node_data_type}")

#             node.set_value(dv)

#         return jsonify({"success": True}), 200

#     except Exception as e:
#         print(f"Error writing settings: {e}")
#         return jsonify({"success": False, "error": str(e)}), 500

#     finally:
#         try:
#             opcua_client.disconnect()  # Disconnect after operation
#         except Exception as disconnect_error:
#             print(f"Error during client disconnect: {disconnect_error}")


# @app.route('/write', methods=['POST'])
# def write():
#     data = request.get_json()
#     if not data:
#         return jsonify({"success": False, "error": "No data provided"}), 400

#     node_ids = load_node_ids()  # Load Node IDs from the YAML file
#     opcua_client = Client(OPC_UA_URL)

#     try:
#         opcua_client.connect()  # Connect to OPC UA server

#         for parameter, value in data.items():
#             node_id = node_ids.get(parameter)
#             if not node_id:
#                 raise ValueError(f"Node ID for parameter '{parameter}' not found")

#             # Retrieve the node and determine its data type
#             node = opcua_client.get_node(node_id)
#             node_data_type = node.get_data_type_as_variant_type()

#             if node_data_type == ua.VariantType.Boolean:
#                 dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
#             else:
#                 raise ValueError(f"Unsupported data type for node {node_id}: {node_data_type}")

#             node.set_value(dv)  # Write the value to the node

#         return jsonify({"success": True}), 200

#     except Exception as e:
#         print(f"Error writing settings: {e}")
#         return jsonify({"success": False, "error": str(e)}), 500

#     finally:
#         try:
#             opcua_client.disconnect()  # Disconnect from OPC UA server
#         except Exception as disconnect_error:
#             print(f"Error during client disconnect: {disconnect_error}")


# @app.route('/write', methods=['POST'])
# def write():
#     data = request.get_json()
#     if not data:
#         return jsonify({"success": False, "error": "No data provided"}), 400

#     opcua_client = Client("opc.tcp://127.0.0.1:4840")  # Replace with your OPC UA server URL

#     try:
#         opcua_client.connect()  # Ensure connection is established

#         for nodeid, value in data.items():
#             node = opcua_client.get_node(nodeid)
#             node_data_type = node.get_data_type_as_variant_type()

#             if node_data_type == ua.VariantType.Boolean:
#                 dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
#             elif node_data_type == ua.VariantType.Int32:
#                 dv = ua.DataValue(ua.Variant(int(value), ua.VariantType.Int32))
#             elif node_data_type == ua.VariantType.Float:
#                 dv = ua.DataValue(ua.Variant(float(value), ua.VariantType.Float))
#             else:
#                 raise ValueError(f"Unsupported data type for node {nodeid}: {node_data_type}")

#             node.set_value(dv)

#         return jsonify({"success": True}), 200

#     except Exception as e:
#         print(f"Error writing settings: {e}")
#         return jsonify({"success": False, "error": str(e)}), 500

#     finally:
#         try:
#             opcua_client.disconnect()  # Disconnect after operation
#         except Exception as disconnect_error:
#             print(f"Error during client disconnect: {disconnect_error}")

@app.route('/write', methods=['POST'])
def write():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    print(f"Received data: {data}")  # Debugging step

    opcua_client = Client("opc.tcp://127.0.0.1:4840")  # Replace with your OPC UA server URL

    try:
        opcua_client.connect()  # Ensure connection is established

        for nodeid, value in data.items():
            node = opcua_client.get_node(nodeid)
            node_data_type = node.get_data_type_as_variant_type()

            # Handle different data types (Boolean, Int32, Float, etc.)
            if node_data_type == ua.VariantType.Boolean:
                dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
            elif node_data_type == ua.VariantType.Int32:
                dv = ua.DataValue(ua.Variant(int(value), ua.VariantType.Int32))
            elif node_data_type == ua.VariantType.Float:
                dv = ua.DataValue(ua.Variant(float(value), ua.VariantType.Float))
            else:
                raise ValueError(f"Unsupported data type for node {nodeid}: {node_data_type}")

            node.set_value(dv)

        return jsonify({"success": True}), 200

    except Exception as e:
        print(f"Error writing settings: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        try:
            opcua_client.disconnect()  # Disconnect after operation
        except Exception as disconnect_error:
            print(f"Error during client disconnect: {disconnect_error}")


@app.route('/writes', methods=['POST'])
def writes():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    opcua_client = Client("opc.tcp://127.0.0.1:4840")  # Replace with your OPC UA server URL

    try:
        opcua_client.connect()  # Ensure connection is established

        for nodeid, value in data.items():
            # Get the node ID from the YAML configuration
            if nodeid not in load_node_ids():
                return jsonify({"success": False, "error": f"Invalid node ID: {nodeid}"}), 400
            
            # Ensure correct parsing of node_id
            node = opcua_client.get_node(load_node_ids()[nodeid])  # Get the correct node based on YAML config

            node_data_type = node.get_data_type_as_variant_type()

            # Handle different data types (Boolean, Int32, Float, etc.)
            if node_data_type == ua.VariantType.Boolean:
                dv = ua.DataValue(ua.Variant(bool(value), ua.VariantType.Boolean))
            elif node_data_type == ua.VariantType.Int32:
                dv = ua.DataValue(ua.Variant(int(value), ua.VariantType.Int32))
            elif node_data_type == ua.VariantType.Float:
                dv = ua.DataValue(ua.Variant(float(value), ua.VariantType.Float))
            else:
                raise ValueError(f"Unsupported data type for node {nodeid}: {node_data_type}")

            node.set_value(dv)  # Write the value to the node

        return jsonify({"success": True}), 200

    except Exception as e:
        print(f"Error writing settings: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        try:
            opcua_client.disconnect()  # Disconnect after operation
        except Exception as disconnect_error:
            print(f"Error during client disconnect: {disconnect_error}")



template_mapping = {
    "Set Point": "Settings/spinning2_sp.html",
    "Digital Input": "Settings/spinning2_di.html",
    "Digital Output": "Settings/spinning2_do.html",
    "Analog Input": "Settings/spinning2_ai.html",
    "Analog Output": "Settings/spinning2_ao.html",
    "Preset Values": "Settings/spinning2_pv.html",
    "Timer": "Settings/spinning2_ti.html",
    "Controllers": "Settings/spinning2_co.html",
    "UPSS": "Settings/spinning2_up.html",
    "Pump Min Set": "Settings/spinning2_pm.html",
}

@app.route('/load_template/<submodule_option>')
def load_template(submodule_option):
    if submodule_option in template_mapping:
        template_path = template_mapping[submodule_option]
        # Include node IDs as part of the context
        return render_template(template_path, msg={"payload": latest_values, "node_ids": load_node_ids()})
    return "Template not found", 404


# @app.route('/load_template/<submodule_option>')
# def load_template(submodule_option):
#     # Ensure the submodule_option exists in the mapping
#     if submodule_option in template_mapping:
#         template_path = template_mapping[submodule_option]
#         return render_template(
#             template_path, 
#             msg={"payload": latest_values, "node_ids": load_node_ids()}
#         )
#     return "Template not found", 404



# # Load alarms and node mappings
# with open("alarms.yaml") as f:
#     alarms_data = yaml.safe_load(f)["alarms"]

# # Mock database to store active alarms and acknowledgment status
# active_alarms = []

# @app.route("/alarms")
# def get_alarms():
#     """Fetch active alarms."""
#     global active_alarms
#     # Simulate active alarms with acknowledgment status
#     active_alarms = [
#         {
#             "alarm": node,
#             "name": alarms_data[node]["name"],
#             "message": alarms_data[node]["message"],
#             "code": alarms_data[node]["code"],
#             "severity": alarms_data[node]["severity"],
#             "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             "acknowledged": alarms_data[node].get("acknowledged", False)
#         }
#         for node in alarms_data if node.endswith("TRIP")
#     ]
#     return jsonify(active_alarms)



@app.route("/acknowledge", methods=["POST"])
def acknowledge_alarm():
    """Acknowledge an alarm."""
    global alarms_data
    data = request.json
    alarm_id = data.get("alarm")

    if alarm_id in alarms_data:
        alarms_data[alarm_id]["acknowledged"] = True
        return jsonify({"success": True, "message": "Alarm acknowledged"})
    return jsonify({"success": False, "message": "Alarm not found"}), 404

@app.route('/write/<node_id>/<int:value>', methods=['POST'])
def write_value(node_id, value):
    try:
        node = client.get_node(node_id)
        node.set_value(value)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/alarmslist')
def alarmslist():
    return render_template('iot/alarmslist.html')  # Render the HTML template


@app.route('/')
def home():
    departmentss = load_data()
    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]
    return render_template('iot/dashboard.html', departmentss=departmentss,allowed_submodules=allowed_submodules)  # Render the HTML template

# @app.route('/trends')
# def trends():
#     # Remove duplicates while preserving order
#     seen = set()
#     allowed_submodules = [
#         submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
#         if not (submodule in seen or seen.add(submodule))
#     ]
#     # Load node_ids from the YAML file
#     with open('nodeid.yaml', 'r') as file:
#         node_ids = yaml.safe_load(file)
#     return render_template('iot/trends.html', node_ids=node_ids, allowed_submodules=allowed_submodules)

@app.route('/dashboard')
def dashboard():
    # Remove duplicates while preserving order
    seen = set()
    allowed_submodules = [
        submodule for modules in ROLE_SUBMODULES.values() for submodule in modules
        if not (submodule in seen or seen.add(submodule))
    ]
    # Load node_ids from the YAML file
    with open('nodeid.yaml', 'r') as file:
        node_ids = yaml.safe_load(file)
    return render_template('iot/dashboard.html', node_ids=node_ids, allowed_submodules=allowed_submodules)

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

# @app.route('/setpoint')
# def setpoint():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_setpoint.html', msg=msg)  # Render the HTML template

# @app.route('/di')
# def di():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_di.html', msg=msg)  # Render the HTML template

@app.route('/do')
def do():
    msg = {
        'payload': latest_values,
        'node_ids': load_node_ids()  # Include node_ids from the YAML file
    }
    return render_template('Settings/spinning2_do.html', msg=msg)  # Render the HTML template

# @app.route('/ai')
# def ai():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_ai.html', msg=msg)  # Render the HTML template

# @app.route('/ao')
# def ao():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_ao.html', msg=msg)  # Render the HTML template

# @app.route('/pv')
# def pv():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_pv.html', msg=msg)  # Render the HTML template

# @app.route('/ti')
# def ti():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_ti.html', msg=msg)  # Render the HTML template

# @app.route('/co')
# def co():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_co.html', msg=msg)  # Render the HTML template

# @app.route('/up')
# def up():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_up.html', msg=msg)  # Render the HTML template

# @app.route('/pu')
# def pu():
#     msg = {"payload": latest_values}
#     return render_template('Settings/spinning2_pu.html', msg=msg)  # Render the HTML template


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

# Render the Trends HTML template
@app.route('/trends')
def trends():
    msg = {'payload': 0}
    return render_template('iot/trends.html', msg=msg)

# configuring input.yaml
# Serve the HTML file
@app.route('/input')
def input_page():
    return render_template('iot/input.html')  # Ensure this file is in the 'templates' folder

# Endpoint to fetch the YAML file content
@app.route('/get-input', methods=['GET'])
def get_input():
    try:
        with open('input.yaml', 'r') as file:
            data = yaml.safe_load(file)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint to update the YAML file
@app.route('/update-input', methods=['POST'])
def update_input():
    try:
        # Receive updated YAML content as JSON
        data = request.json  
        
        # Verify that the data has the expected structure
        if not isinstance(data, dict):
            raise ValueError("Invalid data format, expected a dictionary.")

        # Write updated data to the YAML file
        with open('input.yaml', 'w') as file:
            yaml.safe_dump(data, file, default_flow_style=False)  # Ensures nice, readable formatting

        return jsonify({"message": "File updated successfully!"})

    except Exception as e:
        # Provide a more detailed error message in case of failure
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# Endpoint to add a submodule
@app.route('/add-submodule', methods=['POST'])
def add_submodule():
    try:
        # Get submodule name and file path from the request
        submodule_name = request.json.get('submodule_name')
        submodule_file = request.json.get('submodule_file')

        # Read the current YAML content
        with open('input.yaml', 'r') as file:
            data = yaml.safe_load(file)

        # Ensure 'submodules' key exists in the data
        if 'submodules' not in data:
            data['submodules'] = {}

        # Add the new submodule to the 'submodules' dictionary
        data['submodules'][submodule_name] = submodule_file

        # Write the updated data back to the YAML file
        with open('input.yaml', 'w') as file:
            yaml.safe_dump(data, file)

        return jsonify({"message": "Submodule added successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/remove-submodule', methods=['POST'])
def remove_submodule():
    try:
        submodule_name = request.json.get('submodule_name')
        with open('input.yaml', 'r') as file:
            data = yaml.safe_load(file)

        # Ensure 'submodules' key exists in the data
        if 'submodules' in data:
            # Remove the submodule by deleting the key from the dictionary
            if submodule_name in data['submodules']:
                del data['submodules'][submodule_name]

        # Write the updated data back to the YAML file
        with open('input.yaml', 'w') as file:
            yaml.safe_dump(data, file)

        return jsonify({"message": "Submodule removed successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Start the background thread to read values periodically
    thread = threading.Thread(target=read_values_periodically)
    thread.daemon = True  # Daemonize thread
    thread.start()
    app.run(host="127.0.0.1", port=7005)
    socketio.run(app, host='127.0.0.1', port=7005, debug=True)

import pyodbc
import bcrypt

# Database configuration
DB_SERVER = 'DESKTOP-BSC7DMC\SQLEXPRESS'
DB_DATABASE = 'tse_data'
DB_USER = 'sa'
DB_PASSWORD = 'tiger'

# Connection string
connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_DATABASE};UID={DB_USER};PWD={DB_PASSWORD}'

# SQL commands to create tables
create_operator_table_query = '''
CREATE TABLE Operator (
   id INT PRIMARY KEY IDENTITY(1,1),
   username VARCHAR(100) NOT NULL,
   password VARCHAR(100) NOT NULL
);

ALTER TABLE Operator ADD CONSTRAINT unique_operator_username UNIQUE (username);
'''

create_manager_table_query = '''
CREATE TABLE Manager (
   id INT PRIMARY KEY IDENTITY(1,1),
   username VARCHAR(100) NOT NULL,
   password VARCHAR(100) NOT NULL
);

ALTER TABLE Manager ADD CONSTRAINT unique_manager_username UNIQUE (username);
'''

create_tse_table_query = '''
CREATE TABLE Tse (
   id INT PRIMARY KEY IDENTITY(1,1),
   username VARCHAR(100) NOT NULL,
   password VARCHAR(100) NOT NULL
);

ALTER TABLE Tse ADD CONSTRAINT unique_tse_username UNIQUE (username);
'''

# Function to execute SQL queries
def execute_query(query, values=None):
    try:
        conn = pyodbc.connect(connection_string)
        cursor = conn.cursor()
        if values:
            cursor.execute(query, values)
        else:
            cursor.execute(query)
        conn.commit()
        print("Query executed successfully.")
    except Exception as e:
        print(f"Error executing query: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# Create tables
execute_query(create_operator_table_query)
execute_query(create_manager_table_query)
execute_query(create_tse_table_query)

# Insert data with hashed passwords
def insert_user(table, username, plain_password):
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
    insert_query = f"INSERT INTO {table} (username, password) VALUES (?, ?)"
    execute_query(insert_query, (username, hashed_password.decode('utf-8')))

# Insert sample users
insert_user('Operator', 'operator', 'operator@123')
insert_user('Manager', 'manager', 'manager@123')
insert_user('Tse', 'tse', 'tse@123')
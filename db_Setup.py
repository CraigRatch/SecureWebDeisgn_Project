import sqlite3
from datetime import datetime
from sqlite3 import Error

import bcrypt
from flask import flash


####-----------------------------####
####Password hashing using bcrypt####
####-----------------------------####

def check_database_integrity(database):
    # Connect to the SQLite database
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    # Execute the PRAGMA integrity check
    cursor.execute('PRAGMA integrity_check')

    # Fetch the result and check if it's 'ok'
    result = cursor.fetchone()
    conn.close()  # Close the connection after the check

    # Return the integrity status
    if result[0] != 'ok':
        return f"Database integrity check failed for {database}."
    else:
        return f"Database integrity is ok for {database}."

def hash_password(password):
    # Generate a random salt using bcrypt.gensalt()
    salt = bcrypt.gensalt()
    # Hash the password with the salt using bcrypt.hashpw()
    # The password is first encoded to bytes before hashing
    hash_pw = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Return the hashed password
    return hash_pw


def check_password(dataBase,armyNo, password):
    connection = None
    try:
        connection = create_connection(dataBase) #function to confirm connection to database
        if connection:
            cursor = connection.cursor()

            # Query to check if ArmyNum exists
            query = "SELECT * FROM USERS WHERE ArmyNum = ?"
            cursor.execute(query, (armyNo,))
            user = cursor.fetchone()

            if user:
                # Retrieve the stored hash (assumed to be the 2nd column in the result)
                stored_hash = user[1]  # Assuming password is stored in the second column (Password)
                # Check if the provided password matches the stored hash
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash): return True
                else: return False
            else: return False
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()


def update_user_password(db,armyNo,pw):
    connection = None
    try:
        connection = create_connection(db) #function to confirm connection to database
        if connection:
            cursor = connection.cursor()
            hashed_password = hash_password(pw)# hash the new password

            # Query to check if ArmyNum exists
            query = "SELECT * FROM USERS WHERE ArmyNum = ?"
            cursor.execute(query, (armyNo,))
            user = cursor.fetchone()

            if user:
                # Update the password in the database
                update_query = "UPDATE USERS SET Password = ? WHERE ArmyNum = ?"
                cursor.execute(update_query, (hashed_password, armyNo))
                connection.commit()  # Commit changes

                return True  # Successfully updated
            else:
                return False  # User not found
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()




def check_role(dataBase,armyNo):
    connection = None
    try:
        connection = create_connection(dataBase)
        if connection:
            cursor = connection.cursor()
            # Query to check if ArmyNum exists
            query = "SELECT * FROM USERS WHERE ArmyNum = ?"
            cursor.execute(query, (armyNo,))
            user = cursor.fetchone()
            if user:
                userRole = user[4]
                print("Users role is ",userRole)
                return userRole


    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

def create_connection(dataBase):
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(dataBase)
        return conn
    except Error as e:
        print(e)
    return conn

def delete_user(database, armyNo):
    """Delete a user from the USERS table by ArmyNum"""
    connection = None
    try:
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Delete the user based on the ArmyNum
            cursor.execute("DELETE FROM USERS WHERE ArmyNum = ?", (armyNo,))

            # Commit the changes
            connection.commit()

            if cursor.rowcount > 0:
                flash("User deleted succesfully","success")
                print(f"User with ArmyNum {armyNo} deleted successfully!")
            else:
                flash("User not found", "error")
                print(f"No user found with ArmyNum {armyNo}.")

    except Error as e:
        print(f"An error occurred while deleting the user: {e}")

    finally:
        if connection:
            connection.close()


def create_new_user(database, armyNo, password, rank, surname, role, contact, bio):
    """Create a new user in the USERS table"""
    connection = None
    try:
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Check if the user already exists using army number (Primary Key)
            cursor.execute('''SELECT COUNT(*) FROM USERS WHERE ArmyNum = ?''', (armyNo,))
            result = cursor.fetchone()

            # If the count is greater than 0, it means the equipment already exists
            if result[0] > 0:
                print(f"User with ArmyNo: {armyNo} already exists in the database.")
                return False  # Return False if the stock exists

            # Insert new user data into the USERS table
            cursor.execute("""
                INSERT INTO USERS (ArmyNum, Password, Rank, Surname, Role, Contact, BIO)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (armyNo, password, rank, surname, role, contact, bio))

            # Commit the changes
            connection.commit()

            print(f"User with ArmyNum {armyNo} created successfully!")

    except Error as e:
        print(f"An error occurred while creating the user: {e}")

    finally:
        if connection:
            connection.close()

def create_equipmentDataBase(dataBase):
    connection = None
    try:
        connection = create_connection(dataBase)
        if connection:
            cursor = connection.cursor()

            # Drop the USER table if already exists.
            cursor.execute("DROP TABLE IF EXISTS EQUIPMENT")

            table = """ CREATE TABLE EQUIPMENT (
                                        SerialNo INTEGER PRIMARY KEY,  -- Primary Key for unique identification
                                        Item TEXT,                     -- Use TEXT for string data
                                        Serviceability TEXT,           -- Use TEXT for string data
                                        TotalQuantity INTEGER,        -- Use TEXT for string data
                                        Availability INTEGER,          -- Use INTEGER for phone numbers or similar
                                        Comments TEXT                  --Use text for comments
                                    ); """

            cursor.execute(table)

    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

def create_access_record(db):
    connection = None
    try:
        connection = sqlite3.connect(db)  # Replace with your actual database file
        cursor = connection.cursor()

        cursor.execute('''CREATE TABLE HISTORY (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            armyNo TEXT NOT NULL,
                            role TEXT NOT NULL,
                            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')

        connection.commit()
        print("Table 'History' created successfully")
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")
    finally:
        if connection:
            connection.close()

def log_user_login(db,armyNo, role):
    connection = None
    try:
        connection = create_connection(db)  # Connect to database
        cursor = connection.cursor()

        # Insert login record
        cursor.execute("INSERT INTO HISTORY (armyNo, role, login_time) VALUES (?, ?, ?)",
                       (armyNo, role, datetime.now()))

        connection.commit()  # Save changes
    except Exception as e:
        print(f"Error logging user login: {e}")  # Debugging
    finally:
        if connection:
            connection.close()  # Close connection


def create_equipmentDataBase(dataBase):
    connection = None
    try:
        connection = create_connection(dataBase)
        if connection:
            cursor = connection.cursor()

            # Drop the USER table if already exists.
            cursor.execute("DROP TABLE IF EXISTS EQUIPMENT")

            table = """ CREATE TABLE EQUIPMENT (
                                        SerialNo INTEGER PRIMARY KEY,  -- Primary Key for unique identification
                                        Item TEXT,                     -- Use TEXT for string data
                                        Serviceability TEXT,           -- Use TEXT for string data
                                        TotalQuantity INTEGER,        -- Use TEXT for string data
                                        Availability INTEGER,          -- Use INTEGER for phone numbers or similar
                                        Comments TEXT                  --Use text for comments
                                    ); """

            cursor.execute(table)

    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

def create_taskdatabase(dataBase):
    """ create a database connection to a SQLite database """
    connection = None
    try:
        connection =  create_connection(dataBase)
        if connection:
            cursor = connection.cursor()

            # Drop the USER table if already exists.
            cursor.execute("DROP TABLE IF EXISTS TASKS")

        table = """ CREATE TABLE TASKS (
                            Task No INTEGER PRIMARY KEY,  -- Primary Key for unique identification
                            Description TEXT NOT NULL,
                            Equipment TEXT,                    -- Use TEXT for string data
                            Bodys INTEGER,                 -- Use TEXT for string data
                            Creater TEXT                      -- Use TEXT for long descriptions
                        ); """

        cursor.execute(table)
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()


def create_userdatabase(dataBase):
    """ create a database connection to a SQLite database """
    connection = None
    try:
        connection =  create_connection(dataBase)
        if connection:
            cursor = connection.cursor()

            # Drop the USER table if already exists.
            cursor.execute("DROP TABLE IF EXISTS USERS")

        table = """ CREATE TABLE USERS (
                            ArmyNum INTEGER PRIMARY KEY,  -- Primary Key for unique identification
                            Password TEXT NOT NULL,
                            Rank TEXT,                    -- Use TEXT for string data
                            Surname TEXT,                 -- Use TEXT for string data
                            Role TEXT,                    -- Use TEXT for string data
                            Contact INTEGER,              -- Use INTEGER for phone numbers or similar
                            BIO TEXT                      -- Use TEXT for long descriptions
                        ); """

        cursor.execute(table)
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

def stock_order(database,sn,quantity,name):
    connection = None

    try:
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Fetch current stock details
            cursor.execute("SELECT * FROM EQUIPMENT WHERE SerialNo = ?", (sn,))
            stock_info = cursor.fetchone()

            if stock_info:
                serviceability = stock_info[2]
                availability = stock_info[4]
                total_quantity = stock_info[3]

                if serviceability.lower() == 'serviceable':  # Handle case sensitivity
                    if availability >= int(quantity):  # Ensure quantity is an integer
                        new_availability = availability - int(quantity)
                        new_total_quantity = total_quantity - int(quantity)  # Subtract from TotalQuantity too

                        # Update both Availability and TotalQuantity in the database
                        cursor.execute(
                            "UPDATE EQUIPMENT SET Availability = ?, TotalQuantity = ? WHERE SerialNo = ?",
                            (new_availability, new_total_quantity, sn)
                        )

                        connection.commit()  # Save changes to the database
                        print(f"New availability for {sn}: {new_availability}")
                    else:
                        flash(f"Not enough stock available for {sn},{name}. availability is {availability} Please try again", "error")
                        print("Not enough stock available")
                else:
                    flash(f"stock: ,{name}. has no units serviceable","error")
                    print("Item is not serviceable")
            else:
                flash(f"stock cannt be found or does not exist","error")
                print("No stock found for the given serial number")

    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()


def get_user_info(database, armyNum):
    """Fetch user information based on ArmyNum."""
    connection = None
    try:
        # Connect to the database
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Query to fetch user information based on ArmyNum
            cursor.execute("SELECT * FROM USERS WHERE ArmyNum = ?", (armyNum,))

            # Fetch the first row of data (user info)
            user_info = cursor.fetchone()

            # If a user with the given ArmyNum is found, return their information
            if user_info:
                return {
                    'ArmyNum': user_info[0],    # ArmyNum (Primary Key)
                    'Password': user_info[1],   # Password
                    'Rank': user_info[2],       # Rank
                    'Surname': user_info[3],    # Surname
                    'Role': user_info[4],       # Role
                    'Contact': user_info[5],    # Contact (phone number)
                    'BIO': user_info[6]         # BIO
                }
            else:
                return None  # If no user is found with that ArmyNum
    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection:
            connection.close()



def insertask(database,number,description,equipment,bodys,creater):
    connection = None
    try:
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Insert the new task into the TASKS table
            cursor.execute("INSERT INTO TASKS (Task, Description, Equipment, Bodys, Creater) VALUES (?, ?, ?, ?, ?)",
                            (number, description, equipment, bodys, creater))
            connection.commit()

            flash("Task created successfully!", "success")

    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

print("Data inserted successfully!")

##----used to add first user who is admin to database--##
##-----------------------------------------------------##
def insertdata(dataBase):
    connection = None
    try:
        connection = create_connection(dataBase)

        cursor = connection.cursor()

        # Sample values to insert
        army_num = 12345
        Password = hash_password('admin')
        rank = 'Cpl'
        surname = 'Ratchford'
        role = 'Admin'
        contact = 1234567890
        bio = 'First admin in data base'

        # SQL Insert Query
        cursor.execute('''INSERT INTO USERS (ArmyNum,Password,Rank, Surname, Role, Contact, Bio) 
                    VALUES (?, ?, ?, ?, ?, ?,?)''',(army_num,Password,rank,surname,role,contact,bio))

        # Commit the transaction to save the changes
        connection.commit()
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()

    print("Data inserted successfully!")



def insert_stock(dataBase, sn, item, service, totalquan, avail, comment):
    connection = None
    try:
        connection = create_connection(dataBase)

        cursor = connection.cursor()

        # Check if the stock already exists using SerialNo (Primary Key)
        cursor.execute('''SELECT COUNT(*) FROM EQUIPMENT WHERE SerialNo = ?''', (sn,))
        result = cursor.fetchone()

        # If the count is greater than 0, it means the equipment already exists
        if result[0] > 0:
            print(f"Equipment with SerialNo {sn} already exists in the database.")
            return False  # Return False if the stock exists

        # SQL Insert Query
        cursor.execute('''INSERT INTO Equipment (SerialNo,Item,Serviceability, TotalQuantity, Availability,Comments) 
                        VALUES (?, ?, ?, ?, ?, ?)''', (sn,item,service,totalquan, avail, comment))

        # Commit the transaction to save the changes
        connection.commit()


    except Error as e:
        print(f"An error occurred while updating the equipment: {e}")

    finally:
        # Close the connection if it exists
        if connection:
            connection.close()

def update_equipment(database, sn, item, service, totalquan,comment):
    connection = None
    try:
        # Create a connection to the database
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()
            # Fetch current stock details
            cursor.execute("SELECT * FROM EQUIPMENT WHERE SerialNo = ?", (sn,))
            stock_info = cursor.fetchone()

            if stock_info:

                availability = int(stock_info[4]) + int(totalquan)
                total_quantity = int(stock_info[3]) + int(totalquan)



            # Update equipment data in the EQUIPMENT table
            cursor.execute("""
                UPDATE EQUIPMENT
                SET SerialNo = ?,Item = ?, Serviceability = ?, TotalQuantity = ?,Availability = ?,Comments = ?
                WHERE SerialNo = ?  -- assuming SerialNo is the unique identifier
            """, (sn, item, service, total_quantity,availability,comment,sn))  # Passing `sn` twice: once for the new values and once for the WHERE clause

            # Commit the changes
            connection.commit()

            print(f"Equipment with SerialNo {sn} updated successfully!")

            return True
        else:
            return False

    except Error as e:
        print(f"An error occurred while updating the equipment: {e}")

    finally:
        # Close the connection if it exists
        if connection:
            connection.close()



######--------Updating data for user database--------######
######---------------------------------------------------##
def update_user_info(database, armyNo, rank, surname, role, contact, bio):
    """Update user information in the USERS table"""
    connection = None
    try:
        connection = create_connection(database)
        if connection:
            cursor = connection.cursor()

            # Update user data in the USERS table
            cursor.execute("""
                UPDATE USERS
                SET Rank = ?, Surname = ?, Role = ?, Contact = ?, BIO = ?
                WHERE ArmyNum = ?
            """, (rank, surname, role, contact, bio, armyNo))

            # Commit the changes
            connection.commit()

            print(f"User with ArmyNum {armyNo} updated successfully!")

    except Error as e:
        print(f"An error occurred while updating the user: {e}")

    finally:
        if connection:
            connection.close()

## database and name of database passed as paramters
def view_stock(database,table):
    """Fetch data from any table in the specified database."""
    # Create a connection to the database
    connection = create_connection(database)

    if connection:

        try:
            cursor = connection.cursor()

            # Fetch all records from the specified table
            query = f"SELECT * FROM {table}"  # Dynamically select the table
            cursor.execute(query)
            data = cursor.fetchall()

            # Close the connection
            connection.close()

            return data  # Return the fetched data

        except sqlite3.Error as e:
            # Handle any potential errors
            print(f"Error during SQL operation: {e}")
        connection.close()

        return f"Error: Unable to fetch data from the {table} table."

def view_history(db):
    connection = None
    try:
        connection = sqlite3.connect(db)
        cursor = connection.cursor()

        cursor.execute("SELECT id, armyNo, role, login_time FROM HISTORY ORDER BY login_time DESC")
        records = cursor.fetchall()

        history_list = []
        for record in records:
            history_list.append({
                'id': record[0],
                'armyNo': record[1],
                'role': record[2],
                'login_time': record[3]
            })

        return history_list

    except sqlite3.Error as e:
        print(f"Error retrieving history: {e}")
        return []
    finally:
        if connection:
            connection.close()

from flask import Flask, request, make_response, redirect, jsonify
import threading
import base64

app = Flask(__name__)

# Dictionary to store sessions (session_id -> username)
sessions = {}
# Lock to make sure session increments are thread-safe
session_lock = threading.Lock()
# Start session counter
current_session_id = 1

# Simple login page with AJAX form
@app.route('/')
def login():
    # Check if user already has a valid session cookie
    session_id = request.cookies.get('session_id')

    # Validate the session ID by checking if it exists in our session dictionary
    if session_id in sessions:
        return redirect('/welcome')

    # If session_id is not valid, show the login form
    return '''
        <html>
            <head>
                <style>
                    body {
                        background-color: green;
                        color: yellow;
                        font-family: Arial, sans-serif;
                        text-align: center;
                        margin-top: 100px;
                    }
                    h2 {
                        font-size: 2.5em;
                    }
                    form {
                        display: inline-block;
                        background-color: #444;
                        padding: 20px;
                        border-radius: 10px;
                    }
                    input[type="text"], input[type="password"] {
                        font-size: 1.2em;
                        padding: 10px;
                        margin: 10px;
                        border-radius: 5px;
                    }
                    input[type="button"] {
                        font-size: 1.2em;
                        background-color: yellow;
                        color: green;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                    }
                    input[type="button"]:hover {
                        background-color: darkyellow;
                    }
                    #message {
                        margin-top: 20px;
                        color: red;
                    }
                </style>
                <script>
                    function login() {
                        var username = document.getElementById('username').value;
                        var password = document.getElementById('password').value;

                        var credentials = btoa(username + ':' + password); // Base64 encode the username:password

                        fetch('/login', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Basic ' + credentials
                            }
                        }).then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                window.location.href = '/welcome'; // Redirect on successful login
                            } else {
                                document.getElementById('message').innerHTML = 'Invalid credentials. Please try again.';
                            }
                        });
                    }
                </script>
            </head>
            <body>
                <h2>Encrypted Login</h2>
                <form id="loginForm">
                    <label for="username">Username: </label><br>
                    <input type="text" name="username" id="username"><br>
                    <label for="password">Password: </label><br>
                    <input type="password" name="password" id="password"><br>
                    <input type="button" value="Login" onclick="login()">
                </form>
                <div id="message"></div>
            </body>
        </html>
    '''

# Handle login and set cookies
@app.route('/login', methods=['POST'])
def login_action():
    global current_session_id

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return jsonify({'success': False})

    # Decode the Base64-encoded credentials
    auth_token = auth_header.split(' ')[1]
    decoded_credentials = base64.b64decode(auth_token).decode('utf-8')
    username, password = decoded_credentials.split(':')

    # You can add password validation logic here if needed
    if username == "" or password == "":
        return jsonify({'success': False})

    # Assign a unique session ID for each login in a thread-safe manner
    with session_lock:
        session_id = str(current_session_id)
        current_session_id += 1

    # Store the session (session_id -> username) in the dictionary
    sessions[session_id] = username

    # Create a response
    resp = make_response(jsonify({'success': True}))

    # Set the session_id cookie with Secure and HttpOnly flags
    resp.set_cookie(
        'session_id',
        session_id,
        max_age=3600,  # Set cookie to expire in 1 hour
        secure=True,  # Only send cookie over HTTPS
        httponly=True,  # Cookie cannot be accessed via JavaScript
        samesite='Lax'  # Helps prevent CSRF attacks
    )

    return resp

# Handle logout
@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')

    # Remove the session from the dictionary if it exists
    if session_id in sessions:
        del sessions[session_id]

    # Create a response
    resp = make_response(redirect('/'))

    # Clear the session_id cookie
    resp.set_cookie('session_id', '', expires=0, secure=True, httponly=True, samesite='Lax')

    return resp

# Welcome page after login
@app.route('/welcome')
def welcome():
    session_id = request.cookies.get('session_id')

    # Check if the session_id is valid
    if session_id in sessions:
        username = sessions[session_id]
        return f'''
        <html>
            <head>
                <style>
                    body {{
                        background-color: green;
                        color: yellow;
                        font-family: Arial, sans-serif;
                        text-align: center;
                        margin-top: 100px;
                    }}
                    h1 {{
                        font-size: 2.5em;
                    }}
                    .logout-button {{
                        font-size: 1.2em;
                        background-color: yellow;
                        color: green;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        margin-top: 20px;
                        display: inline-block;
                        text-decoration: none;
                    }}
                    .logout-button:hover {{
                        background-color: darkyellow;
                    }}
                </style>
            </head>
            <body>
                <h1>Welcome, {username}!</h1>
                <a href="/logout" class="logout-button">Logout</a>
            </body>
        </html>
        '''

    # If session validation fails, redirect to login page
    return redirect('/')

if __name__ == '__main__':
    # Run the app with SSL
    app.run(
        host='0.0.0.0',
        port=8443,
        ssl_context=('/home/juicetin/ssl/server.crt', '/home/juicetin/ssl/server.key')
    )

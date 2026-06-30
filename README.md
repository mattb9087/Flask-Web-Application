This project improves the original Lab 1 command line system by turning it into a Flask web application with SQLite. The Lab 1 versión used a CSV file and plaintext passwords, while this final version stores plaintext usernames, salted password hashes, access levels, failed login attempts, and account status in a SQLite database.

The program includes login, registration, password validation, a strong password generator, role-based intranet menu access, and protections against vulnerabilities such as SQL injection and XSS.

Login Lockout:
Each registered user gets three login attempts. After three failed attempts, the user's account is locked and cannot be used to log in.

Password Validation:
The registration form requires passwords to follow these rules:

Minimum length of 8 characters
Maximum length of 25 characters
At least one number
At least one lowercase letter
At least one uppercase letter
At least one special character

Strong Password Generator:
The registration page includes a strong password generator. The generated password automatically satisfies the length and complexity rules.


Files
app.py - Main Flask web application and routes
auth_utils.py - Password hashing, password validation, and password generator functions
database.py - SQLite database setup and database helper functions
requirements.txt - Required Python package list
templates/ - HTML templates for the web interface
static/style.css - CSS styling
intranet.db - SQLite database file created automatically when the app runs


Setup Instructions
Extract the submitted folder.
Open the folder in PyCharm or other IDE as a Project.
Install Flask with "pip install -r requirements.txt"
Run the application with "python app.py"
Open the URL that comes up in a browser.


Testing Instructions

Test Registration:
Go to /register and try a weak password such as abc. The application should reject it as it is shorter than 8 characters and does not satisfy the complexity rules.

Try a valid password such as Valid123! and the user should be created.

Test Password Generator
Go to /register and click Generate Strong Password. A valid password should be generated and placed into the password fields.

Test Login
Go to /login log in with one of the default users or a newly registered user.
A successful login redirects to the dashboard.

Test Lockout
Register a test user and try to log in with the wrong password three times.
The account should become locked after the third failed attempt.

Test SQL Injection Protection
Try logging in with a username such as:
' OR '1'='1
The login should fail because the application uses parameterized queries instead of building SQL with string concatenation.

Test XSS Protection
Register a username containing HTML/JavaScript characters, or try entering script-like text in form fields. The application should not execute it as code because Jinja escapes user output by default.

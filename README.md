# Flask User Authentication Example

This project demonstrates a basic user authentication system implemented using Flask, including signup, login, logout, forgot password, and reset password functionalities. It utilizes Flask-SQLAlchemy for database management, Flask-Mail for sending emails, Flask-Migrate for database migrations, and WTForms for form validation and security.

## Features

* **User Registration:** Allows users to create new accounts with username, email, and password.
* **Login/Logout:** Secure login and logout functionality with session management.
* **Password Hashing:**  Uses `pbkdf2:sha256` for secure password storage.
* **Forgot Password:**  Allows users to reset their password via email.
* **Password Reset:**  Users can reset their password using a secure token sent to their email.
* **Input Validation:**  Basic input validation using WTForms to prevent common vulnerabilities.
* **Flash Messages:**  Provides feedback to the user about the success or failure of operations.


## Installation

1. **Clone the repository**

    ```bash
    git clone https://github.com/VikumKarunathilake/Login-Authentication.git
    cd Login-Authentication
    ```
2. **Create a virtual environment (recommended)**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3. **Install the required packages**
    ```bash
    pip install -r requirements.txt
    ```
4. **Set up environment variables**
    ```py
    SECRET_KEY='your_secret_key'  # Generate a strong secret key
    MAIL_USERNAME='your_email@gmail.com'  # Your Gmail address
    MAIL_PASSWORD='your_email_password'  # Your email password (use app passwords for Gmail)
    ```
5. **Initialize the database**
    ```bash
    flask db init
    flask db migrate
    flask db upgrade
    ```
## Usage
1. **Run the application**
    ```bash
    flask run
    ```
2. **Access in your browser**
    - *Signup*: http://127.0.0.1:5000/signup 
    - *Login*: http://127.0.0.1:5000/login
    - *Forgot Password*: http://127.0.0.1:5000/forgot_password
## Security Considerations

- HTTPS: Always enforce HTTPS in a production environment.

- Strong Passwords: Enforce strong password complexity rules.

- Rate Limiting: Implement rate limiting on login attempts.

- Session Management: Use secure session management practices (e.g. server-side sessions).

- Input Sanitization: Sanitize all user inputs before displaying them on the HTML pages to prevent XSS vulnerabilities.

## Contributing
- Contributions are welcome! Please open an issue or submit a pull request.
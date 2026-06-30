"""Secure Flask intranet"""

import re
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth_utils import (
    generate_strong_password,
    hash_password,
    validate_password,
    verify_password,
)
from database import (
    DEFAULT_ACCESS_LEVEL,
    create_user,
    get_user,
    increment_failed_attempts,
    init_database,
    list_users,
    reset_failed_attempts,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "final_lab-123456789asdfgñlkjh"

MENU_OPTIONS = {
    "time_reporting": ("Time Reporting", {"admin", "accounting", "engineering", "employee"}),
    "accounting": ("Accounting", {"admin", "accounting"}),
    "settings": ("Settings", {"admin"}),
    "engineering": ("Engineering Documents", {"admin", "engineering"}),
}

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,25}$")


def login_required(view_function):
    """redirect anonymous users to the login page"""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)

    return wrapped_view


def sanitize_username(username: str) -> str:
    """normalize input for username"""
    return (username or "").strip()


@app.before_request
def setup_database_once() -> None:
    """initialize the database before the first request if needed."""
    if not getattr(app, "database_initialized", False):
        init_database()
        app.database_initialized = True


@app.route("/")
def index():
    """initiaal login menu"""
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """authenticate an existing user"""
    if request.method == "POST":
        username = sanitize_username(request.form.get("username"))
        password = request.form.get("password") or ""

        try:
            user = get_user(username)
            if user is None:
                flash("Invalid username or password.", "danger")
                return render_template("login.html", username=username)

            if int(user["locked"]):
                flash("This account is locked after three failed login attempts.", "danger")
                return render_template("login.html", username=username)

            if verify_password(user["password_hash"], password):
                reset_failed_attempts(username)
                session.clear()
                session["username"] = user["username"]
                session["access_level"] = user["access_level"]
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            attempts = increment_failed_attempts(username)
            if attempts >= 3:
                flash("Invalid password. Account is now locked.", "danger")
            else:
                remaining = 3 - attempts
                flash(f"Invalid username or password. {remaining} attempt(s) remaining.", "danger")
        except Exception:
            app.logger.exception("Unexpected login error")
            flash("An unexpected login error occurred. Please try again.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """register a new user with low privileges"""
    generated_password = request.args.get("generated", "")

    if request.method == "POST":
        username = sanitize_username(request.form.get("username"))
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        try:
            if not USERNAME_PATTERN.fullmatch(username):
                flash(
                    "Username must be 3-25 characters and may only contain "
                    "letters, numbers, and underscores.",
                    "danger",
                )
                return render_template("register.html", username=username)

            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("register.html", username=username)

            valid, message = validate_password(password)
            if not valid:
                flash(message, "danger")
                return render_template("register.html", username=username)

            created = create_user(
                username=username,
                password_hash=hash_password(password),
                access_level=DEFAULT_ACCESS_LEVEL,
            )
            if not created:
                flash("That username is already registered.", "danger")
                return render_template("register.html", username=username)

            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception:
            app.logger.exception("Unexpected registration error")
            flash("An unexpected registration error occurred. Please try again.", "danger")

    return render_template("register.html", generated_password=generated_password)


@app.route("/generate-password")
def generate_password_route():
    """generate a strong password and send it to the registration page"""
    generated_password = generate_strong_password()
    flash("A strong password was generated. You may copy it or use it directly.", "info")
    return redirect(url_for("register", generated=generated_password))


@app.route("/dashboard")
@login_required
def dashboard():
    """protected intranet dashboardp"""
    return render_template(
        "dashboard.html",
        username=session["username"],
        access_level=session["access_level"],
        menu_options=MENU_OPTIONS,
    )


@app.route("/area/<area_name>")
@login_required
def area(area_name: str):
    """display protected areas depending on access level"""
    option = MENU_OPTIONS.get(area_name)
    if option is None:
        flash("Invalid intranet area.", "danger")
        return redirect(url_for("dashboard"))

    title, allowed_roles = option
    access_level = session.get("access_level")
    if access_level not in allowed_roles:
        flash("You are not authorized to access that area.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("area.html", title=title)


@app.route("/users")
@login_required
def users():
    """admin only page showing safe user account status information"""
    if session.get("access_level") != "admin":
        flash("Only administrators can view user account status.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("users.html", users=list_users())


@app.route("/logout")
def logout():
    """log out the current user"""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_database()
    app.run(debug=True, port=8097)

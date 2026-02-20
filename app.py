from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)
app.secret_key = 'secret_key'


#Create User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(100))
    
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()
    
    
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect("/register")
        if password and len(password) < 6:
            flash("Password must be at least 6 characters long!", "danger")
            return redirect("/register")
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered!", "danger")
            return redirect("/register")
        
        try:
            new_user = User(name=name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect('/login')
        except Exception as e:
            db.session.rollback()
            flash("Registration failed. Please try again.", "danger")
            return redirect("/register")
    
    return render_template("register.html")

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash("Email and password are required!", "danger")
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid email or password!", "danger")
            return render_template('login.html')
        
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template("dashboard.html", user=user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/login') 

if __name__ == '__main__':
    app.run(debug=True)
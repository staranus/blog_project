from flask import Flask, request, render_template, redirect, url_for, session, abort
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
import hashlib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = '1234'
db = SQLAlchemy(app)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'saartaranus@gmail.com'
app.config['MAIL_PASSWORD'] = 'ccue mtep elmd tvxh'
app.config['MAIL_DEBUG'] = True
mail = Mail(app)


class Users(db.Model):  # extends db.Model to tell sqlalchemy that it's a table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # db.String(64) since you are storing the hexadecimal
    # representation of a SHA-256 hash, which is 64 characters long.


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.Text, nullable=False)
    title = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # When doing a query, display each row represented
    # by an object containing what's in the return statement
    def __repr__(self):
        return 'Post ' + str(self.id)


PER_PAGE = 5  # Number of posts per page

with app.app_context():
    db.create_all()
    # user_1 = Users(username="elad", password=hashlib.sha256("1234".encode()).hexdigest(), is_admin=True, email = "blah")
    # user_2 = Users(username="saar", password=hashlib.sha256("1234".encode()).hexdigest(), is_admin=False, email = "blah")
    # db.session.add(user_1, user_2)
    # db.session.commit()

    # query data from db
    # user = Users.query.filter_by(username="saar").first()
    # print(user)
    # print(user.username)
    # print(user.password)
    # print(user.id)


@app.route("/")
def index():
    if 'username' in session:
        print(f"User {session['username']} is already in session")
        return redirect(url_for('view_and_publish_posts'))

    else:
        print("User is not in session, redirecting to login")
        return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
def login():
    if 'username' in session:
        return redirect(url_for('view_and_publish_posts'))

    if request.method == "POST":
        username = request.form.get('username')
        password = hashlib.sha256(request.form.get('password').encode()).hexdigest()

        user = Users.query.filter_by(username=username).first()
        if user and user.password == password:
            session['logged_in'] = True
            session['username'] = username
            # session['email'] = request.form['email_address']
            return redirect(url_for('view_and_publish_posts'))
        return render_template('login.html', message="Wrong Login!")
    return render_template('login.html')


@app.route('/signup', methods=["GET", "POST"])
def user_sign_up():
    if 'username' in session:
        return redirect(url_for('view_and_publish_posts'))

    if request.method == "POST":
        username = request.form.get('username')

        user = Users.query.filter_by(username=username).first()
        if user:
            match_passwords = True
            return render_template('login.html',
                                   match_passwords=True, message='User already exists!')

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email_address = request.form.get('email_address')

        if password != confirm_password:
            match_passwords = True
            return render_template('sign-up.html',
                                   match_passwords=True, message=f"Passwords don't match!")

        password = hashlib.sha256(password.encode()).hexdigest()

        user = Users(username=username, password=password, is_admin=False, email=email_address)
        db.session.add(user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('view_and_publish_posts'))

    return render_template('signup.html', match_passwords=True)


@app.route('/logout')
def user_logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/posts', methods=['POST', 'GET'])
def view_and_publish_posts():
    if 'username' not in session:
        return redirect(url_for('login'))
    current_user = Users.query.filter_by(username=session['username']).first()

    if not current_user:
        print("User not found in DB")
        return redirect(url_for('login'))

    user_id = current_user.id

    if request.method == 'POST':
        db.session.add(Posts(
            title=request.form['title'],
            post=request.form['content'],
            user_id=user_id
        ))
        db.session.commit()
        # return redirect('/posts')
    posts = Posts.query.all()
    return render_template('index.html', posts=posts, current_user_id=user_id)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit_posts(id):
    post_object = Posts.query.filter_by(id=id).first()
    if post_object.user_id != Users.query.filter_by(username=session['username']).first().id:
        abort(403)  # Forbidden if the current user is not the author of the post
    # print(post_object.title)
    if request.method == 'POST':
        post_object.post = request.form['content']
        db.session.commit()
        return redirect('/posts')
    # todo- redo for previous code, instead of post_content (to consider)
    return render_template('edit.html', post=post_object, post_content=post_object.post)


@app.route('/posts/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    if post_to_delete.user_id != Users.query.filter_by(username=session['username']).first().id:
        abort(403)  # Forbidden if the current user is not the author of the post
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect('/posts')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # For simplicity, we assume the token is the user's ID
    user_id = int(token)
    user = Users.query.get(user_id)

    if not user:
        print(f"{user} not found")
        abort(404)  # User not found

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return render_template('reset-password.html', error='Passwords do not match')

        # Update the user's password
        user.password = hashlib.sha256(new_password.encode()).hexdigest()
        db.session.commit()

        return render_template('reset-password-success.html', email=user.email)

    return render_template('reset-password.html', token=token)


@app.route('/recover-password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form.get('user_email')
        user = Users.query.filter_by(email=email).first()

        if user:
            # Generate a temporary token (you might want to use a library for this)
            # For simplicity, we are using the user's ID as a token in this example
            print(user)
            token = str(user.id)

            # Send a password recovery email
            recover_url = url_for('reset_password', token=token, _external=False)
            print(recover_url)
            subject = 'Password Recovery'
            body = f'Click the following link to reset your password: {recover_url}'

            msg = Message(subject, recipients=email, body=body)
            mail.send(msg)

            return render_template('recover-password-success.html', email=email)
        else:
            return render_template('recover-password.html', error='Invalid email address')

    return render_template('recover-password.html')


if __name__ == '__main__':
    app.run(debug=True, port=8885)

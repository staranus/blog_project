import hashlib
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, session, abort, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = '1234'
db = SQLAlchemy(app)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
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
    nickname = db.Column(db.String(50), unique=True, nullable=False)
    # db.String(64) since you are storing the hexadecimal
    # representation of a SHA-256 hash, which is 64 characters long.


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.Text, nullable=False)
    title = db.Column(db.Text, nullable=False)
    time_published = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', backref=db.backref('posts', lazy=True))

    # When doing a query, display each row represented
    # by an object containing what's in the return statement
    def __repr__(self):
        return 'Post ' + str(self.id)


with app.app_context():
    db.create_all()
    # user_1 = Users(username="elad", nickname = "elad da king", password=hashlib.sha256("1234".encode()).hexdigest(), is_admin=True, email = "blah")
    # user_2 = Users(username="saar", nickname = "saar da king", password=hashlib.sha256("1234".encode()).hexdigest(), is_admin=False, email = "blah")
    # db.session.add(user_1, user_2)
    # db.session.commit()

    # query data from db
    user = Users.query.filter_by(username="saar").first()
    print(user)
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
            return redirect(url_for('view_and_publish_posts'))
        return render_template('login.html', message="Wrong login, please check your"
                                                     " user name and password")
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

        nickname = request.form.get('nickname')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email_address = request.form.get('email_address')

        if password != confirm_password:
            match_passwords = True
            return render_template('sign-up.html',
                                   match_passwords=True, message=f"Passwords don't match!")

        password = hashlib.sha256(password.encode()).hexdigest()

        user = Users(username=username, nickname=nickname, password=password, is_admin=False, email=email_address)
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
        flash('New post added successfully!', 'success')

    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of posts per page

    filter_username = request.args.get('filterUsername', '')
    is_admin = current_user.is_admin
    if filter_username:
        filter_user = Users.query.filter_by(nickname=filter_username).first()
        if filter_user:
            pagination = Posts.query.filter_by(user_id=filter_user.id).order_by(Posts.time_published.desc()).paginate(
                page=page, per_page=per_page, error_out=False)
        else:
            flash(f"No posts found for username '{filter_username}', please check again", 'info')
            pagination = None
    else:
        pagination = Posts.query.order_by(Posts.time_published.desc()).paginate(page=page, per_page=per_page,
                                                                                error_out=True)

    posts = pagination.items if pagination else []
    print(posts)
    time_now = datetime.utcnow()

    for post in posts:
        time_published_str = post.time_published.strftime('%Y-%m-%d %H:%M')
        time_published = datetime.strptime(time_published_str, '%Y-%m-%d %H:%M')

        # Assuming time_now is the current datetime
        time_now = datetime.now()

        # Calculate time difference
        time_difference = time_now - time_published

        days = time_difference.days
        hours, remainder = divmod(time_difference.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

    next_url = url_for('view_and_publish_posts', page=pagination.next_num,
                       filterUsername=filter_username) if pagination and pagination.has_next else None
    prev_url = url_for('view_and_publish_posts', page=pagination.prev_num,
                       filterUsername=filter_username) if pagination and pagination.has_prev else None
    return render_template('index.html', posts=posts, is_admin=is_admin,
                           current_user_id=user_id, next_url=next_url, prev_url=prev_url,
                           time_now=time_now, time_published_str=time_published_str, days=days,
                           minutes=minutes, seconds=seconds)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit_posts(id):
    post_object = Posts.query.filter_by(id=id).first()
    if post_object.user_id != Users.query.filter_by(username=session['username']).first().id:
        abort(403)  # Forbidden if the current user is not the author of the post
    if request.method == 'POST':
        post_object.post = request.form['content']
        db.session.commit()
        return redirect('/posts')

    return render_template('edit.html', post=post_object, post_content=post_object.post)


@app.route('/posts/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    current_user = Users.query.filter_by(username=session['username']).first()

    if not current_user.is_admin and post_to_delete.user_id != current_user.id:
        abort(403)  # Forbidden if the current user is not the author of the post
    db.session.delete(post_to_delete)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect('/posts')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
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
        print(email)
        user = Users.query.filter_by(email=email).first()

        if user:
            # Generate a temporary token from user id
            print(user)
            token = str(user.id)

            # Send a password recovery email
            recover_url = url_for('reset_password', token=token, _external=False)
            print(recover_url)
            host = "http://127.0.0.1:5000"
            subject = 'Password Recovery'

            body = f'Click the following link to reset your password: {host}{recover_url}'
            print(subject, body)
            msg = Message(subject, sender="saartaranus@gmail.com", recipients=[email], body=body)
            mail.send(msg)
            print(mail.send(msg))

            return render_template('recover-password-success.html', email=email)
        else:
            return render_template('recover-password.html', error='Invalid email address')

    return render_template('recover-password.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)

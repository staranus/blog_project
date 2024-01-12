from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = '1234'
db = SQLAlchemy(app)


class Users(db.Model):  # extends db.Model to tell sqlalchemy that it's a table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    #db.String(64) since you are storing the hexadecimal
    # representation of a SHA-256 hash, which is 64 characters long.


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.Text, nullable=False)
    title = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id') ,nullable=False)

    # When doing a query, display each row represented
    # by an object containing what's in the return statement
    def __repr__(self):
        return 'Post ' + str(self.id)

with app.app_context():
    db.create_all()
    user_2 = Users(username="saar", password=hashlib.sha256("1234".encode()).hexdigest())
    db.session.add(user_2)
    db.session.commit()

            #query data from db
    user = Users.query.filter_by(username="saar").first()
    print(user)
    print(user.username)
    print(user.password)
    print(user.id)

@app.route("/")
def index():
    if 'username' in session:
        return redirect(url_for('view_and_publish_posts'))
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
            session['username'] = username
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
            return render_template('login.html',
                                   match_passwords=True, message='User already exists!')

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template('login.html',
                                   match_passwords=True, message=f"Passwords don't match!")

        password = hashlib.sha256(password.encode()).hexdigest()

        user = Users(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('view_and_publish_posts'))

    return render_template('login.html', match_passwords=True)

@app.route('/logout')
def user_logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/posts', methods=['POST', 'GET'])
def view_and_publish_posts():
    user_id = Users.query.filter_by(username=session['username']).first().id
    if request.method == 'POST':
        db.session.add(Posts(
            title=request.form['title'],
            post=request.form['content'],
            user_id=user_id
        ))
        db.session.commit()
        return redirect('/posts')
    posts = Posts.query.all()
    return render_template('index.html', posts=posts)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit_posts(id):
    #TODO:change id to post_id (kept word in python)
    # post_object = Posts.query.get(id)
    post_object = Posts.query.filter_by(id=id).first()
   # print(post_object.title)
    if request.method == 'POST':
        post_object.post = request.form['content']
        db.session.commit()
        return redirect('/posts')
    #todo- redo for previous code, instead of post_content (to consider)
    return render_template('edit.html', post=post_object, post_content=post_object.post)

@app.route('/posts/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect('/posts')



# @app.route('/all_todos', methods=["POST", "GET"])
# def all_posts():
#     if 'username' not in session:
#         return redirect(url_for('login'))
#
#     user_id = Users.query.filter_by(username=session['username']).first().id
#
#     if request.method == "POST":
#         content = request.form.get('content')
#
#         post = Posts(content=content)
#         db.session.add(post)
#         db.session.commit()
#
#     todos = Posts.query.filter_by(user_id=user_id).all()
#
#     return render_template('todos.html', todos=todos)

if __name__ == '__main__':
    app.run(debug=True, port=8885)

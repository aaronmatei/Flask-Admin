import datetime
from flask import Flask, redirect, render_template, url_for, render_template_string, request, flash, session
from flask_admin import Admin, BaseView, expose
from flask_mongoengine import MongoEngine
from flask_admin.form import rules
from flask_admin.contrib.mongoengine import ModelView
from werkzeug.security import generate_password_hash
from flask_admin.contrib.fileadmin import FileAdmin
from os.path import dirname, join
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_mongoengine import BaseQuerySet
from flask_user import login_required, UserManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token


# Create application
app = Flask(__name__)

# Create dummy secret key so we can use sessions
app.config['SECRET_KEY'] = 'Thisismysecretkey123456790'
app.config['MONGODB_SETTINGS'] = {'DB': 'ephoenixtesting'}
app.config['USER_APP_NAME'] = "E-Phoenix"
app.config['USER_ENABLE_EMAIL'] = False
app.config['USER_ENABLE_USERNAME'] = True
app.config['USER_REQUIRE_RETYPE_PASSWORD'] = False
app.config['USER_EMAIL_SENDER_EMAIL'] = False

# Create models
db = MongoEngine()
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
login_manager = LoginManager(app)
# user_manager = UserManager(app, db, User)


@login_manager.user_loader
def load_user(name):
    return User.objects(name='Aronique')


# Define mongoengine documents
class User(db.Document, UserMixin):
    active = db.BooleanField(default=True)
    # information to authenticate the user
    username = db.StringField(default='')
    password = db.StringField()
    # user information
    first_name = db.StringField(max_length=40)
    last_name = db.StringField(max_length=40)
    email = db.StringField(max_length=40)
    phone = db.StringField(max_length=40)
    birthday = db.DateTimeField()
    address = db.StringField()
    roles = db.ListField(db.StringField(), default=[])

    # meta = {'collection': 'user', 'queryset_class': BaseQuerySet}

    # @staticmethod
    # def is_authenticated(self):
    #     return True

    # @staticmethod
    # def is_active(self):
    #     return True

    # @staticmethod
    # def is_anonymous(self):
    #     return False

    # def get_id(self):
    #     return self._id

    def __unicode__(self):
        return self.username

    @staticmethod
    def check_password(password_hash, password):
        return check_password_hash(password_hash, password)

    @classmethod
    def get_by_username(cls, username):
        result = User.objects(username=username)
        if result is not None:
            return cls(**{'username': username})

    @classmethod
    def get_by_email(cls, email):
        result = User.objects(email=email)
        if result is not None:
            return cls(**{'email': email})

    @classmethod
    def get_by_id(cls, _id):
        data = User.objects(_id=_id)
        if data is not None:
            return cls(**{'_id': _id})

    @staticmethod
    def login_valid(email, password):
        verify_user = User.get_by_email(email)
        if verify_user is not None:
            return bcrypt.check_password_hash(verify_user.password, password)
        return False

    @classmethod
    def register_user(cls, username, email, password):
        user = cls.get_by_email(email)
        if user is None:
            new_user = cls(username, email, password)
            new_user.save_to_mongo()
            session['email'] = email
            return True
        else:
            return False

    def json(self):

        return {
            'username': self.username,
            'email': self.email,
            '_id': self._id,
            'password': self.password
        }

    def save_to_mongo(self):
        db.user.insert(self.json())


user_manager = UserManager(app, db, User)

class File(db.Document):
    name = db.StringField(max_length=20)
    data = db.FileField()


class Image(db.Document):
    name = db.StringField(max_length=20)
    image = db.ImageField(thumbnail_size=(100, 100, True))


# Customized admin views
class UserView(ModelView):
    column_filters = ['first_name']

    column_searchable_list = ('first_name', 'password')


    can_export = True
    column_display_pk = True
    # create_modal = True

    def on_model_change(self, form, model, is_created):
        model.password = generate_password_hash(
            model.password, method='sha256')

    def is_accessible(self):
        return True

    def inaccessible_callback(self, name, **kwargs):
        return '<h1>You are not logged in! </h>'




class ReportsView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin/reports.html')


class NotificationsView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin/notifications.html')

# Flask views
@app.route('/')
def home_page():
       
    return render_template('index.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    return render_template('register.html', title='Register')


@app.route('/newUser', methods=['POST', 'GET'])
def newUser():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        phone = request.form['phone']
        address = request.form['address']
        birthday = request.form['birthday']       
        
        password = bcrypt.generate_password_hash(
            request.form['password']).decode('utf-8')
        find_user = None   #User.get_by_email(email)
        if find_user is None:
            user = User(first_name=first_name,last_name=last_name,email=email,username=username,phone=phone,address=address,birthday=birthday,password=password )
            user.save()
            flash(
                f'Account for {username} created successfuly', 'success')
            return redirect(url_for('login'))
        else:
            flash(
                f'Account for {username} already exists', 'success')
            return redirect(url_for('register'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']    
        find_user = User.objects.get(email=email)
                              
        if find_user:
            if bcrypt.check_password_hash(find_user.password, password):
                access_token = create_access_token(identity={
                'first_name': find_user.first_name,
                'last_name': find_user.last_name,
                'email': find_user.email})                
                # loguser = User(email=email)
                # login_user(loguser)
                session['username']=find_user.username
                flash(f'Login successful', 'success')
                if find_user.username == 'Admin':
                    return redirect(url_for('admin_index'))
                return redirect(url_for('home_page'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
                return redirect(url_for('login'))
    return render_template('login.html', title='Login')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home_page'))

# The Members page is only accessible to authenticated users via the @login_required decorator
@app.route('/members')
@login_required    # User must be authenticated
def member_page():
    # String-based templates
    return 'Helloo'


@app.route('/admin')
def admin_index():
    return '<a href="/admin/">Click me to get to Admin!</a>'


if __name__ == '__main__':
    # Create admin
    admin = Admin(app, 'Ephoenix Admin')

    # Add views
    admin.add_view(UserView(User))

    admin.add_view(ModelView(File))
    # admin.add_view(ModelView(Image))
    admin.add_view(ReportsView(name='Reports', endpoint='reports'))
    admin.add_view(NotificationsView(
        name='Notifications', endpoint='notifications'))

    # @app.route('/login')
    # def login():
    #     # if current_user.is_authenticated:
    #     #     user = User.objects(name='Aronique')
    #     #     print(user)
    #     #     # login_user(user)
    #     return redirect(url_for('admin.index'))
    #     # return None

    # @app.route('/logout')
    # def logout():
    #     logout_user()
    #     return redirect(url_for('admin.index'))

    path = join(dirname(__file__), 'uploads')
    admin.add_view(FileAdmin(path, '/uploads', name='Uploads'))

    # Start app
    app.run(debug=True)

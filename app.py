import datetime

from flask import Flask, redirect, render_template, url_for
from flask_admin import Admin, BaseView, expose
from flask_mongoengine import MongoEngine
from flask_admin.form import rules
from flask_admin.contrib.mongoengine import ModelView
from werkzeug.security import generate_password_hash
from flask_admin.contrib.fileadmin import FileAdmin
from os.path import dirname, join
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_mongoengine import BaseQuerySet

# Create application
app = Flask(__name__)

# Create dummy secrey key so we can use sessions
app.config['SECRET_KEY'] = '123456790'
app.config['MONGODB_SETTINGS'] = {'DB': 'testing'}

# Create models
db = MongoEngine()
db.init_app(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(name):
    return User.objects(name='Aronique')


# Define mongoengine documents
class User(db.Document, UserMixin):
    name = db.StringField(max_length=40)
    tags = db.ListField(db.ReferenceField('Tag'))
    email = db.StringField(max_length=40)
    phone = db.StringField(max_length=40)
    birthday = db.DateTimeField()
    password = db.StringField()

    meta = {'collection': 'user', 'queryset_class': BaseQuerySet}

    @staticmethod
    def is_authenticated(self):
        return True

    @staticmethod
    def is_active(self):
        return True

    @staticmethod
    def is_anonymous(self):
        return False

    def get_id(self):
        return self._id

    def __unicode__(self):
        return self.name


class Todo(db.Document):
    title = db.StringField(max_length=60)
    text = db.StringField()
    done = db.BooleanField(default=False)
    pub_date = db.DateTimeField(default=datetime.datetime.now)
    user = db.ReferenceField(User, required=False)

    # Required for administrative interface
    def __unicode__(self):
        return self.title


class Tag(db.Document):
    name = db.StringField(max_length=10)

    def __unicode__(self):
        return self.name


class Comment(db.EmbeddedDocument):
    name = db.StringField(max_length=20, required=True)
    value = db.StringField(max_length=20)
    tag = db.ReferenceField(Tag)


class Post(db.Document):
    name = db.StringField(max_length=20, required=True)
    value = db.StringField(max_length=20)
    inner = db.ListField(db.EmbeddedDocumentField(Comment))
    lols = db.ListField(db.StringField(max_length=20))


class File(db.Document):
    name = db.StringField(max_length=20)
    data = db.FileField()


class Image(db.Document):
    name = db.StringField(max_length=20)
    image = db.ImageField(thumbnail_size=(100, 100, True))


# Customized admin views
class UserView(ModelView):
    column_filters = ['name']

    column_searchable_list = ('name', 'password')

    form_ajax_refs = {
        'tags': {
            'fields': ('name',)
        }
    }
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


class TodoView(ModelView):
    column_filters = ['done']

    form_ajax_refs = {
        'user': {
            'fields': ['name']
        }
    }


class PostView(ModelView):
    form_subdocuments = {
        'inner': {
            'form_subdocuments': {
                None: {
                    # Add <hr> at the end of the form
                    'form_rules': ('name', 'tag', 'value', rules.HTML('<hr>')),
                    'form_widget_args': {
                        'name': {
                            'style': 'color: red'
                        }
                    }
                }
            }
        }
    }


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
def index():
    return '<a href="/admin/">Click me to get to Admin!</a>'


if __name__ == '__main__':
    # Create admin
    admin = Admin(app, 'Admin: MongoEngine')

    # Add views
    admin.add_view(UserView(User))
    admin.add_view(TodoView(Todo))
    admin.add_view(ModelView(Tag))
    admin.add_view(PostView(Post))
    admin.add_view(ModelView(File))
    # admin.add_view(ModelView(Image))
    admin.add_view(ReportsView(name='Reports', endpoint='reports'))
    admin.add_view(NotificationsView(
        name='Notifications', endpoint='notifications'))

    @app.route('/login')
    def login():
        # if current_user.is_authenticated:
        #     user = User.objects(name='Aronique')
        #     print(user)
        #     # login_user(user)
        return redirect(url_for('admin.index'))
        # return None

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('admin.index'))

    path = join(dirname(__file__), 'uploads')
    admin.add_view(FileAdmin(path, '/uploads', name='Uploads'))

    # Start app
    app.run(debug=True)

from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand

from compass import create_app, db
from compass.auth.models import User


app = create_app('default')


manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, User=User)

manager.add_command("db", MigrateCommand)
manager.add_command("shell", Shell(make_context=make_shell_context))


if __name__ == "__main__":
    manager.run()

import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'very hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    COMPASS_MAIL_SUBJECT_PREFIX = '[Compass]'
    COMPASS_MAIL_SENDER = 'Compass Admin <jansabacko@gmail.com>'
    COMPASS_ADMIN = os.environ.get('COMPASS_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = (os.environ.get('DEV_DATABASE_URI') or
                               'sqlite:///' + os.path.join(basedir,
                                                           'data-dev.sqlite'))


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = (os.environ.get('TEST_DATABASE_URL') or
                               'sqlite:///' + os.path.join(basedir,
                                                           'data-test.sqlite'))
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}

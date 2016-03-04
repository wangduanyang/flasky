import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_POST_PER_PAGE = 10
    FLASKY_FOLLOWERS_PER_PAGE = 10
    FLASKY_COMMENTS_PER_PAGE = 10
    FLASKY_MAIL_SUBJECT_PREFIX = '[FLASKY]'
    FLASKY_MAIL_SENDER = '13063624378@163.com'
    FLASKY_ADMIN = '786497042@qq.com'
    MAIL_SERVER = 'smtp.163.com'
    MAIL_PORT = 25
    MAIL_USE_TLS = True
    SSL_DISABLE = True
    # FLASK_CONFIG = os.environ.get('FLASK_CONFIG')

    @staticmethod
    def init_app(cls, app):
        Config.init_app(app)

        import logging
        from logging.handlers import SMTPHandler
        credentials = None
        secure = None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()
            mail_handler = SMTPHandler(
                mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
                fromaddr=cls.FLASKY_MAIL_SENDER,
                toaddrs=[cls.FLASKY_ADMIN],
                subject=cls.FLASKY_MAIL_SUBJECT_PREFIX + ' Application Error',
                credentials=credentials,
                secure=secure
            )
            mail_handler.setLevel(logging.Error)
            app.logger.addHandler(mail_handler)

        # if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
        #     from flask.ext.sslify import SSLify
        #     sslify = SSLify(app)


class DevelopmentConfig(Config):
    DEBUG = True
    #email
    # MAIL_SERVER = 'smtp.163.com'
    # MAIL_PORT = 25
    # MAIL_USE_TLS = True
    MAIL_USERNAME = '13063624378@163.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')


class ProductionConfig(Config):
    # DEBUG = True
    #email
    # MAIL_SERVER = 'smtp.163.com'
    # MAIL_PORT = 25
    # MAIL_USE_TLS = True
    # MAIL_USERNAME = '13063624378@163.com'
    # MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data-pro.sqlite')


class HerokuConfig(ProductionConfig):
    SSL_DISABLE = bool(os.environ.get('SSL_DISABLE'))

    @staticmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.WARNNING)
        app.logger.addHandler(file_handler)

        # from werkzeug.contrib.fixers import ProxyFix
        # app.wsgi_app = ProxyFix(app.wsgi_app)


config = {
    'default': DevelopmentConfig,
    'production': ProductionConfig,
    'heroku': HerokuConfig
}

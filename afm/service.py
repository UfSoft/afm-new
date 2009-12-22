# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
"""
    sshg.service
    ~~~~~~~~~~~~

    This module is responsible for console options parsing and services
    starting.

    :copyright: © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
    :license: BSD, see LICENSE for more details.
"""

import sys
from ConfigParser import SafeConfigParser, NoSectionError
import getpass
from datetime import datetime, timedelta
from os import makedirs
from os.path import abspath, basename, expanduser, isdir, isfile, join
from types import ModuleType

from twisted.application import internet
from twisted.application.service import (IServiceMaker, Application,
                                         IServiceCollection)
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.internet import reactor, task
from twisted.web import server, wsgi
from twisted.python.threadpool import ThreadPool
from zope.interface import implements


from sshg import (__version__, __summary__, application, config, database as db,
                  upgrades, logger)
from sshg.checkers import MercurialAuthenticationChekers
from sshg.factories import MercurialReposFactory
from sshg.notification import NotificationSystem
from sshg.portals import MercurialRepositoriesPortal
from sshg.utils.crypto import gen_secret_key
from sshg.realms import MercurialRepositoriesRealm
from sshg.web.wsgi import WSGIApplication


try:
    from migrate.versioning.api import upgrade
    from migrate.versioning.repository import Repository

    UPGRADES_REPO = Repository(upgrades.__path__[0])
except ImportError:
    upgrade = UPGRADES_REPO = None

log = logger.getLogger(__name__)

def required_imports_ok():
    if not upgrade or not UPGRADES_REPO:
        print "You need the SQLAlchemy-migrate package installed."
        print "  http://code.google.com/p/sqlalchemy-migrate/"
        return False
    return True

class PasswordsDoNotMatch(Exception):
    """Simple exception to catch non-matching passwords"""

def ask_password(ask_pass_text=None, calledback=None):
    if calledback is not None:
        # This is called automatically if it's OpenSSL asking for it
        return getpass.getpass("Please specify the password for the key: ")

    # It's not a password being requested, it's a password to define
    passwd = getpass.getpass(ask_pass_text or
                             "Define a password for the new private key "
                             "(leave empty for none): ")
    if not passwd:
        return None
    verify_password = getpass.getpass("Verify Password: ")
    if passwd != verify_password:
        print "Passwords do not match!"
        raise PasswordsDoNotMatch
    return passwd

class BaseOptions(usage.Options):
    def opt_version(self):
        """Show version"""
        print "%s - %s" % (basename(sys.argv[0]), __version__)
    opt_v = opt_version

    def opt_help(self):
        """Show this help message"""
        super(BaseOptions, self).opt_help()
    opt_h = opt_help

class SetupOptions(BaseOptions):
    longdesc = "Configure SSHg"

    def getService(self):
        if not isfile(config.private_key):
            print "Generating the SSH Private Key"
            from OpenSSL import crypto
            privateKey = crypto.PKey()
            privateKey.generate_key(crypto.TYPE_RSA, 1024)
            password = ''
            while not password:
                try:
                    password = ask_password()
                    break
                except PasswordsDoNotMatch:
                    # Passwords did not match
                    pass

            encryption_args = password and ["DES-EDE3-CBC", password] or []
            privateKeyData = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                                    privateKey,
                                                    *encryption_args)
            open(config.private_key, 'w').write(privateKeyData)

            print "You can provide your own private key."
            print "Just point to the correct paths on the configuration file."
            print
            print "Generating configuration server SSL certificate"
            cert = crypto.X509()
            subject = cert.get_subject()
            subject.CN = 'SSHg Configuration Server'
            cert.set_pubkey(privateKey)
            cert.set_serial_number(1)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 5) # Five Years
            cert.set_issuer(subject)
            cert.sign(privateKey, "md5")
            certData = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            open(join(config.dir, 'certificate.pem'), 'w').write(certData)
            print "Done. This certificate is valid for 5 years."
            print "You can provide your own private key/certificate,"
            print "just point to the correct paths on the configuration file."
            print


        print "Creating Database"
        application.database_engine = db.create_engine()
        db.metadata.create_all(application.database_engine)
        print "Setup initial username"
        username = raw_input("Username [%s]: " % getpass.getuser())
        if not username:
            username = getpass.getuser()
        password = None
        while not password:
            try:
                password = ask_password('Define a password for "%s": ' %
                                        username)
                if not password:
                    print "Password cannot not be empty"
            except PasswordsDoNotMatch:
                pass

        session = db.session()
        user = db.User(username, password, is_admin=True)
        pubkey_path = raw_input("Path to your public key [~/.ssh/id_rsa.pub]: ")
        if not pubkey_path:
            pubkey_path = expanduser('~/.ssh/id_rsa.pub')
        if not isfile(expanduser(pubkey_path)):
            print "File %r does not exist" % expanduser(pubkey_path)
        key = db.PublicKey(open(expanduser(pubkey_path)).read())
        user.keys.append(key)
        session.add(user)

        # Setup database schema version control
        if not required_imports_ok():
            sys.exit(1)
        session.add(db.SchemaVersion("SSHg Schema Version Control",
                                     UPGRADES_REPO.path, UPGRADES_REPO.latest)
        )

        session.commit()

        config.parser.set('main', 'app_manager', username)
        config.parser.write(open(config.file, 'w'))
        print "Done"
        sys.exit()

class MigrateScriptAccess(BaseOptions):
    longdesc = "SQLAlchemy Migrate Script Access"

    def parseOptions(self, options=None):
        if not required_imports_ok():
            sys.exit(1)
        from migrate.versioning.shell import main
        # Tweak sys.argv
        sys.argv = sys.argv[sys.argv.index('migrate'):]
        main(url=db.create_engine().url, repository=UPGRADES_REPO.path)
        sys.exit()

class UpgradeOptions(BaseOptions):
    longdesc = "Upgrade SSHg"

    subCommands = [
        ["migrate", None, MigrateScriptAccess, MigrateScriptAccess.longdesc]
    ]

    def getService(self):
        if not required_imports_ok():
            sys.exit(1)
        application.database_engine = db.create_engine()
        session = db.session()
        if not application.database_engine.has_table(
                                                db.SchemaVersion.__tablename__):
            # Too old db schema version, does not even have the control table
            db.SchemaVersion.__table__.create(bind=application.database_engine)

        if not session.query(db.SchemaVersion).first():
            # No previously entered record
            session.add(
                db.SchemaVersion("SSHg Schema Version Control",
                                 unicode(UPGRADES_REPO.path), 0)
            )
            session.commit()

        schema_version = session.query(db.SchemaVersion).first()

        if schema_version.version >= UPGRADES_REPO.latest:
            print "No upgrade needed."
            sys.exit()

        # Do the database upgrade
        if config.db.engine == 'sqlite':
            from shutil import copy
            print "Backup current database:"
            old_db_path = join(config.db.path, config.db.name)
            new_db_path = join(config.db.path, '.'.join(
                [config.db.name, str(UPGRADES_REPO.latest), 'bak'])
            )
            print " %s -> %s" % (old_db_path, new_db_path)
            copy(old_db_path, new_db_path)
        print "Upgrading..."
        upgrade(application.database_engine.url, UPGRADES_REPO)

        sys.exit()

class ServiceOptions(BaseOptions):
    longdesc = "Mercurial repositories SSH server"

    def getService(self):

        def upgrade_required():
            print "You need to upgrade your database!"
            print "Please run the upgrade command"
            sys.exit(1)
        application.database_engine = db.create_engine()

        session = db.session()
        if not application.database_engine.has_table(
                                                db.SchemaVersion.__tablename__):
            # Too old db schema version, does not even have the control table
            upgrade_required()
        elif not session.query(db.SchemaVersion).first():
            # Table exists!? Yet, no previously entered record!?
            upgrade_required()

        if required_imports_ok():
            schema_version = session.query(db.SchemaVersion).first()
            if schema_version.version < UPGRADES_REPO.latest:
                upgrade_required()

        realm = MercurialRepositoriesRealm()
        portal = MercurialRepositoriesPortal(realm)
        portal.registerChecker(MercurialAuthenticationChekers())
        factory = MercurialReposFactory(realm, portal)
        return internet.TCPServer(config.port, factory)

class SSHgOptions(BaseOptions):
    longdesc = "Mercurial repositories SSH server"

    optParameters = [
        ["config-dir", "c", None, "Configuration directory"],
    ]

    subCommands = [
        ["setup", None, SetupOptions, SetupOptions.longdesc],
        ["server", None, ServiceOptions, ServiceOptions.longdesc],
        ["upgrade", None, UpgradeOptions, UpgradeOptions.longdesc],
    ]

    defaultSubCommand = "server"

    def opt_config_dir(self, configdir):
        configdir = self.opts['config-dir'] = abspath(expanduser(configdir))
        configfile = join(configdir, 'sshg.ini')
        parser = SafeConfigParser()

        if not isdir(configdir):
            print "Creating configuration directory: %r" % configdir
            makedirs(configdir, 0750)

        if not isfile(configfile):
            print "Creating configuration file with defaults: %r" % configfile

            # Main Server Options
            parser.add_section('main')
            parser.set('main', 'port', '22')
            parser.set('main', 'private_key', '%(here)s/privatekey.pem')
            parser.set('main', 'motd_file', '%(here)s/motd.txt')
            parser.set('main', 'app_manager', '')

            motd_file = join(configdir, 'motd.txt')
            if not isfile(motd_file):
                open(motd_file, 'w').write(
                    "%(green)s  Welcome to the SSHg console terminal. "
                    "Type ? for help."
                )

            # Database Options
            parser.add_section('database')
            parser.set('database', 'echo', 'false')
            parser.set('database', 'engine', 'sqlite')
            parser.set('database', 'username', '')
            parser.set('database', 'password', '')
            parser.set('database', 'name', 'database.db')
            parser.set('database', 'path', '%(here)s')

            # Web Admin Options
            import string
            from random import choice
            parser.add_section("web")
            parser.set('web', 'port', '8443')
            parser.set('web', 'certificate', '%(here)s/certificate.pem')
            parser.set('web', 'cookie_name', 'SSHg')
            parser.set('web', 'secret_key', gen_secret_key())
            parser.set('web', 'min_threads', '5')
            parser.set('web', 'max_threads', '25')

            # Notification Settings
            parser.add_section('notification')
            parser.set('notification', 'enabled', 'true')
            parser.set('notification', 'smtp_server', '')
            parser.set('notification', 'smtp_port', '25')
            parser.set('notification', 'smtp_user', '')
            parser.set('notification', 'smtp_pass', '')
            parser.set('notification', 'smtp_from', '')
            parser.set('notification', 'from_name', 'SSHg')
            parser.set('notification', 'reply_to', '')
            parser.set('notification', 'use_tls', 'false')

            parser.write(open(configfile, 'w'))
            print "Please check configuration and run the setup command again"
            sys.exit(0)

        parser.read([configfile])
        parser.set('DEFAULT', 'here', configdir)

        config.dir = configdir
        config.file = configfile
        config.parser = parser

        config.port = parser.getint('main', 'port')
        config.private_key = abspath(parser.get('main', 'private_key'))
        config.app_manager = parser.get('main', 'app_manager')

        motd = abspath(parser.get('main', 'motd_file'))
        if isfile(motd):
            config.motd = open(motd).read()
        else:
            config.motd = "%(green)s  Welcome to the SSHg console terminal. "+ \
                          "Type ? for help."

        config.db = ModuleType('config.db')
        config.db.echo = parser.getboolean('database', 'echo')
        config.db.engine = parser.get('database', 'engine')
        if config.db.engine not in ('sqlite', 'mysql', 'postgres', 'oracle',
                                    'mssql', 'firebird'):
            print 'Database engine "%s" not supported' % config.db.engine
            sys.exit(1)
        config.db.path = '/' + abspath(parser.get('database', 'path'))
        config.db.username = parser.get('database', 'username')
        config.db.password = parser.get('database', 'password')
        config.db.name = parser.get('database', 'name')

        try:
            config.web = ModuleType('config.web')
            config.web.port = parser.getint('web', 'port')
            config.web.certificate = abspath(parser.get('web', 'certificate'))
            config.web.cookie_name = parser.get('web', 'cookie_name')
            config.web.secret_key = parser.get('web', 'secret_key', raw=True)
            config.web.min_threads = parser.getint('web', 'min_threads')
            config.web.max_threads = parser.getint('web', 'max_threads')
            config.notification = ModuleType('config.notification')
            config.notification.enabled = parser.getboolean('notification',
                                                            'enabled')
            config.notification.smtp_server = parser.get('notification',
                                                         'smtp_server')
            config.notification.smtp_port = parser.getint('notification',
                                                          'smtp_port')
            config.notification.smtp_user = parser.get('notification',
                                                       'smtp_user')
            config.notification.smtp_pass = parser.get('notification',
                                                       'smtp_pass')
            config.notification.smtp_from = parser.get('notification',
                                                       'smtp_from')
            config.notification.from_name = parser.get('notification',
                                                       'from_name')
            config.notification.reply_to =  parser.get('notification',
                                                       'reply_to')
            config.notification.use_tls = parser.getboolean('notification',
                                                            'use_tls')
            application.notification = NotificationSystem()
        except NoSectionError:
            print "You will need to upgrade... Are you upgrading?"



    def postOptions(self):
        if not self.opts.get('config-dir'):
            print "You need to pass a configuration directory. Exiting..."
            sys.exit(1)
        if not isfile(config.private_key) and self.subCommand != 'setup':
            print "The private key file(%r) does not exist" % config.private_key
            print "Did you run the setup command?"
            sys.exit(1)


class SSHgService(object):
    implements(IServiceMaker, IPlugin)
    tapname = 'sshg'
    description = __summary__
    options = SSHgOptions

    def __clean_old_changes_from_db(self):
        session = db.session()
        expired = session.query(db.Change).filter(
            db.Change.created<datetime.utcnow()-timedelta(days=1)
        )
        log.debug("Expired User Changes: %r", expired.all())
        for entry in expired.all():
            log.debug("Cleaning up expired %r", entry)
            session.delete(entry)
        session.commit()

    def makeService(self, options):
        app = Application("Mercurial SSH Server") #, uid, gid)
        services = IServiceCollection(app)
        service = options.subOptions.getService()
        service.setServiceParent(services)


        wsgi_app = WSGIApplication()
        threadpool = ThreadPool(config.web.min_threads, config.web.max_threads)
        threadpool.start()
        reactor.addSystemEventTrigger('after', 'shutdown', threadpool.stop)
        root = wsgi.WSGIResource(reactor, threadpool, wsgi_app)
        factory = server.Site(root)
        if isfile(config.web.certificate):
            from OpenSSL import SSL
            # Run SSL Server
            class SSLContext(object):
                def getContext(self):
                    ctx = SSL.Context(SSL.SSLv23_METHOD)
                    ctx.use_privatekey_file(config.private_key)
                    ctx.use_certificate_file(config.web.certificate)
                    return ctx
            config_service = internet.SSLServer(config.web.port, factory,
                                                SSLContext())
        else:
            config_service = internet.TCPServer(config.web.port, factory)
        config_service.setServiceParent(app)

        clean_changes_task = task.LoopingCall(self.__clean_old_changes_from_db)
        clean_changes_task.start(5*60, now=True) # Every 5 minutes
        reactor.addSystemEventTrigger('after', 'shutdown',
                                      clean_changes_task.stop)
        return services


# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================

import logging
import sys
from os import makedirs
from os.path import abspath, exists, expanduser, isdir, join
from ConfigParser import SafeConfigParser

from twisted.python import reflect, util, usage
from twisted.python.log import PythonLoggingObserver

from afm import application, config
from afm.database import db, Certificate
from afm.logger import Logging
from afm.usage import RawUsageOptions, certs, client, server, SysExit

class ServiceOptions(RawUsageOptions):
    optParameters = [
        ("config", "c", "~/.afm", "Configuration directory"),
        ("logfile", "l", None, "Logfile path"),
    ]
    optFlags = [
        ['quiet', 'q', 'Be quiet. No output.'],
        ['debug', 'd', 'Debug output'],
    ]

    subCommands = [
        ["certs", None, certs.CertsCreatorOptions,
         certs.CertsCreatorOptions.__doc__],
        ["server", None, server.ServerOptions,
         server.ServerOptions.__doc__],
        ["client", None, client.ClientOptions,
         client.ClientOptions.__doc__]
    ]

    def opt_config(self, config_dir):
        self.opts['config'] = abspath(expanduser(config_dir))
        if not isdir(self.opts['config']):
            makedirs(self.opts['config'])

        config.dir = self.opts['config']
        config.file = join(config.dir, 'afm.ini')
        self.parser = parser = SafeConfigParser()
        config.parser = parser

        if not exists(config.file):
            self._write_initial_config(parser)

        parser.read([config.file])
        parser.set('DEFAULT', 'here', config.dir)
        self._populate_application_config(parser)


    def opt_quiet(self):
        self.opts['logging_level'] = logging.FATAL
        self.opts['quiet'] = True

    def opt_debug(self):
        self.opts['logging_level'] = logging.DEBUG
        self.opts['debug'] = True

    def _populate_application_config(self, parser):
        # Database Settings
        config.db.engine = parser.get('database', 'engine')

        if config.db.engine not in ('sqlite', 'mysql', 'postgres', 'oracle',
                                    'mssql', 'firebird'):
            print 'Database engine "%s" not supported' % config.db.engine
            sys.exit(1)

        config.db.name = parser.get('database', 'name')
        config.db.path = parser.get('database', 'path')
        config.db.username = parser.get('database', 'username')
        config.db.password = parser.get('database', 'password')

        print "Setting up database"
        application.database_engine = db.create_engine()
        try:
            db.metadata.create_all(application.database_engine)
        except Exception, err:
            print err
            raise

        # Server settings
        config.server.root_ca = abspath(
            expanduser(parser.get('server', 'root-ca'))
        )

        config.server.certificate = abspath(
            expanduser(parser.get('server', 'certificate'))
        )

        config.server.private_key = abspath(
            expanduser(parser.get('server', 'private-key'))
        )

        # Client settings
        config.client.root_ca = abspath(
            expanduser(parser.get('client', 'root-ca'))
        )

        config.client.certificate = abspath(
            expanduser(parser.get('client', 'certificate'))
        )

        config.client.private_key = abspath(
            expanduser(parser.get('client', 'private-key'))
        )

#        if self.subOptions and not self.subOptions.subCommand == 'newca':
#            if not db.session().query(Certificate).filter_by(root_ca=True).count():
#                print "You haven't generate your Root Certificate Authority yet!"
#                print "Please run the \"newca\" command"
#                sys.exit(1)


    def _write_initial_config(self, parser):
        # Database Options
        parser.add_section('database')
        parser.set('database', 'engine', 'sqlite')
        parser.set('database', 'username', '')
        parser.set('database', 'password', '')
        parser.set('database', 'name', 'database.db')
        parser.set('database', 'path', '%(here)s')

        parser.write(open(config.file, 'w'))
        raise SysExit("Initial configuration has been written to %s.\n"
                      "Please check it before running again.", config.file,
                      code=0)

    def postOptions(self):
        if self.opts['config'] == "~/.afm":
            self.opt_config(self.opts['config'])

        if self.opts['quiet'] and self.opts['debug']:
            print "ERROR: Only pass one of '--debug' or '--quiet', not both."
            self.opt_help()

        if 'logging_level' not in self.opts:
            self.opts['logging_level'] = logging.INFO

        # Setup logging
        if logging.getLoggerClass() is not Logging:
            afm_log = logging.getLogger('afm')
            afm_log.setLevel(self.opts['logging_level'])
            if self.opts['logfile']:
                from logging.handlers import RotatingFileHandler
                handler = RotatingFileHandler(
                    self.opts['logfile'],
                    maxBytes=1*1024*1024,   # 1 MB
                    backupCount=5,
                    encoding='utf-8'
                )
            else:
                handler = logging.StreamHandler()

            handler.setLevel(self.opts['logging_level'])
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)-8s] [%(name)-15s] %(message)s",
                "%H:%M:%S"
            )
            handler.setFormatter(formatter)
            afm_log.addHandler(handler)

            sqla_log = logging.getLogger('sqlalchemy')
            sqla_log.setLevel(logging.ERROR)

            if self.opts['debug']:
                sqla_log.setLevel(self.opts['logging_level'])

                # SQLA Engine Logging
                sqlae = logging.getLogger('sqlalchemy.engine')
                sqlae.setLevel(self.opts['logging_level'])
                sqlae.addHandler(handler)

                # SQLA Unit-Of-Work Logging
                sqlauof = logging.getLogger('sqlalchemy.orm.unitofwork')
                sqlauof.setLevel(self.opts['logging_level'])
                sqlauof.addHandler(handler)

            sqla_log.addHandler(handler)


            tw_log = logging.getLogger('twisted')
            tw_log.setLevel(self.opts['logging_level'])
            tw_log.addHandler(handler)

            logging.setLoggerClass(Logging)

            twisted_logging = PythonLoggingObserver('twisted')
            twisted_logging.start()

        if self.subOptions and not self.subOptions.subCommand == 'newca':
            if not db.session().query(Certificate).\
                                            filter_by(root_ca=True).count():
                SysExit("You haven't generate your Root Certificate Authority "
                        "yet!\nPlease run the \"newca\" command")

if __name__ == '__main__':
    sys.path.insert(0, abspath('../../'))

    runner = ServiceOptions()
    try:
        runner.parseOptions() # When given no argument, parses sys.argv[1:]
    except usage.UsageError, errortext:
        print '%s: %s' % (sys.argv[0], errortext)
        print '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)

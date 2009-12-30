# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
"""
    afm.database
    ~~~~~~~~~~~~

    This module is a layer on top of SQLAlchemy to provide asynchronous
    access to the database and has the used tables/models used in AFM

    :copyright: © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
    :license: BSD, see LICENSE for more details.
"""

import logging
import os
import sys
from os import path
from datetime import datetime
from types import ModuleType
from uuid import uuid4

import sqlalchemy
from sqlalchemy import and_, or_
from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import make_url, URL

from OpenSSL import crypto

#from afm import logger, exceptions, config
from afm import config
#from sshg.utils.crypto import gen_pwhash, check_pwhash

from twisted.python import log as twlog

log = logging.getLogger(__name__)

def get_engine():
    """Return the active database engine (the database engine of the active
    application).  If no application is enabled this has an undefined behavior.
    If you are not sure if the application is bound to the active thread, use
    :func:`~zine.application.get_application` and check it for `None`.
    The database engine is stored on the application object as `database_engine`.
    """
    from afm import application
    return application.database_engine

def create_engine():
    if config.db.engine == 'sqlite':
        info = URL('sqlite', database=path.join(config.db.path, config.db.name))
    else:
        if config.db.username and config.db.password:
            uri = '%(engine)s://%(username)s:%(password)s@%(host)s/%(name)s'
        if config.db.username and not config.db.password:
            uri = '%(engine)s://%(username)s@%(host)s/%(name)s'
        else:
            uri = '%(engine)s://%(host)s/%(name)s'
        info = make_url(uri % config.db.__dict__)
    if info.drivername == 'mysql':
        info.query.setdefault('charset', 'utf8')
    options = {'convert_unicode': True,
               'echo': False, 'echo_pool': False, 'echo_uow': False}

    # alternative pool sizes / recycle settings and more.  These are
    # interpreter wide and not from the config for the following reasons:
    #
    # - system administrators can set it independently from the webserver
    #   configuration via SetEnv and friends.
    # - this setting is deployment dependent should not affect a development
    #   server for the same instance or a development shell
    for key in 'pool_size', 'pool_recycle', 'pool_timeout':
        value = os.environ.get('SSHG_DATABASE_' + key.upper())
        if value is not None:
            options[key] = int(value)
    try:
        return sqlalchemy.create_engine(info, **options)
    except TypeError:
        options.pop('echo_uow')
        return sqlalchemy.create_engine(info, **options)

def session():
    return orm.create_session(get_engine(), autoflush=True, autocommit=False)

def require_session(f):
    def wrapper(*args, **kwargs):
        current_session = session()
        try:
            return f(session=current_session, *args, **kwargs)
        except:
            twlog.err()
            current_session.rollback()
            raise # We need to keep raising the exceptions, for now, all of them
        finally:
            current_session.close()
    return wrapper

#: create a new module for all the database related functions and objects
sys.modules['afm.database.db'] = db = ModuleType('db')
key = value = mod = None
for mod in sqlalchemy, orm:
    for key, value in mod.__dict__.iteritems():
        if key == 'create_engine':
            continue
        if key in mod.__all__:
            setattr(db, key, value)
del key, mod, value
db.and_ = and_
db.or_ = or_
#del and_, or_

db.create_engine = create_engine
db.session = session
db.require_session = require_session


DeclarativeBase = declarative_base()
db.metadata = metadata = DeclarativeBase.metadata

class SchemaVersion(DeclarativeBase):
    """SQLAlchemy-Migrate schema version control table."""

    __tablename__   = 'migrate_version'
    repository_id   = db.Column(db.String(255), primary_key=True)
    repository_path = db.Column(db.Text)
    version         = db.Column(db.Integer)

    def __init__(self, repository_id, repository_path, version):
        self.repository_id = repository_id
        self.repository_path = repository_path
        self.version = version


class Certificate(DeclarativeBase):
    """Generated Certificates table"""

    __tablename__   = certificates_table = 'certificates'

    cert_id     = db.Column(db.Integer, autoincrement=True, primary_key=True)
    serial      = db.Column(db.Integer)
    certificate = db.Column(db.Text)
    private_key = db.Column(db.Text)
    issued_on   = db.Column(db.DateTime, default=datetime.utcnow)
    root_ca     = db.Column(db.Boolean, default=False)
    issuer_id   = db.Column(db.ForeignKey('certificates.cert_id'))

    # Relations
    issued      = db.relation("Certificate",
                              remote_side="Certificate.issuer_id",
                              backref=db.backref("issuer", uselist=False,
                                                 remote_side='Certificate.cert_id'))
    revoked     = db.relation("RevokedCertificate", backref="cert",
                              uselist=False, cascade="all,delete-orphan")


    def __init__(self, serial, certificate, private_key,
                 root_ca=False, issuer=None):
        self.serial = serial
        self.certificate = certificate
        self.private_key = private_key
        self.root_ca = root_ca
        if not issuer:
            issuer = self
        self.issuer = issuer

    def __repr__(self):
        return '<%s serial="%d">' % (self.__class__.__name__, self.serial)

    def revoke(self):
        self.revoked = True
        self.revoked_on = datetime.utcnow()

    @property
    def cert(self):
        if not hasattr(self, '_cert'):
            self._cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                 self.certificate)
        return self._cert

    @property
    def subject(self):
        return self.cert.get_subject()

    @property
    def cert_issuer(self):
        return self.cert.get_issuer()


class RevokedCertificate(DeclarativeBase):
    """Revoked certificates Table"""

    __tablename__ = 'revocations'

    cert_id = db.Column(db.ForeignKey('certificates.cert_id'), primary_key=True)
    when    = db.Column(db.DateTime, default=datetime.utcnow)
    reason  = db.Column(db.Text)

    def __init__(self, reason):
        self.reason = reason

class Failure(DeclarativeBase):
    """Audio Failures log table"""

    __tablename__ = 'failures'

    id      = db.Column(db.DateTime, default=datetime.utcnow, primary_key=True)
    level   = db.Column(db.Integer)
    text    = db.Column(db.Text)

    def __init__(self, failure_level, failure_text):
        self.level = failure_level
        self.text = failure_text

    def __repr__(self):
        return '<%s level="%s" text="%s">' % (self.__class__.__name__,
                                              self.level, self.text)

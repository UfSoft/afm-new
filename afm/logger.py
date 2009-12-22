# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================

import os
import logging
from twisted.internet import defer

LoggingLoggerClass = logging.getLoggerClass()

from foolscap.logging import log

#class FoolscapBridge(object):
#
#    def msg(self, *args, **kwargs):
#        print 1234567, args, kwargs
#        return log.msg(*args, **kwargs)
#
#    def add_event(self, facility, level, event):
#        logger = logging.getLogger(facility)
#        print 1234567, facility, level, event
##        log.log(level)

def observer(evt):
#    print 1234567, evt, '\n\n'
    if 'facility' in evt:
        if evt['facility'].startswith('foolscap'):
            logger = logging.getLogger(evt['facility'])
            try:
                logger.log(evt['level'], evt['message'])
            except KeyError:
                if 'format' not in evt:
                    print 123456789, evt, '\n\n'
                else:
                    logger.log(evt['level'], evt['format'] % evt)
            except:
                print 123456789000, evt, '\n\n'
    else:
        print 1234567, evt, '\n\n'

log.theLogger.addObserver(observer)
#log.theLogger = FoolscapBridge

class Logging(LoggingLoggerClass):
    def __init__(self, logger_name='afm', level=logging.DEBUG):
        LoggingLoggerClass.__init__(self, logger_name, level)

    @defer.inlineCallbacks
    def debug(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.debug(self, msg, *args, **kwargs)

    @defer.inlineCallbacks
    def info(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.info(self, msg, *args, **kwargs)

    @defer.inlineCallbacks
    def warning(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.warning(self, msg, *args, **kwargs)

    warn = warning

    @defer.inlineCallbacks
    def error(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.error(self, msg, *args, **kwargs)

    @defer.inlineCallbacks
    def critical(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.critical(self, msg, *args, **kwargs)

    @defer.inlineCallbacks
    def exception(self, msg, *args, **kwargs):
        yield LoggingLoggerClass.exception(self, msg, *args, **kwargs)


""" Simple wrapper on Foolscap logging. For more information, please see:
  http://foolscap.lothar.com/docs/logging.html
"""
#from foolscap.logging import log
#
#class Logging1(LoggingLoggerClass):
#    def __init__(self, facility="afm"):
#        LoggingLoggerClass.__init__(self, facility, level=log.NOISY)
#        self.facility = facility
#
#    def bad(self, msg, *args, **kwargs):
#        """something which significantly breaks functionality.
#        Unhandled exceptions and broken invariants fall into this category."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.BAD
#        if 'stacktrace' not in kwargs:
#            kwargs['stacktrace'] = True
#        return log.msg(msg, *args, **kwargs)
#    exception = bad
#
#    def scary(self, msg, *args, **kwargs):
#        """something which is a problem, and shouldn't happen in normal
#        operation, but which causes minimal functional impact, or from which
#        the application can somehow recover."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.SCARY
#        return log.msg(msg, *args, **kwargs)
#    critical = scary
#
#    def weird(self, msg, *args, **kwargs):
#        """not as much of a problem as SCARY, but still not right."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.WEIRD
#        return log.msg(msg, *args, **kwargs)
#    warning = weird
#
#    def curious(self, msg, *args, **kwargs):
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.CURIOUS
#        return log.msg(msg, *args, **kwargs)
#
#    def infrequent(self, msg, *args, **kwargs):
#        """messages which are emitted as a normal course of operation, but which
#        happen infrequently, perhaps once every ten to one hundred seconds. User
#        actions like triggering an upload or sending a message fall into this
#        category."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.INFREQUENT
#        return log.msg(msg, *args, **kwargs)
#
#    def unusual(self, msg, *args, **kwargs):
#        """messages which indicate events that are not normal, but not
#        particularly fatal. Examples include excessive memory or CPU usage,
#        minor errors which can be corrected by fallback code."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.UNUSUAL
#        return log.msg(msg, *args, **kwargs)
#    error = unusual
#
#    def operational(self, msg, *args, **kwargs):
#        """messages which are emitted as a normal course of operation, like all
#        the steps involved in uploading a file, potentially one to ten per
#        second."""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.OPERATIONAL
#        return log.msg(msg, *args, **kwargs)
#    info = operational
#
#    def noisy(self, msg, *args, **kwargs):
#        """verbose debugging about small operations, potentially emitting tens
#        or hundreds per second"""
#        if 'facility' not in kwargs:
#            kwargs['facility'] = self.facility
#        if 'level' not in kwargs:
#            kwargs['level'] = log.NOISY
#        return log.msg(msg, *args, **kwargs)
#    debug = noisy
#
#
def setup(config_dir):
    logs_dir = os.path.join(config_dir, 'logs')
    log.setLogDir(logs_dir)
#    log.bridgeLogsFromTwisted()
#
#def getLogger(name):
#    log.explain_facility(name, name.__doc__)
#    return Logging(name)

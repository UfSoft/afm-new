# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
"""
    afm.usage
    ~~~~~~~~~

    This module is responsible for console usage options.

    :copyright: © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
    :license: BSD, see LICENSE for more details.
"""

from sys import argv, exit
from os.path import abspath, basename, expanduser
from twisted.python import usage, reflect, util

from afm import __version__, config

class SysExit(BaseException):
    def __init__(self, msg, *args, **kwargs):
        BaseException.__init__(self, msg % args % kwargs)
        print msg % args % kwargs
        exit(kwargs.pop('code', 1))

class RawUsageOptions(usage.Options):

    # Hack Start
    def loadConfigFileOptions(self, subCommand):
        dont_dispatch = ['help', 'version']
        if hasattr(self, 'parser'):
            for key in self.defaults.iterkeys():
                if self.parser.has_section(subCommand) and \
                                    self.parser.has_option(subCommand, key):
                    config_value = self.parser.get(subCommand, key)
                    self.defaults[key] = config_value

                    if key not in dont_dispatch:
                        try:
                            if callable(self._dispatch[key]):
                                self._dispatch[key](key, config_value)
                            else:
                                self._dispatch[key].dispatch(key, config_value)
                        except SysExit:
                            print "Option error in configuration file under",
                            print "the section %s variable %s" % (subCommand,
                                                                  key)
                            raise
#                        if key not in self.opts:
#                            self.opts[key] = self.opts[key] = config_value
#                    else:
#                        self.defaults[key] = config_value
                elif self.parser.has_section('certs-common') and \
                                self.parser.has_option('certs-common', key):
                    config_value = self.parser.get('certs-common', key)
                    self.defaults[key] = config_value
                    if key not in dont_dispatch:
                        try:
                            if callable(self._dispatch[key]):
                                self._dispatch[key](key, config_value)
                            else:
                                self._dispatch[key].dispatch(key, config_value)
                        except SysExit:
                            print "Option error in configuration file under",
                            print "the section %s variable %s" % (subCommand,
                                                                  key)
                            raise

#                        if key not in self.opts:
#                            self.opts[key] = self.opts[key] = config_value
#                    else:
#                        self.defaults[key] = self.opts[key] = config_value
#                        # Also update opts
##                        self.opts[key] = self.defaults[key]
#            # Command specific overrides
#            if self.parser.has_section(subCommand):
#                for key in self.defaults.iterkeys():
#                    if self.parser.has_option(subCommand, key):
#                        self.defaults[key] = self.parser.get(subCommand, key)
#                        if key not in dont_dispatch:
#                            self._dispatch[key].dispatch(key, self.defaults[key])
    # Hack End

    def parseOptions(self, options=None):
        """
        The guts of the command-line parser.
        """


        if options is None:
            options = usage.sys.argv[1:]
        try:
            opts, args = usage.getopt.getopt(options,
                                             self.shortOpt, self.longOpt)
        except usage.getopt.error, e:
            raise usage.UsageError(str(e))

        for opt, arg in opts:
            if opt[1] == '-':
                opt = opt[2:]
            else:
                opt = opt[1:]

            optMangled = opt
            if optMangled not in self.synonyms:
                optMangled = opt.replace("-", "_")
                if optMangled not in self.synonyms:
                    raise usage.UsageError("No such option '%s'" % (opt,))

            optMangled = self.synonyms[optMangled]

            if isinstance(self._dispatch[optMangled], usage.CoerceParameter):
                self._dispatch[optMangled].dispatch(optMangled, arg)
            else:
                self._dispatch[optMangled](optMangled, arg)

        if (getattr(self, 'subCommands', None)
            and (args or self.defaultSubCommand is not None)):
            if not args:
                args = [self.defaultSubCommand]
            sub, rest = args[0], args[1:]
            for (cmd, short, parser, doc) in self.subCommands:
                if sub == cmd or sub == short:
                    self.subCommand = cmd
                    self.subOptions = parser()
                    self.subOptions.parent = self
                    # Hack Start
                    if hasattr(self, 'parser'):
                        self.subOptions.parser = self.parser
                    self.subOptions.loadConfigFileOptions(cmd)
                    # Hack End
                    self.subOptions.parseOptions(rest)
                    break
            else:
                raise usage.UsageError("Unknown command: %s" % sub)
        else:
            try:
                self.parseArgs(*args)
            except TypeError:
                raise usage.UsageError("Wrong number of arguments.")

        self.postOptions()


    def opt_version(self):
        """Show version"""
        print basename(argv[0]), '- %s' % __version__
    opt_v = opt_version

    def opt_help(self):
        """Show this help message"""
        usage.Options.opt_help(self)
    opt_h = opt_help

    def postOptions(self):
        self.parent.postOptions()
        self.executeCommand()

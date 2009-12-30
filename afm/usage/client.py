# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================

from twisted.internet import reactor

from afm.protocol.client import Client
from afm.usage import RawUsageOptions, SysExit

class ClientOptions(RawUsageOptions):
    "Run Client"
    longdesc = __doc__

    optParameters = [
        ["port", "p", 58846, "Server Port", int],
        ["host", "H", "localhost", "Server hostname"],
    ]

    def opt_port(self, port):
        self.opts['port'] = int(port)

    def executeCommand(self):
        client = Client()
        client.connect(self.opts['host'], self.opts['port'])
        reactor.run()

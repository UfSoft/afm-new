# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================

from twisted.internet import reactor

from afm.protocol.server import RPCServer
from afm.usage import RawUsageOptions, SysExit

class ServerOptions(RawUsageOptions):
    "Run Server"
    longdesc = __doc__

    optParameters = [
        ["port", "p", 58846, "Port to bind to", int],
        ["interface", "i", None, "Interface to bind to"],
    ]

    def opt_port(self, port):
        self.opts['port'] = int(port)

    def executeCommand(self):
        server = RPCServer(int(self.opts['port']), self.opts['interface'] or '')
        reactor.run()

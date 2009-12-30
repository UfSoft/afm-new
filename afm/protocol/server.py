#
# rpcserver.py
#
# Copyright (C) 2008,2009 Andrew Resch <andrewresch@gmail.com>
# Copyright (C) 2009 Pedro Algarvio <ufs@ufsoft.org>
#
# Deluge is free software.
#
# You may redistribute it and/or modify it under the terms of the
# GNU General Public License, as published by the Free Software
# Foundation; either version 3 of the License, or (at your option)
# any later version.
#
# deluge is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with deluge.    If not, write to:
#     The Free Software Foundation, Inc.,
#     51 Franklin Street, Fifth Floor
#     Boston, MA  02110-1301, USA.
#
#    In addition, as a special exception, the copyright holders give
#    permission to link the code of portions of this program with the OpenSSL
#    library.
#    You must obey the GNU General Public License in all respects for all of
#    the code used other than OpenSSL. If you modify file(s) with this
#    exception, you may extend this exception to your version of the file(s),
#    but you are not obligated to do so. If you do not wish to do so, delete
#    this exception statement from your version. If you delete this exception
#    statement from all source files in the program, then also delete it here.
#
#

"""RPCServer Module"""

import sys
import logging

from twisted.internet.protocol import Factory
from twisted.internet import reactor

from afm import config
from afm.protocol import AfmRPCProtocol, RPC_EVENT, ServerContextFactory

log = logging.getLogger(__name__)

class RPCServer(object):
    """
    This class is used to handle rpc requests from the client.  Objects are
    registered with this class and their methods are exported using the export
    decorator.

    :param port: the port the RPCServer will listen on
    :type port: int
    :param interface: the interface to listen on
    :type interface: str
    """

    def __init__(self, port=58846, interface=""):

        self.factory = Factory()
        self.factory.protocol = AfmRPCProtocol
        # Holds the registered methods
        self.factory.methods = {}
        # Holds the session_ids and auth levels
        self.factory.authorized_sessions = {}
        # Holds the protocol objects with the session_id as key
        self.factory.session_protocols = {}
        # Holds the interested event list for the sessions
        self.factory.interested_events = {}

        hostname = ""

        if interface:
            hostname = interface

        log.info("Starting DelugeRPC server %s:%s", hostname, port)

        try:
            reactor.listenSSL(port, self.factory, ServerContextFactory(),
                              interface=hostname)
        except Exception, e:
            log.info("Daemon already running or port not available..")
            log.error(e)
            sys.exit(0)

    def register_object(self, obj, name=None):
        """
        Registers an object to export it's rpc methods.  These methods should
        be exported with the export decorator prior to registering the object.

        :param obj: the object that we want to export
        :type obj: object
        :param name: the name to use, if None, it will be the class name of the object
        :type name: str
        """
        if not name:
            name = obj.__class__.__name__.lower()

        for d in dir(obj):
            if d[0] == "_":
                continue
            if getattr(getattr(obj, d), '_rpcserver_export', False):
                log.debug("Registering method: %s", name + "." + d)
                self.factory.methods[name + "." + d] = getattr(obj, d)

    def get_object_method(self, name):
        """
        Returns a registered method.

        :param name: the name of the method, usually in the form of 'object.method'
        :type name: str

        :returns: method

        :raises KeyError: if `name` is not registered

        """
        return self.factory.methods[name]

    def get_method_list(self):
        """
        Returns a list of the exported methods.

        :returns: the exported methods
        :rtype: list
        """
        return self.factory.methods.keys()

    def emit_event(self, event):
        """
        Emits the event to interested clients.

        :param event: the event to emit
        :type event: :class:`deluge.event.DelugeEvent`
        """
        log.debug("intervents: %s", self.factory.interested_events)
        # Find sessions interested in this event
        for session_id, interest in self.factory.interested_events.iteritems():
            if event.name in interest:
                log.debug("Emit Event: %s %s", event.name, event.args)
                # This session is interested so send a RPC_EVENT
                self.factory.session_protocols[session_id].sendData(
                    (RPC_EVENT, event.name, event.args)
                )


if __name__ == '__main__':
    server = RPCServer()

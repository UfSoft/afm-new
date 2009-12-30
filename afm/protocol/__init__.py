# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================

import sys
import zlib
import logging
import traceback
from OpenSSL import crypto, SSL
from twisted.internet import defer, reactor
from twisted.internet.protocol import Protocol

from afm.protocol import rencode
from afm import config

log = logging.getLogger(__name__)


RPC_RESPONSE = 1
RPC_ERROR = 2
RPC_EVENT = 3

def export():
    """
    Decorator function to register an object's method as an RPC.  The object
    will need to be registered with an :class:`RPCServer` to be effective.

    :param func: the function to export
    :type func: function
    :param auth_level: the auth level required to call this method
    :type auth_level: int

    """
    def wrap(func, *args, **kwargs):
        func._rpcserver_export = True
        doc = func.__doc__
        func.__doc__ = "**RPC Exported Function**"
        if doc:
            func.__doc__ += doc

        return func
    return wrap

class AFMError(Exception):
    pass

class NotAuthorizedError(AFMError):
    pass


class ServerContextFactory(object):
    def getContext(self):
        """
        Create an SSL context.

        This loads the servers cert/private key SSL files for use with the
        SSL transport.
        """
        ctx = SSL.Context(SSL.SSLv3_METHOD)
        ctx.use_certificate_file(config.server.certificate)
        ctx.use_privatekey_file(config.server.private_key)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       self.verify_certificate)
        # Since we have self-signed certs we have to explicitly
        # tell the server to trust them.
        ctx.load_verify_locations(config.server.root_ca)
        return ctx

    def verify_certificate(self, connection, x509, errnum, errdepth, ok):
        if not ok:
            log.warn('invalid cert from subject: %s', x509.get_subject())
            return False
        else:
            log.debug("Certs are fine")
        return True


class ClientContextFactory(object):
    def getContext(self):
        """
        Create an SSL context.

        This loads the servers cert/private key SSL files for use with the
        SSL transport.
        """
        ctx = SSL.Context(SSL.SSLv3_METHOD)
        ctx.use_certificate_file(config.client.certificate)
        ctx.use_privatekey_file(config.client.private_key)
        return ctx


class AfmRPCProtocol(Protocol):
    __buffer = None

    transport = factory = None

    def dataReceived(self, data):
        """
        This method is called whenever data is received from a client.  The
        only message that a client sends to the server is a RPC Request message.
        If the RPC Request message is valid, then the method is called in a thread
        with :meth:`dispatch`.

        :param data: the data from the client. It should be a zlib compressed
            rencoded string.
        :type data: str

        """
        if self.__buffer:
            # We have some data from the last dataReceived() so lets prepend it
            data = self.__buffer + data
            self.__buffer = None

        while data:
            dobj = zlib.decompressobj()
            try:
                request = rencode.loads(dobj.decompress(data))
            except Exception, e:
                #log.debug("Received possible invalid message (%r): %s", data, e)
                # This could be cut-off data, so we'll save this in the buffer
                # and try to prepend it on the next dataReceived()
                self.__buffer = data
                return
            else:
                data = dobj.unused_data

            if type(request) is not tuple:
                log.debug("Received invalid message: type is not tuple")
                return

            if len(request) < 1:
                log.debug("Received invalid message: there are no items")
                return

            for call in request:
                if len(call) != 4:
                    log.debug("Received invalid rpc request: number of items "
                              "in request is %s", len(call))
                    continue

                # Format the RPCRequest message for debug printing
                try:
                    s = call[1] + "("
                    if call[2]:
                        s += ", ".join([str(x) for x in call[2]])
                    if call[3]:
                        if call[2]:
                            s += ", "
                        s += ", ".join([key + "=" + str(value) for key, value in
                                        call[3].items()])
                    s += ")"
                except UnicodeEncodeError:
                    log.debug("RPCRequest had some non-ascii text..")
                    pass
                else:
                    log.debug("RPCRequest: %s", s)
                    pass

                reactor.callLater(0, self.dispatch, *call)

    def sendData(self, data):
        """
        Sends the data to the client.

        :param data: the object that is to be sent to the client.  This should
            be one of the RPC message types.

        """
        self.transport.write(zlib.compress(rencode.dumps(data)))

    def connectionMade(self):
        """
        This method is called when a new client connects.
        """
        peer = self.transport.getPeer()
        log.info("Deluge Client connection made from: %s:%s", peer.host, peer.port)
        # Set the initial auth level of this session to AUTH_LEVEL_NONE
        self.factory.authorized_sessions[self.transport.sessionno] = {}

    def connectionLost(self, reason):
        """
        This method is called when the client is disconnected.

        :param reason: the reason the client disconnected.
        :type reason: str

        """

        # We need to remove this session from various dicts
        del self.factory.authorized_sessions[self.transport.sessionno]
        if self.transport.sessionno in self.factory.session_protocols:
            del self.factory.session_protocols[self.transport.sessionno]
        if self.transport.sessionno in self.factory.interested_events:
            del self.factory.interested_events[self.transport.sessionno]

        log.info("Deluge client disconnected: %s", reason.value)

    def dispatch(self, request_id, method, args, kwargs):
        """
        This method is run when a RPC Request is made.  It will run the local method
        and will send either a RPC Response or RPC Error back to the client.

        :param request_id: the request_id from the client (sent in the RPC Request)
        :type request_id: int
        :param method: the local method to call. It must be registered with
            the :class:`RPCServer`.
        :type method: str
        :param args: the arguments to pass to `method`
        :type args: list
        :param kwargs: the keyword-arguments to pass to `method`
        :type kwargs: dict

        """
        def sendError():
            """
            Sends an error response with the contents of the exception that was raised.
            """
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()

            self.sendData((
                RPC_ERROR,
                request_id,
                (exceptionType.__name__,
                exceptionValue.args[0] if len(exceptionValue.args) == 1 else "",
                "".join(traceback.format_tb(exceptionTraceback)))
            ))

        if method == "daemon.set_event_interest" and \
                self.transport.sessionno in self.factory.authorized_sessions:
            # This special case is to allow clients to set which events they are
            # interested in receiving.
            # We are expecting a sequence from the client.
            try:
                if self.transport.sessionno not in self.factory.interested_events:
                    self.factory.interested_events[self.transport.sessionno] = []
                self.factory.interested_events[self.transport.sessionno].extend(args[0])
            except Exception, e:
                sendError()
            else:
                self.sendData((RPC_RESPONSE, request_id, (True)))
            finally:
                return

        if method in self.factory.methods and \
                self.transport.sessionno in self.factory.authorized_sessions:
            try:
                method_auth_requirement = self.factory.methods[method]._rpcserver_auth_level
                auth_level = self.factory.authorized_sessions[self.transport.sessionno]
                if auth_level < method_auth_requirement:
                    # This session is not allowed to call this method
                    log.debug("Session %s is trying to call a method it is not "
                              "authorized to call!", self.transport.sessionno)
                    raise NotAuthorizedError(
                        "Auth level too low: %s < %s" %
                        (auth_level, method_auth_requirement)
                    )
                ret = self.factory.methods[method](*args, **kwargs)
            except Exception, e:
                sendError()
                # Don't bother printing out DelugeErrors, because they are just for the client
                if not isinstance(e, AFMError):
                    log.exception("Exception calling RPC request: %s", e)
            else:
                # Check if the return value is a deferred, since we'll need to
                # wait for it to fire before sending the RPC_RESPONSE
                if isinstance(ret, defer.Deferred):
                    def on_success(result):
                        self.sendData((RPC_RESPONSE, request_id, result))
                        return result

                    def on_fail(failure):
                        try:
                            failure.raiseException()
                        except Exception, e:
                            sendError()
                        return failure

                    ret.addCallbacks(on_success, on_fail)
                else:
                    self.sendData((RPC_RESPONSE, request_id, ret))

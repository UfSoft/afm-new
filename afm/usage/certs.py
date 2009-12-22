#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2008 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# Please view LICENSE for additional licensing information.
# ==============================================================================

import os
import sys
import stat
import random
import getpass
import itertools

from twisted.python import usage, util, reflect
from OpenSSL import crypto

from afm import config
from afm.database import db, Certificate
from afm.usage import RawUsageOptions, SysExit

def ask_password(calledback=None):
    try:
        if calledback is not None:
            return getpass.getpass("Please enter the signing certificate "
                                   "password:")

        # It's not a password being requested, it's a password to define
        passwd = getpass.getpass("Define a password for the new private key "
                                 "(leave empty for none):")
        if not passwd:
            return None
        verify_password = getpass.getpass("Verify Password:")
        if passwd != verify_password:
            print "Passwords do not match. Exiting..."
            sys.exit(1)
        return passwd
    except KeyboardInterrupt:
        sys.exit(1)

class BaseOptions(RawUsageOptions):
    x509names = {
              "common-name": "commonName",
             "organization": "organizationName",
        "organization-unit": "organizationalUnitName",
                 "locality": "localityName",
        "state-or-province": "stateOrProvinceName",
                  "country": "countryName",
                    "email": "emailAddress"
    }


class BaseCertOptions(BaseOptions):
    optParameters = [
        ["cert-name", None, "newcert.pem", "Certificate Name"],
        ["common-name", None, "NewCert", "The Certificate common name"],
        ["organization", None, None, "Organization Name"],
        ["organization-unit", None, None, "Organisation Unit Name"],
        ["locality", None, None, "Locality Name"],
        ["state-or-province", None, None, "State or Province Name"],
        ["country", None, None, "Two(2) Letter Country Name"],
        ["email", None, None, "Email Address"],
        ["years", None, 5, "Years to expire", int]
    ]

    def updateDestinguishedName(self, subject):
        DN = {}
        parameters = []
        reflect.accumulateClassList(self.__class__, 'optParameters', parameters)
        for parameter in parameters:
            key, short, val, doc, _type = util.padTo(5, parameter)
            if self.opts[key]:
                val = _type and _type(self.opts[key]) or self.opts[key]
            elif self.defaults[key]:
                val = _type and _type(self.defaults[key]) or self.defaults[key]
            if key == 'years':
                val = 60 * 60 * 24 * 365 * val
            if val and key in self.x509names:
                try:
                    setattr(subject, self.x509names.get(key), val.strip())
                except crypto.Error, err:
                    raise SysExit("Setting value of '%s' failed: %s",
                                  key, err[0][0][2])
                DN[self.x509names.get(key)] = val.strip()

        if not subject.commonName:
            raise SysExit("Common Name for certificate not defined.\n"
                          "You must pass at least a non empty --common-name")
        return subject

    def generatePrivateKey(self):
        privateKey = crypto.PKey()
        privateKey.generate_key(crypto.TYPE_RSA, 1024)
        password = ask_password()
        encryption_args = password and ["DES-EDE3-CBC", password] or []
        privateKeyData = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                                privateKey,
                                                *encryption_args)
        return privateKey, privateKeyData.strip()

    def generateCertificateRequest(self, privateKey):
        certReq = crypto.X509Req()
        subject = self.updateDestinguishedName(certReq.get_subject())
        certReq.set_pubkey(privateKey)
        certReq.sign(privateKey, "md5")
        return certReq

    def generateCertificate(self, privateKey, serial,
                            issuer=None, issuerPrivateKey=None):

        cert = crypto.X509()
        cert.set_subject(self.updateDestinguishedName(cert.get_subject()))
        cert.set_pubkey(privateKey)
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.opts.get('years'))
        if not issuer and not issuerPrivateKey:
            # Generating a RootCA
            cert.set_issuer(self.updateDestinguishedName(cert.get_subject()))
            cert.add_extensions([
                crypto.X509Extension('basicConstraints', True,
                                     'CA:TRUE, pathlen:0')
            ])
            cert.sign(privateKey, "md5")
        elif issuer and issuerPrivateKey:
            cert.set_issuer(issuer)
            cert.sign(issuerPrivateKey, "md5")
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).strip()

    def get_next_serial(self):
        serial = db.session().query(db.func.max(Certificate.serial)).first()[0]
        if not serial:
            return random.randint(1000, 10000)
        return serial+1

    def opt_years(self, years):
        years = int(years)
        if years < 1:
            raise SysExit("Certificate will need to be valid for at least one "
                          "year")
        self.opts['years'] = 60 * 60 * 24 * 365 * years

    def opt_country(self, country):
        if len(country) > 2:
            raise SysExit("Please use the short name of your country, for USA "
                          "it's US")
        self.opts['country'] = country

    def executeCommand(self):
        raise NotImplementedError


class NewCA(BaseCertOptions):
    longdesc = """Create a new root certificate which will be used to issue both
    server and client certificates which are then use in authentication."""

    optParameters = [
        ["start-serial", None, random.randint(1000, 10000),
         "Initial serial sequence number. If not provided a default random one "
         "will be generated.", int],
        ["common-name", None, "Root CA", "The Root CA common name"],
    ]

    def executeCommand(self):
        session = db.session()
#        if session.query(Certificate).filter_by(root_ca=True).count():
#            print "You already have a root CA generated!"
#            print "For now we can only have one."
#            sys.exit(1)

        serial = self.get_next_serial() or self.opts['start-serial']
        private_key, private_key_data = self.generatePrivateKey()
        certificate = self.generateCertificate(private_key, serial)
        root_ca = Certificate(serial, certificate, private_key_data,
                              root_ca=True)
        session.add(root_ca)
        session.commit()
        sys.exit(0)

class NewCert(BaseCertOptions):
    longdesc = "Create a new certificate which will be signed by the root CA."

    optParameters = [
        ["rootca", None, None, "The RootCA ID.", int],
    ]

    def opt_rootca(self, cert_id):
        self.opts['rootca'] = int(cert_id)

    def executeCommand(self):
        session = db.session()
        if self.opts['rootca']:
            root_ca = session.query(Certificate).get(self.opts['rootca'])
            if not root_ca:
                raise SysExit("Root CA with the ID %d was not found!",
                              self.opts['rootca'])
            elif root_ca and not root_ca.root_ca:
                raise SysExit("A certificate with the ID %d was found"
                              "but it's not a Root CA. It cannot be used to "
                              "sign other certificates.", self.opts['rootca'])
        else:
            root_ca = session.query(Certificate).filter_by(root_ca=True)
            root_ca_count = root_ca.count()
            if not root_ca_count:
                raise SysExit("No Root CA was found on the database!")
                sys.exit(1)
            elif root_ca_count > 1:
                raise SysExit("There is more than one Root CA in the "
                              "database.\nYou need to specify the ID of the "
                              "Root CA certificate to use")
            root_ca = root_ca.first()

        rootCaCert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                             root_ca.certificate)

        try:
            rootPrivateKey = crypto.load_privatekey(
                crypto.FILETYPE_PEM, root_ca.private_key, ask_password
            )
        except crypto.Error, error:
            raise SysExit("Private key needs password and wrong password "
                          "entered:", error[0][0][2])

        print "Generating new private key"
        serial = self.get_next_serial()
        privateKey, privateKeyData = self.generatePrivateKey()
        print "Generating new certificate"
        content = self.generateCertificate(privateKey, serial,
                                           issuer=rootCaCert.get_issuer(),
                                           issuerPrivateKey=rootPrivateKey)
        certificate = Certificate(serial, content, privateKeyData,
                                  issuer=root_ca)
        session.add(certificate)
        session.commit()
        print "Done"
        sys.exit(0)


#class SignCert(BaseOptions):
#    longdesc = """Sign an already created certificate pair with the root CA."""
#
#    optParameters = [
#        ["cert-name", None, "newcert.pem", "Certificate Name"],
#        ["rootca-pk-file", None, "./.ssh/private/cakey.pem",
#         "The Root CA private key file"],
#        ["cacert", None, "./.ssh/cacert.pem",
#         "The Root CA certificate file path"]
#    ]
#
#    def executeCommand(self):
#        print "This command does not currently do anything"
#        sys.exit(0)

class ExportCerts(BaseOptions):
    longdesc = """Export certificates in store"""

    optParameters = [
        ["output", "o", './certificate.pem', "Output certificate path"],
        ["id", "i", None, "certificate id", int],
    ]
    optFlags = [
        ["include-private-key", "I", "Include Certificate's private key."]
    ]

    writeMode = 'w'

    def opt_id(self, cert_id):
        self.opts['id'] = int(cert_id)

    def executeCommand(self):
        if not self.opts['id']:
            raise SysExit("You must specify which certificate you wish to "
                          "export")
        cert = db.session().query(Certificate).get(self.opts['id'])
        if not cert:
            raise SysExit("Certificate with the ID %d not found",
                          self.opts['id'])

        print 'Exporting certificate with id %i to "%s" ...' % (
            cert.cert_id, self.opts['output'])

        if self.opts.get('include-private-key'):
            print "including private-key ...",
            open(self.opts['output'],
                 self.writeMode).write(cert.private_key + '\n')
            self.writeMode = 'a'

        open(self.opts['output'],
             self.writeMode).write(cert.certificate + '\n')
        print "Done."
        sys.exit(0)


class ListCerts(BaseOptions):
    longdesc = """List certificates in store"""

    def executeCommand(self):
        session = db.session()
        certificates = session.query(Certificate).all()
        if not certificates:
            raise SysExit("There are no certificates currently stored on the "
                          "database.", code=0)
        maxid = max([len(str(c.cert_id)) for c in certificates])
        maxserial = max([len(c.root_ca and "*%s" % c.serial or
                             str(c.serial)) for c in certificates]
                        + [len('Serial')])
        maxCN = max([len(c.subject.CN) for c in certificates] +
                    [len("Common Name")])
        maxIS = max([c.issuer and len(c.issuer.subject.CN) or 0
                     for c in certificates] + [len("Issuer (Root CA ID)")])
        format = ' %%s %%-%ds | %%-%ds | %%-%ds | %%-%ds' % (
            maxid, maxserial, maxCN, maxIS)
        header = format % ('', 'ID', 'Serial', 'Common Name',
                           "Issuer (Root CA ID/Serial)")
        print
        print header
        print '-'*len(header)
        for cert in certificates:
            print format % (cert.root_ca and "*"  or ' ',
                            cert.cert_id, cert.serial, cert.subject.CN,
                            cert.issuer and cert.issuer.subject.CN + (" (%s/%s)" %
                                (cert.issuer.cert_id, cert.issuer.serial)
                            or ''))
        print '\n * - Root Certificate\n'
        sys.exit(0)

class DeleteCerts(BaseOptions):
    longdesc = """Delete certificates in store"""

    optParameters = [
        ["id", "i", None, "certificate id", int],
    ]

    def opt_id(self, cert_id):
        self.opts['id'] = int(cert_id)

    def executeCommand(self):
        if not self.opts['id']:
            raise SysExit("You must specify which certificate you wish to "
                          "delete")

        session = db.session()
        cert = session.query(Certificate).get(self.opts['id'])
        if not cert:
            raise SysExit("Certificate with the ID %d not found",
                          self.opts['id'])
        print "Deleting certificate with the ID %d" % cert.cert_id
        session.delete(cert)
        session.commit()
        raise SysExit("Done", code=0)

class CertsCreatorOptions(BaseOptions):
    """Certificates Manager"""

    subCommands = [
        ["newca", None, NewCA, "Create new Root CA"],
        ["newcert", None, NewCert, "Create new certificate"],
        ["list", None, ListCerts, "List certificates in store"],
        ["export", None, ExportCerts, "Export certificates in store"],
#        ["sign", None, SignCert, "Sign an already created certificate"]
        ["delete", None, DeleteCerts, "Delete certificates in store"]
    ]

    def executeCommand(self):
        if not self.subCommand:
            self.opt_help()


if __name__ == '__main__':
    runner = CertsCreatorOptions()
    try:
        runner.parseOptions() # When given no argument, parses sys.argv[1:]
    except usage.UsageError, errortext:
        print '%s: %s' % (sys.argv[0], errortext)
        print '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)

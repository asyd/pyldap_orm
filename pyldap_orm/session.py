# Authors: Bruno Bonfils
# Copyright: Bruno Bonfils
# License: Apache License version2

import ldap
import logging
import warnings
import os

from pyldap_orm.exceptions import LDAPSessionException

logger = logging.getLogger(__name__)


class LDAPSession(object):
    """
    Create a LDAPSession by connecting to the LDAP server.

    Tested servers:
      - OpenDJ
      - OpenLDAP

    A basic usage looks like:

    >>> session = LDAPSession(backend='ldap://localhost:389', mode=LDAPSession.STARTTLS)
    >>> session.authenticate('cn=admin,dc=example,dc=com', 'password')

    You can also bind as anonymous:

    >>> session.authenticate()

    :param backend: a LDAP URI like ``ldaps?://host(:port)?``
    :param mode: Transport mode, must be LDAPSession.PLAIN (the default), LDAPSession.STARTTLS or LDAPSession.LDAPS
    :param cert: An optional client certificate, in PEM format
    :param key: The client certificate related private key, in PEM format with no password
    :param cacertdir: Directory of CA certificates, default is /etc/ssl/certs
    """
    PLAIN = 0
    STARTTLS = 1
    LDAPS = 2

    AUTH_SIMPLE_BIND = 0
    AUTH_SASL_EXTERNAL = 1

    bind_dn = None
    credential = None
    backend = None

    def __init__(self, backend, mode=PLAIN,
                 cert=None,
                 key=None,
                 cacertdir='/etc/ssl/certs',
                 ):

        self.backend = backend
        self._server = None
        self._schema = {}
        self._cert = cert
        self._key = key

        logger.debug("LDAP _session created, id: {}".format(id(self)))

        # Switch to LDAPS mode if ldaps is backend start with 'ldaps'
        if 'ldaps' == backend[:5].lower():
            mode = self.LDAPS

        # Set CACERTDIR and REQUIRED_CERT to TLS_DEMAND (validation required) if needed
        if mode in (self.STARTTLS, self.LDAPS) and cacertdir is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, cacertdir)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

        if cacertdir is None:
            warnings.warn("You are in INSECURE mode", ImportWarning, stacklevel=2)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        # Set client certificate if both cert and key are provided
        if cert is not None and key is not None:
            if not os.path.isfile(cert):
                raise LDAPSessionException("Certificate file {} does not exist".format(cert))
            if not os.path.isfile(key):
                raise LDAPSessionException("Certificate key file {} does not exist".format(cert))
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, cert)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, key)

        self._server = ldap.initialize(self.backend, bytes_mode=False)

        # Proceed STARTTLS
        if mode == self.STARTTLS:
            self._server.start_tls_s()

    def authenticate(self, bind_dn=None, credential=None, mode=AUTH_SIMPLE_BIND):
        """
        Perform LDAP authentication and parse schema. This method is mandatory.

        :param bind_dn: optional string to perform a bind
        :param credential: optional string with the password of bind_dn
        :param mode: Can se LDAPSession.AUTH_SIMPLE_BIND (the default) or LDAPSession.AUTH_SASL_EXTERNAL
        """
        if mode == self.AUTH_SIMPLE_BIND:
            if bind_dn is not None and credential is not None:
                logger.debug("LDAP _session: bind as {}".format(bind_dn))
                self._server.simple_bind_s(bind_dn, credential)
            else:
                logger.debug("LDAP _session: bind as anonymous")
                self._server.simple_bind_s()
        elif mode == self.AUTH_SASL_EXTERNAL:
            if self._cert is None or self._key is None:
                raise LDAPSessionException(
                    "Client certificate and key must be provided to use SASL_EXTERNAL authentication")
            else:
                self._server.sasl_bind_s(None, 'EXTERNAL', None)

        self.parse_schema()

    @property
    def server(self):
        return self._server

    def search(self, base, scope=ldap.SCOPE_SUBTREE, ldap_filter='(objectClass=*)', attributes=None,
               serverctrls=None):
        """
        Perform a low level LDAP search (synchronous) using the given arguments.

        :param base: Base DN of the search
        :param scope: Scope of the search, default is SCOPE_SUBTREE
        :param ldap_filter: ldap filter, default is '(objectClass=*)'
        :param attributes: An array of attributes to return, default is ['*']
        :param serverctrls: An array server extended controls
        :return: a list of tuples (dn, attributes)
        """
        if serverctrls is None:
            logger.debug("Performing LDAP search: base: {}, scope: {}, filter: {}".format(base, scope, ldap_filter))
            return self._server.search_s(base, scope, ldap_filter, attributes)
        else:
            logger.debug("Performing ext LDAP search: base: {}, scope: {}, filter: {}, serverctrls={}".
                         format(base,
                                scope,
                                ldap_filter,
                                serverctrls))
            return self._server.search_ext_s(base, scope, ldap_filter, attrlist=attributes,
                                             serverctrls=serverctrls)

    def whoami(self):
        return self.server.whoami_s().split(':')[1]

    def parse_schema(self):
        """
        Create ``self.schema['attributes']`` dictionary where values are a tuple holding the syntax oid and a boolean
        (true if the attribute is single valued).
        """

        def get_attribute_syntax(attr_name):
            """
            Get some information about an attributeType, directly or by a potential inheritance.

            :param attr_name: Name of the attribute
            :return: a tuple with (SYNTAX_OID, Boolean) where boolean is True if the attribute is single valued.
            """
            attribute = schema.get_obj(ldap.schema.AttributeType, attr_name)
            if attribute.syntax is None:
                return get_attribute_syntax(attribute.sup[0])
            return attribute.syntax, attribute.single_value

        self._schema['attributes'] = {}
        self._schema['objectClass'] = {}
        # TODO: base must be discovered from server (using subSchemaEntry)
        request = self.server.search_s(base='cn=schema', scope=ldap.SCOPE_BASE, attrlist=['+'])
        schema = ldap.schema.SubSchema(request[0][1])

        for attr in schema.tree(ldap.schema.AttributeType):
            definition = schema.get_obj(ldap.schema.AttributeType, attr)
            if definition is not None:
                syntax = get_attribute_syntax(definition.names[0])
                for attribute_name in definition.names:
                    self._schema['attributes'][attribute_name] = (syntax[0], definition.single_value)

        self._schema['attributes']['memberOf'] = ('1.3.6.1.4.1.1466.115.121.1.12', False)

    @property
    def schema(self):
        return self._schema

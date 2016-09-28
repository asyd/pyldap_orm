import ldap
import logging
from pyldap_orm.exceptions import catch_ldap_exception

logger = logging.getLogger(__name__)


class LDAPSession(object):
    """
    LDAPSession represents a connection to a LDAP server.

    This class also manage initial binding if required. If no credentials are given, an anonymous bind
    will be performed.

    Tested servers:
      - OpenDJ
      - OpenLDAP
    """
    PLAIN = 0
    STARTTLS = 1
    LDAPS = 2

    SASL_EXTERNAL = 1

    bind_dn = None
    credential = None
    backend = None

    def __init__(self, backend, bind_dn=None, credential=None, mode=PLAIN,
                 sasl=None,
                 cert=None,
                 key=None,
                 cacertdir='/etc/ssl/certs',
                 ):
        """
        Create a LDAPSession by connecting to the LDAP server, and perform optional initial bind if bind_dn and
        credential are defined, otherwise perform an anonymous bind.

        :param backend: a LDAP URI like ldap://host:port
        :param bind_dn:
        :param credential:
        :param mode: Transport mode, must be self.PLAIN (the default), self.STARTTLS or self.LDAPS
        :param sasl: SASL Mechanism mode (only EXTERNAL is supported in this version)
        :param cert: Client certificate (optional), must be in PEM format
        :param key: Certificate private key, must be in PEM format with no password
        :param cacertdir: Directory of CA certificates, default is /etc/ssl/certs
        """
        self.backend = backend
        self.bind_dn = bind_dn
        self._server = None

        logger.debug("LDAP _session created, id: {}".format(id(self)))

        # Switch to LDAPS mode if ldaps is backend start with 'ldaps'
        if 'ldaps' == backend[0 - 5]:
            mode = self.LDAPS

        # Set CACERTDIR and REQUIRED_CERT to TLS_DEMAND (validation required) if needed
        if mode in (self.STARTTLS, self.LDAPS) and cacertdir is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, cacertdir)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

        # Set client certificate is both cert and key are provided
        if cert is not None and key is not None:
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, cert)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, key)

        try:
            self._server = ldap.initialize(self.backend, bytes_mode=False)
        except ldap.LDAPError as e:
            catch_ldap_exception(e)

        # Proceed STARTTLS
        if mode == self.STARTTLS:
            try:
                self._server.start_tls_s()
            except ldap.LDAPError as e:
                catch_ldap_exception(e)

        # Perform a SASL binding with EXTERNAL mechanism if cert and key are provided
        if cert is not None and key is not None and sasl == self.SASL_EXTERNAL:
            try:
                # No need to set bind_dn and credential, the server will use the certificate to map a LDAP entry
                self._server.sasl_bind_s(None, 'EXTERNAL', None)
            except ldap.LDAPError as e:
                catch_ldap_exception(e)
        # Otherwise, use simple_bind_s
        else:
            if bind_dn is not None and credential is not None:
                logger.debug("LDAP _session: bind as {}".format(bind_dn))
                self._server.simple_bind_s(bind_dn, credential)
            else:
                logger.debug("LDAP _session: bind as anonymous")
                self._server.simple_bind_s()

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

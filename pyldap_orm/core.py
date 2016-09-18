"""
This is core of pyldap_orm.


:ref:`LDAPSession`

"""

import ldap
import ldap.modlist
import logging
import pyldap_orm.controls

logger = logging.getLogger(__name__)


class LDAPModelException(Exception):
    pass


class LDAPModelQueryException(LDAPModelException):
    pass


class LDAPSession(object):
    """
    LDAPSession represents a connection to a LDAP server. For the moment, only plain LDAP is supported.
    STARTTLS and TLS will be supported in the a future release.

    This class also manage initial binding if required. If no credentials are given, an anonymouns bind
    will be performed.

    Tested servers:
      - OpenDJ
      - OpenLDAP
    """
    bind_dn = None
    credential = None
    backend = None

    def __init__(self, backend, bind_dn=None, credential=None):
        """
        Create a LDAPSession by connecting to the LDAP server, and perform optional initial bind if bind_dn and
        credential are defined, otherwise perform an anonymous bind.

        :param backend: a LDAP URI like ldap://host:port
        :param bind_dn:
        :param credential:
        """
        self.backend = backend
        self.bind_dn = bind_dn
        self.credential = credential
        logger.debug("LDAP _session created, id: {}".format(id(self)))
        self._server = ldap.initialize(self.backend)
        if self.bind_dn is not None and self.credential is not None:
            logger.debug("LDAP _session: bind as {}".format(self.bind_dn))
            self._server.simple_bind_s(self.bind_dn, self.credential)
        else:
            logger.debug("LDAP _session: bind as anonymous")
            self._server.simple_bind_s()

    def search(self, base, scope=ldap.SCOPE_SUBTREE, ldap_filter='(objectClass=*)', attributes=None,
               sortattrs=None):
        """
        Perform a low level LDAP search (synchronous) using the given arguments.

        :param base: Base DN of the search
        :param scope: Scope of the search, default is SCOPE_SUBTREE
        :param ldap_filter: ldap filter, default is '(objectClass=*)'
        :param attributes: An array of attributes to return, default is ['*']
        :param sortattrs: An array of attributes to use for sort the result. Only used if you server support ...
        :return: a list of tuples (dn, attributes)
        """
        if sortattrs is None:
            logger.debug("Performing LDAP search: base: {}, scope: {}, filter: {}".format(base, scope, ldap_filter))
            return self._server.search_s(base, scope, ldap_filter, attributes)
        else:
            serverctrls = [pyldap_orm.controls.ServerSideSort(sortattrs)]
            logger.debug("Performing ext LDAP search: base: {}, scope: {}, filter: {}, sortattrs={}".
                         format(base,
                                scope,
                                ldap_filter,
                                serverctrls))
            return self._server.search_ext_s(base, scope, ldap_filter, attrlist=attributes,
                                             serverctrls=serverctrls)


class LDAPObject(object):
    """
    LDAPObject is one of the core class of the ORM. It represent an LDAP object.
    """
    name_attribute = 'cn'
    base = None
    filter = None
    required_attributes = []
    required_objectclasses = []

    STATUS_NEW = 1
    STATUS_SYNC = 2
    STATUS_MODIFIED = 3

    @classmethod
    def filter(cls):
        """
        Compute the filter regarding given required_attributes and required_objectclasses
        class attributes.

        :return: A string that hold the LDAP filter.
        """
        buffer = '(&'
        for attr in cls.required_attributes:
            buffer += '({}=*)'.format(attr)
        for oc in cls.required_objectclasses:
            buffer += '(objectClass={})'.format(oc)
        buffer += ')'
        return buffer

    def __init__(self, session):
        """
        :param session: a LDAPSession instance used to perform operations on a LDAP server.
        :type session: LDAPSession
        """
        self._attributes = dict()
        self._dn = None
        self._state = self.STATUS_NEW
        self._session = session

    def by_dn(self, dn, attributes=None):
        """
        Request an object by its DN.

        :param dn: DN of the LDAP object to query
        :param attributes: Optional array of attributes to returned, if none, all standard attributes are returned.
        :return: An instance of current LDAPObject inheritance
        """
        return self.parse_single(self._session.search(dn, scope=ldap.SCOPE_BASE, attributes=attributes))

    def by_attr(self, attr, value, attributes=None):
        """
        Search an object by adding a LDAP filter (&(..)(attr=value), where (..) is the search attribute
        model filter, like '(objectClass=inetOrgPerson)' for a user.

        :param attr: Attribute to search, like uid, givenName, etc.
        :param value: Attribute value
        :param attributes: Optional array of attributes to returned, if none, all standard attributes are returned.
        :return: an instance of class cls
        """
        entries = self._session.search(base=self.base,
                                       ldap_filter="(&{}({}={}))".format(self.filter(), attr, value),
                                       attributes=attributes)
        return self.parse_single(entries)

    def parse(self, entry):
        """
        This method fill attributes and dn of current instance.

        Then, the _check function is called to make some tests, like
        test if each required_attributes are present.

        :param entry: a LDAP entry
        """
        (dn, attributes) = entry
        self._dn = dn
        for attr in attributes.keys():
            self._attributes[attr] = [value.decode() for value in attributes[attr]]
        self.check()
        self._state = self.STATUS_SYNC
        return self

    def check(self):
        """
        Override this method to perform post operations like remove unwanted values or perform
        some business checks.

        For example, if you want to remove groups that doesn't belong to your LDAPGroup.base
        you can use the following code:

        .. code-block:: python

            for group in getattr(self, self.membership_attribute):
                if LDAPGroup.base not in group:
                getattr(self, self.membership_attribute).remove(group)

        """
        pass

    def parse_single(self, entries):
        """
        Parse the first entry of entries by calling parse instance method.

        :param entries:
        :return:
        :type entries: list
        """
        if len(entries) != 1:
            raise LDAPModelQueryException(
                "A query expected only single result returned {} entries".format(len(entries)))
        return self.parse(entries[0])

    def attributes(self):
        """
        Return the list of attributes existing for the current instance

        :return: List of attributes
        :rtype: list
        """
        return self._attributes.keys()

    def __getattr__(self, item):
        """
        Fallback for ldapModelInstance.attribute to return attribute value lists. Values comes from self._attributes.
        Every values returned are List instances.

        The only exception is for dn, which returns a single string.
        :param item: LDAP object attribute value
        :return: a list or a string when item is dn
        """
        if item == 'dn':
            return self._dn
        else:
            return self._attributes[item]

    def __setattr__(self, key, value):
        """
        Used to catch modifications on object to create a pyldap.modlist.

        If key is dn or start by a _, call the real __setattr__, else update the _attributes dictionnary.

        :param key: key to update
        :param value: new value
        """
        if key == 'dn' or key[0] == '_':
            object.__setattr__(self, key, value)
        else:
            if self._state >= self.STATUS_SYNC:
                self._state = self.STATUS_MODIFIED
            try:
                print("Old value: {}, new value: {}".format(self._attributes[key], value))
            except KeyError:
                print("Old value: None, new value: {}".format(value))
            self._attributes[key] = value


class LDAPModelList(object):
    """
    A list of LDAPObject instances
    """
    children = None  # type: LDAPObject
    filter = None

    def __init__(self, session=None):
        """
        Create a list of objects, each object will be an instance of self.children (expected a class than inherits
        of LDAPModel).

        :param session: An optional instance of LDAPSession. This parameter must be defined for methods that
         required access to the LDAP server, like search, bind, etc.
        :type session: LDAPSession
        """
        self._objects = list()
        self._dn = None
        self._session = session
        # TODO: check children

    def _parse_multiple(self, entries):
        for entry in entries:
            current = self.children(None).parse(entry)
            self._objects.append(current)
        return self._objects

    def all(self, sortattrs=None, attributes=None):
        entries = self._session.search(base=self.children.base,
                                       ldap_filter=self.children.filter(),
                                       scope=ldap.SCOPE_SUBTREE,
                                       attributes=attributes,
                                       sortattrs=sortattrs)
        return self._parse_multiple(entries)

    def by_attr(self, attr, value, attributes=None, sortattrs=None):
        """
        Search an object of class cls by adding a LDAP filter (&(..)(attr=value))

        :param attr:  Attribute to search
        :param value: Attribute value
        :param attributes: An optional array of the expected attributes returned by the search
        :param sortattrs: An optional array with attributes to request server side sorting
        :return: A list of self.children
        :rtype: list
        """
        entries = self._session.search(base=self.children.base,
                                       ldap_filter="(&{}({}={}))".format(self.children.filter(), attr, value),
                                       scope=ldap.SCOPE_SUBTREE,
                                       attributes=attributes,
                                       sortattrs=sortattrs)
        return self._parse_multiple(entries)

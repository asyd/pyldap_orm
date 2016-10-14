"""
This is core of pyldap_orm.
"""

# Authors: Bruno Bonfils
# Copyright: Bruno Bonfils
# License: Apache License version2

import logging

import ldap.modlist

from pyldap_orm.exceptions import *

logger = logging.getLogger(__name__)


class LDAPObject(object):
    """
    LDAPObject is one of the core class of the ORM. It represent an LDAP object.

    :param session: an optional LDAPSession instance used to perform operations on a LDAP server.
    :type session: LDAPSession
    """
    name_attribute = 'cn'
    base = None
    filter = None
    required_attributes = []
    required_objectclasses = []

    STATUS_NEW = 1
    STATUS_SYNC = 2
    STATUS_MODIFIED = 3

    OID_TO_STR = [
        '1.3.6.1.4.1.1466.115.121.1.12',  # DN
        '1.3.6.1.4.1.1466.115.121.1.15',  # Directory String
        '1.3.6.1.4.1.1466.115.121.1.26',  # IA String
        '1.3.6.1.4.1.1466.115.121.1.37',  # Object Class
        '1.3.6.1.4.1.1466.115.121.1.50',  # Telephone number
        '1.3.6.1.4.1.1466.115.121.1.38',  # OID
    ]

    OID_TO_INT = [
        '1.3.6.1.4.1.1466.115.121.1.27',  # Integer
    ]

    OID_TO_BOOL = [
        '1.3.6.1.4.1.1466.115.121.1.7',  # Boolean
    ]

    def __init__(self, session):
        self._attributes = dict()
        self._initial_attributes = None
        self._dn = None
        self._state = self.STATUS_NEW
        self._session = session

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
        # Save initial attributes values, used for ldapmodify
        self._initial_attributes = attributes
        for attr in attributes.keys():
            # Decode to string some attribute, regarding the syntax hey use
            if self._session.schema['attributes'][attr][0] in self.OID_TO_STR + self.OID_TO_INT + self.OID_TO_BOOL:
                self._attributes[attr] = [value.decode() for value in attributes[attr]]
                if self._session.schema['attributes'][attr][0] in self.OID_TO_INT:
                    self._attributes[attr] = [int(value) for value in attributes[attr]]
                if self._session.schema['attributes'][attr][0] in self.OID_TO_BOOL:
                    self._attributes[attr] = [value.upper() in ['TRUE', '1'] for value in attributes[attr]]
            else:
                self._attributes[attr] = attributes[attr]
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
        Every values returned are lists. The only exception is for dn, which returns a single string.

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

        If key is dn or start by a _, call object.__setattr__(), else update the _attributes dictionary.

        :param key: key to update
        :param value: new value
        """
        if key == 'dn':
            object.__setattr__(self, '_dn', value)
            # TODO: check status, if it's sync, it's a rename operation
        elif key[0] == '_':
            object.__setattr__(self, key, value)
        else:
            if self._state == self.STATUS_NEW:
                self._attributes[key] = value
            elif self._state in (self.STATUS_SYNC, self.STATUS_MODIFIED):
                self._state = self.STATUS_MODIFIED
                try:
                    if self._attributes[key] == value:
                        # Skip if there is no change (aka current value is equal the new value)
                        return
                except KeyError:
                    # It may be a new attribute
                    pass
                self._attributes[key] = value

    def save(self):
        """
        This method is a little magic. Depending on the object state you called it, it can create
        or update an existing object.

        There is even more magic when you create a new object. If the _dn attribute is not set (None),
        it will be computed from the name_attribute, and the base.

        If there is no objectClass defined, the required_objectclasses will be used.

        Last, verify that all attributes from required_attributes exists.

        """
        # Do nothing if state is not NEW or MODIFIED
        if self._state not in (self.STATUS_NEW, self.STATUS_MODIFIED):
            return

        if self._state == self.STATUS_MODIFIED:
            # If status is MODIFIED, compute a modifyModList from _initial_attributes and _attributes.
            raw_attributes = self._attributes
            # New to convert to bytes if values are in strings
            for attribute in raw_attributes.keys():
                if self._session.schema['attributes'][attribute][0] in self.OID_TO_BOOL + self.OID_TO_INT:
                    raw_attributes[attribute] = [str(value).lower() for value in raw_attributes[attribute]]

                if self._session.schema['attributes'][attribute][0] in \
                                        self.OID_TO_STR + self.OID_TO_BOOL + self.OID_TO_INT:
                    raw_attributes[attribute] = [value.encode('UTF-8') for value in raw_attributes[attribute]]

            ldif = ldap.modlist.modifyModlist(self._initial_attributes, self._attributes)
            logger.debug("Updating object: {} with following updates: {}".format(self.dn, ldif))
            self._session.server.modify_s(self._dn, ldif)
        elif self._state == self.STATUS_NEW:
            # Check if attributes in required_attributes are defined
            for attr in self.required_attributes:
                try:
                    getattr(self, attr)
                except KeyError:
                    raise LDAPORMException("A required attribute is not defined: {}".format(attr)) from None

            raw_attributes = dict()
            # If objectClass is not defined, fill it by using required_objectclasses
            try:
                getattr(self._attributes, 'objectClass')
            except AttributeError:
                raw_attributes['objectClass'] = [value.encode("UTF-8") for value in self.required_objectclasses]

            # If dn is none, set it using <name_attribute> = <value>[0], <base>
            if self._dn is None:
                name_attribute_value = getattr(self, self.name_attribute)[0]
                if self._session.schema['attributes'][self.name_attribute][0] not in self.OID_TO_STR:
                    name_attribute_value = name_attribute_value.decode('UTF-8')

                self._dn = "{}={},{}".format(self.name_attribute,
                                             name_attribute_value,
                                             self.base)

            # Convert all mapped attributes to bytes array
            for attribute in self._attributes.keys():
                if self._session.schema['attributes'][attribute][0] in \
                                        self.OID_TO_BOOL + self.OID_TO_INT + self.OID_TO_STR:
                    raw_attributes[attribute] = [str(value) for value in self._attributes[attribute]]
                    raw_attributes[attribute] = [value.encode('UTF-8') for value in self._attributes[attribute]]
                else:
                    raw_attributes[attribute] = self._attributes[attribute]

            ldif = ldap.modlist.addModlist(raw_attributes)
            logger.debug("Adding new object: {}".format(self._dn))
            self._session.server.add_s(self._dn, ldif)

        self._state = self.STATUS_SYNC
        self._initial_attributes = None

    def delete(self):
        self._session.server.delete_s(self._dn)


class LDAPModelList(object):
    """
    Manages a list of ``LDAPObject`` instances.

    :param session: An optional instance of LDAPSession.
    :type session: LDAPSession
    """
    children = None  # type: LDAPObject()

    def __init__(self, session=None):
        self._objects = list()
        self._dn = None
        self._session = session

    def _parse_multiple(self, entries):
        for entry in entries:
            current = self.children(self._session).parse(entry)
            self._objects.append(current)
        return self._objects

    def all(self, attributes=None, serverctrls=None):
        entries = self._session.search(base=self.children.base,
                                       ldap_filter=self.children.filter(),
                                       scope=ldap.SCOPE_SUBTREE,
                                       attributes=attributes,
                                       serverctrls=serverctrls)
        return self._parse_multiple(entries)

    def by_attr(self, attr, value, attributes=None, serverctrls=None):
        """
        Search an object of class cls by adding a LDAP filter (&(..)(attr=value))

        :param attr:  Attribute to search
        :param value: Attribute value
        :param attributes: An optional array of the expected attributes returned by the search
        :param serverctrls: An optional array with attributes to request server side sorting
        :return: A list of self.children
        :rtype: list
        """
        entries = self._session.search(base=self.children.base,
                                       ldap_filter="(&{}({}={}))".format(self.children.filter(), attr, value),
                                       scope=ldap.SCOPE_SUBTREE,
                                       attributes=attributes,
                                       serverctrls=serverctrls)
        return self._parse_multiple(entries)

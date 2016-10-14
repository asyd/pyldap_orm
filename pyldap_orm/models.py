# Authors: Bruno Bonfils
# Copyright: Bruno Bonfils
# License: Apache License version2

from pyldap_orm.__init__ import LDAPObject, LDAPModelList
from pyldap_orm.controls import PasswordModify

"""
Templates of current LDAP objects like user(s), group(s).

You need to create your own class that inherits of one theses.

You must set:

* ``required_attribues`` with an array of required attributes, like ``['uid', 'cn']``
* ``base`` is the root base dn to find instances of the object, like ``ou=People,dc=example,dc=com``

"""


class LDAPModelUser(LDAPObject):
    """
    This is a basic template to manage a user.
    """
    required_attributes = ['cn', 'sn', 'uid']
    required_objectclasses = ['inetOrgPerson']
    membership_attribute = 'memberOf'

    def change_password(self, new, current=None):
        self._session.server.extop_s(PasswordModify(self._dn, new, current))


class LDAPModelGroup(LDAPObject):
    """
    LDAPModelGroup is a template to represent a group (of users). By default, the cn attribute is required and also
    used as name attribute.
    """
    required_attributes = ['cn']
    required_objectclasses = ['groupOfNames']
    name_attribute = 'cn'
    member_attribute = 'member'


class LDAPModelUsers(LDAPModelList):
    """
    LDAPModelUsers is a template to represent a list of users. This template also add
    the following specifics methods to search users:

    * by_dn_membership
    * by_name_membership

    """
    children = None  # type: LDAPModelUser

    def by_dn_membership(self, dn):
        """
        Find users belongs to group defined by dn. The search will be perform by create a LDAP filter as
        (&(groupFilter)(membership_attribute=dn)).

        :param dn: The DN of the group to filter user by membership
        :return: a list of children instances.
        :rtype: list
        """
        entries = self._session.search(base=self.children.base,
                                       ldap_filter="(&{}({}={}))".format(self.children.filter(),
                                                                         self.children.membership_attribute,
                                                                         dn))

        return self._parse_multiple(entries)

    def by_name_membership(self, name, group_cls):
        """
        Find users that belongs the group name name.

        :param name: Name of the group. Use LDAPModelGroup.name_attribute as filter. Default name_attribute is cn
        :param group_cls: Class that inherits LDAPModelGroup
        :type group_cls: LDAPModelGroup()
        :return: A list of LDAPObject
        """
        group = group_cls(self._session).by_attr(group_cls.name_attribute,
                                                 name,
                                                 attributes=[group_cls.name_attribute])
        return self.by_dn_membership(group.dn)


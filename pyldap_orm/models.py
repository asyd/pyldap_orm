"""
Templates of current LDAP objects like user(s), group(s).

You need to create your own class that inherits of one theses.

You must setup :
* required_attribues with an array of required attributes like ['uid', 'cn']
* base is the root base dn to find instances of the object
"""
from pyldap_orm.__init__ import LDAPObject, LDAPModelQueryException, LDAPModelList


class LDAPModelUser(LDAPObject):
    """
    This is
    """
    required_attributes = None
    base = None
    membership_attribute = 'memberOf'


class LDAPModelGroup(LDAPObject):
    required_attributes = ['cn']
    name_attribute = 'cn'


class LDAPModelUsers(LDAPModelList):
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

        :param name: Name of the group. Use LDAPModelGroup.name_attribute as filter.
        Default name_attribute is cn

        :param group_cls: Class that inherits LDAPModelGroup
        :type group_cls: LDAPModelGroup
        :return: A list of LDAPObject
        """
        group = group_cls(self._session).by_attr(group_cls.name_attribute,
                                                 name,
                                                 attributes=[group_cls.name_attribute])
        return self.by_dn_membership(group.dn)

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
    filter = None
    membership_attribute = 'memberOf'


class LDAPModelGroup(LDAPObject):
    name_attribute = 'cn'


class LDAPModelUsers(LDAPModelList):
    children = None  # type: LDAPModelUser

    def _by_membership_dn(self, dn):
        """
        Find users belongs to group defined by dn. The search will be perform by create a LDAP filter as
        (&groupFilter(membership_attribute=dn)).
        :param dn: The DN of the group to filter user by membership
        :return: a list of children instances.
        :rtype: list
        """
        entries = self._session.search(base=self.children.base,
                                       ldap_filter="(&{}({}={}))".format(self.children.filter,
                                                                         self.children.membership_attribute,
                                                                         dn))

        return self._parse_multiple(entries)

    def by_membership(self, dn=None, name=None, group_cls=None):
        """
        Find users by group membership. The query may be performed by using either the full DN of the group,
        or by providing a name, and the definition of a class than inherits LDAPModelGroup.

        The inherit is required to have access to the group definition, like the base dn, filter.

        :param name: (optional) The name of the group. Name will be found by performing a LDAP search request
        using group_class.groupnameAttribute
        :param dn: (optional) The DN of the group.
        :param group_cls: (optional) name of LDAPModelGroup instance model
        :type group_cls: LDAPModelGroup
        :return:
        """
        if name is not None and dn is not None:
            raise LDAPModelQueryException("Wrong usage of LDAPModelUsers.by_membership: either set name or dn")
        if name is None and dn is None:
            raise LDAPModelQueryException("Wrong usage of LDAPModelUsers.by_membership: either set name or dn")
        if name is not None and group_cls is None:
            raise LDAPModelQueryException(
                "Wrong usage of LDAPModelUsers.by_membership: group_cls must be set to search by name")
        if dn is not None:
            return self._by_membership_dn(dn)
        else:
            # Since we just have the name, we must search the DN which have name_attribute: name
            group = group_cls(session=self._session).by_attr(group_cls.name_attribute, name,
                                                             attributes=[group_cls.name_attribute])
            return self._by_membership_dn(group.dn)
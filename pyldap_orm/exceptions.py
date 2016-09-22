import ldap


class LDAPORMException(Exception):
    pass


class LDAPModelQueryException(LDAPORMException):
    pass


class LDAPServerDown(LDAPORMException):
    pass


def catch_ldap_exception(e):
    """
    Generic method to catch ldap.

    :param e:
    :type e: Exception
    :return:
    """
    if isinstance(e, ldap.SERVER_DOWN):
        raise LDAPServerDown("Can't contact LDAP server") from None

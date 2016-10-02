import ldap


class LDAPORMException(Exception):
    pass


class LDAPModelQueryException(LDAPORMException):
    pass


class LDAPSessionException(LDAPORMException):
    pass


def catch_ldap_exception(e):
    """
    Generic method to catch exceptions raises from python-ldap

    :param e:
    :type e: Exception
    :return:
    """
    if isinstance(e, ldap.SERVER_DOWN):
        raise LDAPSessionException("Can't contact LDAP server") from None

import pyldap_orm
import pytest
import ldap


def test_session():
    session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
    with pytest.raises(ldap.INVALID_CREDENTIALS):
        session.authenticate('cn=test', 'password')
    session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                         'password')


def test_session_exception():
    with pytest.raises(ldap.SERVER_DOWN):
        session = pyldap_orm.LDAPSession(backend='ldap://localhost:1')
        session.authenticate()


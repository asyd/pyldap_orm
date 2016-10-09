import pyldap_orm
import pytest
import ldap


class TestSession:
    def setup_class(self):
        self.session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                  'password')

    def test_failure_authentication(self):
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                      'invalid')

    def test_session_exception(self):
        with pytest.raises(ldap.SERVER_DOWN):
            session = pyldap_orm.LDAPSession(backend='ldap://localhost:1')
            session.authenticate()




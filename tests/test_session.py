import pyldap_orm
import pytest
import ldap
import os


class TestSession:
    def test_sasl_external_wo_cert(self):
        with pytest.raises(pyldap_orm.exceptions.LDAPSessionException):
            session = pyldap_orm.LDAPSession(backend='ldaps://localhost:9636',
                                             cacertdir=None)
            session.authenticate(mode=pyldap_orm.LDAPSession.AUTH_SASL_EXTERNAL)

    def test_sasl_external(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        session = pyldap_orm.LDAPSession(backend='ldaps://localhost:9636',
                                         cacertdir=None,
                                         cert='{}/extra/tls/client.pem'.format(cwd),
                                         key='{}/extra/tls/client.pem'.format(cwd)
                                         )
        session.authenticate(mode=pyldap_orm.LDAPSession.AUTH_SASL_EXTERNAL)
        assert session.whoami() == 'cn=Bruno Bonfils,ou=Employees,ou=People,dc=example,dc=com'

    def test_failure_authentication(self):
        session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                 'invalid')

    def test_server_down(self):
        with pytest.raises(ldap.SERVER_DOWN):
            session = pyldap_orm.LDAPSession(backend='ldap://localhost:1')
            session.authenticate()

    def test_whoami(self):
        session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                             'password')
        assert session.whoami() == 'cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com'

    def test_ldaps(self):
        session = pyldap_orm.LDAPSession(backend='ldaps://localhost:9636', cacertdir=None)
        session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                             'password')

    def test_starttls(self):
        session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389',
                                         cacertdir=None,
                                         mode=pyldap_orm.LDAPSession.STARTTLS)
        session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                             'password')

    def test_no_key(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        with pytest.raises(pyldap_orm.exceptions.LDAPSessionException):
            pyldap_orm.LDAPSession(backend='ldap://localhost:9389',
                                   cacertdir=None,
                                   cert='{}/extra/tls/client.pem'.format(cwd),
                                   key='/dev/null',
                                   mode=pyldap_orm.LDAPSession.STARTTLS)

    def test_no_cert(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        with pytest.raises(pyldap_orm.exceptions.LDAPSessionException):
            pyldap_orm.LDAPSession(backend='ldap://localhost:9389',
                                   cacertdir=None,
                                   cert='/dev/null',
                                   key='{}/extra/tls/client.pem'.format(cwd),
                                   mode=pyldap_orm.LDAPSession.STARTTLS)

import pyldap_orm
import pyldap_orm.models


class LDAPUser(pyldap_orm.models.LDAPModelUser):
    base = 'ou=People,dc=example,dc=com'
    membership_attribute = 'isMemberOf'


class LDAPUsers(pyldap_orm.models.LDAPModelUsers):
    children = LDAPUser


class LDAPGroup(pyldap_orm.models.LDAPModelGroup):
    base = 'ou=Groups,dc=example,dc=com'


class LDAPGroups(pyldap_orm.models.LDAPModelList):
    children = LDAPGroup


class TestModels:
    def setup_class(self):
        self.session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                  'password')

    def test_single_user(self):
        user = LDAPUser(self.session).by_attr('uid', 'jdoe')
        assert user.dn == 'cn=John Doe,ou=Employees,ou=People,dc=example,dc=com'

    def test_user_membership(self):
        dev = LDAPUsers(self.session).by_dn_membership('cn=Developers,ou=Groups,dc=example,dc=com')
        assert len(dev) == 1
        dev = LDAPUsers(self.session).by_name_membership('Developers', LDAPGroup)
        assert len(dev) == 1

import pyldap_orm
import pyldap_orm.models
import pyldap_orm.controls


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

    def test_search_sorted(self):
        LDAPUsers(self.session).all(serverctrls=[pyldap_orm.controls.ServerSideSort(['uid'])])

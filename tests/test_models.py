import pyldap_orm
import pyldap_orm.models
import pytest


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
        assert user.uid == ['jdoe']
        assert user.sn == ['Doe']
        assert user.uidNumber == [10000]
        assert user.gidNumber == [10000]
        assert user.homeDirectory == ['/home/jdoe']
        assert user.cn == ['John Doe']
        for oc in ['inetOrgPerson', 'organizationalPerson', 'person', 'posixAccount', 'top']:
            assert oc in user.objectClass

    def test_user_membership(self):
        dev = LDAPUsers(self.session).by_dn_membership('cn=Developers,ou=Groups,dc=example,dc=com')
        assert len(dev) == 1
        dev = LDAPUsers(self.session).by_name_membership('Developers', LDAPGroup)
        assert len(dev) == 1

    def test_new_user_failed(self):
        new = LDAPUser(self.session)
        new.dn = 'cn=Tests,ou=People,dc=example,dc=com'
        with pytest.raises(pyldap_orm.LDAPORMException):
            new.save()

    def test_new_user_dn(self):
        new = LDAPUser(self.session)
        new.uid = ['bobama']
        new.cn = ['Barack Obama']
        new.sn = ['Obama']
        new.userPassword = [b'password']
        new.save()
        current = LDAPUser(self.session).by_attr('uid', 'bobama')
        assert current.dn == 'cn=Barack Obama,ou=People,dc=example,dc=com'
        current.delete()

    def test_is_member_of(self):
        user = LDAPUser(self.session).by_attr('uid', 'jdoe', attributes=['*', '+'])
        assert 'cn=Developers,ou=Groups,dc=example,dc=com' in user.isMemberOf
        assert 'cn=Not existing group,ou=Groups,dc=example,dc=com' not in user.isMemberOf

    def test_password_change(self):
        new = LDAPUser(self.session)
        new.uid = ['bobama']
        new.cn = ['Barack Obama']
        new.sn = ['Obama']
        new.userPassword = [b'password']
        new.save()
        current = LDAPUser(self.session).by_attr('uid', 'bobama')
        assert current.dn == 'cn=Barack Obama,ou=People,dc=example,dc=com'
        self.session.authenticate(current.dn, 'password')
        current.change_password(new='newpassword', current='password')
        self.session.authenticate(current.dn, 'newpassword')
        self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                  'password')
        current.delete()

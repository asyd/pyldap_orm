import pyldap_orm
import pytest
import ldap


class TestSession:
    def setup_class(self):
        self.session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                  'password')

    def test_list_by_attr(self):
        class SimpleObject(pyldap_orm.LDAPObject):
            base = 'dc=example,dc=com'
            required_objectclasses = ['inetOrgPerson']
            required_attributes = ['uid']

        class TestList(pyldap_orm.LDAPModelList):
            children = SimpleObject

        entries = TestList(self.session).by_attr('objectClass', 'posixAccount')
        assert len(entries) == 3

    def test_entry(self):
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com')
        user.gidNumber = [10000]
        assert sorted(user.attributes()) == sorted(
            ['uidNumber', 'homeDirectory', 'sn', 'gidNumber', 'cn', 'objectClass', 'uid', 'userPassword'])

    def test_save_for_nothing(self):
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com')
        user.save()

    def test_entry_extended_attributes(self):
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com', '[+,*]')
        assert user.dn == 'cn=John Doe,ou=Employees,ou=People,dc=example,dc=com'
        assert user.homeDirectory == ['/home/jdoe']
        assert user.gidNumber == [10000]
        assert user.hasSubordinates == [False]
        assert user.isMemberOf == ['cn=Developers,ou=Groups,dc=example,dc=com']
        with pytest.raises(KeyError):
            user.givenName

    def test_object_list(self):
        class SingleObject(pyldap_orm.LDAPObject):
            base = 'dc=example,dc=com'

        class AllObjects(pyldap_orm.LDAPModelList):
            children = SingleObject

        assert len(AllObjects(self.session).all()) == 11

    def test_update_object(self):
        self.session.authenticate('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com', 'password')
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com',
                                                         '[+,*]')
        user.description = ['Test']
        user.save()
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com')
        assert user.description == ['Test']
        user.description = []
        user.save()

    def test_create_object(self):
        ldap_object = pyldap_orm.LDAPObject(self.session)
        ldap_object.dn = 'cn=Test,ou=Tests,dc=example,dc=com'
        ldap_object.objectClass = ['person']
        ldap_object.sn = ['Test']
        ldap_object.save()
        ldap_object = pyldap_orm.LDAPObject(self.session).by_dn('cn=Test,ou=Tests,dc=example,dc=com')
        assert ldap_object.dn == 'cn=Test,ou=Tests,dc=example,dc=com'
        assert ldap_object.sn == ['Test']
        ldap_object.delete()
        with pytest.raises(ldap.NO_SUCH_OBJECT):
            pyldap_orm.LDAPObject(self.session).by_dn('cn=Test,ou=Tests,dc=example,dc=com')

    def test_parse_single(self):
        class SingleObject(pyldap_orm.LDAPObject):
            base = 'dc=example,dc=com'
        with pytest.raises(pyldap_orm.LDAPModelQueryException):
            SingleObject(self.session).by_attr('uid', '*')


import pyldap_orm
import pytest
import ldap


class TestSession:
    def setup_class(self):
        self.session = pyldap_orm.LDAPSession(backend='ldap://localhost:9389')
        self.session.authenticate('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                                  'password')

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

        AllObjects(self.session).all()
        AllObjects(self.session).by_attr('objectClass', '*')

    def test_update_object(self):
        self.session.authenticate('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com', 'password')
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com', '[+,*]')
        user.description = ['Test']
        user.save()
        user = pyldap_orm.LDAPObject(self.session).by_dn('cn=John Doe,ou=Employees,ou=People,dc=example,dc=com', '[+,*]')
        assert user.description == ['Test']
        user.description = []
        user.save()

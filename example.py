#!/usr/bin/env python3
# coding: UTF-8

from pyldap_orm import LDAPSession, LDAPObject
from pyldap_orm import models
import pyldap_orm.controls
import logging
import os


class LDAPUser(models.LDAPModelUser):
    base = 'ou=People,dc=example,dc=com'
    required_attributes = ['cn']
    required_objectclasses = ['inetOrgPerson']
    membership_attribute = 'isMemberOf'

    def check(self):
        """
        Remove groups that doesn't belong to ou=Groups,dc=example,dc=com
        """
        try:
            for group in getattr(self, self.membership_attribute):
                if LDAPGroup.base not in group:
                    getattr(self, self.membership_attribute).remove(group)
        except KeyError:
            pass


class LDAPUsers(models.LDAPModelUsers):
    children = LDAPUser


class LDAPGroup(models.LDAPModelGroup):
    base = 'ou=Groups,dc=example,dc=com'
    required_attributes = ['cn']


class LDAPGroups(models.LDAPModelList):
    children = LDAPGroup


def print_entry(entry, extended=False):
    """
    Print on stdout a LDAP entry.

    :param entry: a LDAPObject instance
    :param extended: if true, also display entry attributes, otherwise only display its DN.
    :type entry: LDAPObject
    """
    print(entry.dn)
    if extended:
        for attribute in entry.attributes():
            print(" {}: {}".format(attribute, [value for value in getattr(entry, attribute)]))


def main():
    logging.basicConfig(level=logging.INFO)
    # Connect using client certificate, and use a SASL binding, using EXTERNAL mechanism.
    # By default, pyldap_orm will used /etc/ssl/certs
    cwd = os.path.dirname(os.path.realpath(__file__))
    session = LDAPSession(backend='ldap://localhost:9389/',
                          mode=LDAPSession.STARTTLS,
                          cacertdir=None,
                          cert='{}/tests/extra/tls/client.pem'.format(cwd),
                          key='{}/tests/extra/tls/client.pem'.format(cwd))

    print("SASL EXTERNAL authentication")
    session.authenticate(mode=LDAPSession.AUTH_SASL_EXTERNAL)
    print("Whoami: {}".format(session.whoami()))

    user = LDAPUser(session).by_attr('uid', 'bbo')
    print_entry(user, extended=True)

    print("\nAll users, sorted by uid:")
    for user in LDAPUsers(session).all(serverctrls=[pyldap_orm.controls.ServerSideSort(['uid'])]):
        print_entry(user)

    print("\nGroups:")
    for group in LDAPGroups(session).all():
        print("{} {}".format(group.cn[0], group.dn))

    print("\nMembers of group dn: cn=Developers,ou=Groups,dc=example,dc=com")
    for user in LDAPUsers(session).by_dn_membership(dn='cn=Developers,ou=Groups,dc=example,dc=com'):
        print_entry(user)

    print("\nMembers of group name: Developers")
    for user in LDAPUsers(session).by_name_membership('Developers', LDAPGroup):
        print_entry(user)

    print("\n-----")
    # Reconnect using LDAPS and simple bind
    print("Reconnect using LDAPs and simple authentication")
    session = LDAPSession(backend='ldaps://localhost:9636/', cacertdir=None)
    session.authenticate(bind_dn='cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com',
                         credential='password')

    print("Whoami: {}".format(session.whoami()))
    print("\nBy DN, display all attributes including operational ones")
    self_entry = LDAPObject(session).by_dn('cn=ldapmanager,ou=Services,ou=People,dc=example,dc=com', attributes=['*', '+'])
    print_entry(self_entry, extended=True)
    self_entry.description = ['Toto']
    # self_entry.save()

    # Create a new entry
    new_user = LDAPUser(session)
    new_user.dn = 'cn=Vladimir Poutine,ou=Employees,ou=People,dc=example,dc=com'
    new_user.sn = ['Poutine']
    new_user.givenName = ['Validimir']
    new_user.cn = ["{} {}".format(new_user.givenName[0], new_user.sn[0])]
    new_user.uid = ['vpoutine']
    new_user.mail = ['poutine@cei.com']
    new_user.save()
    # But delete it after
    new_user.delete()

if __name__ == '__main__':
    main()

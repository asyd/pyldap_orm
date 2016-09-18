Getting started
===============

In the first time, you must define which kind of business objects you want to manage. Some base models are available
in the ``pyldap_orm.models`` module.

A very simple example:

.. code-block:: python

   class LDAPUser(models.LDAPModelUser):
       required_attributes = ['cn', 'uid']
       required_objectclasses = ['inetOrgPerson']
       base = 'ou=People,dc=OpenCSI,dc=com'


   class LDAPUsers(models.LDAPModelUsers):
       children = LDAPUser

The following code demonstrates how to connect to the LDAP server using a LDAPSession, and then
perform a by_attr search on a LDAPUser. The ``by_attr`` function returns an instance of ``LDAPuser`` you can
use as dict with instance.dn to get the LDAP DN, or ``instance.attribute`` to get attributes values as a list.
Note: even single valued attributes must be used as a list.

.. code-block:: python

    session = LDAPSession(backend='ldap://localhost:1389/')

    user = LDAPUser(session).by_attr('uid', 'asyd')
    print(user.dn)


The full code example
=====================

.. code-block:: python

   #!/usr/bin/env python3

   from pyldap_orm import LDAPSession, LDAPModelException, LDAPObject
   from pyldap_orm import models
   import logging


   class LDAPUser(models.LDAPModelUser):
       required_attributes = ['cn', 'uid']
       required_objectclasses = ['inetOrgPerson']
       base = 'ou=People,dc=OpenCSI,dc=com'


   class LDAPUsers(models.LDAPModelUsers):
       children = LDAPUser


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
               print(" {}: {}".format(attribute, getattr(entry, attribute)))


   def main():
       logging.basicConfig(level=logging.DEBUG)
       session = LDAPSession(backend='ldap://localhost:1389/')
       try:
           user = LDAPUser(session).by_attr('uid', 'bbo')
           print_entry(user, extended=True)
       except LDAPModelException as e:
           print("Error: ", e)
       print()
       for user in LDAPUsers(session).all():
           print_entry(user)


   if __name__ == '__main__':
       main()

To get the list of an object, you can use the attributes() method:

.. code-block:: python

    user = LDAPUser(session).by_attr('uid', 'asyd')
    for attribute in user.attributes():
        values = getattr(user, attribute)


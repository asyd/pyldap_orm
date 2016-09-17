.. PyLDAP ORM documentation master file, created on Sat Sep 17 02:07:40 2016.

PyLDAP ORM
==========

PyLDAP_ORM is a Python3 module, based on pyldap, to help uses of python classes to interact with a
LDAP server.

A simple example:

.. code-block:: python

   #!/usr/bin/env python3

   from pyldap_orm import LDAPSession, LDAPModelException, LDAPObject
   from pyldap_orm import models


   class LDAPUser(models.LDAPModelUser):
       required_attributes = ['cn', 'uid']
       base = 'ou=People,dc=OpenCSI,dc=com'
       filter = '(objectClass=inetOrgPerson)'


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


Contents:

.. toctree::
   :maxdepth: 2

Getting started
===============


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


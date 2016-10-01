Getting started
===============

In a first time, you must define which kind of business objects you want to manage. Some base models are available
in the ``pyldap_orm.models`` module.

.. code-block:: python

    from pyldap_orm import LDAPSession
    from pyldap_orm import models

    class LDAPUser(models.LDAPModelUser):
        required_attributes = ['cn', 'uid']
        required_objectclasses = ['inetOrgPerson']
        base = 'ou=People,dc=OpenCSI,dc=com'


    class LDAPUsers(models.LDAPModelUsers):
        children = LDAPUser


Then, you need to create a connection to the LDAP server, using ``LDAPSession`` object.

.. code-block:: python

    session = LDAPSession(backend='ldap://localhost:1389/')

Then, you can perform a search by ``uid`` attribute, and print the user's dn using the following code:

.. code-block:: python

    user = LDAPUser(session).by_attr('uid', 'asyd')
    print(user.dn)



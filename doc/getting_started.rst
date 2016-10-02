Getting started
===============

Before using PyORM, there are three steps:

* Define models
* Create a session
* Perform authentication

Models
------

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


Session
-------

Then, you need to create a connection to the LDAP server, using ``LDAPSession`` object.

The following connection methods are available:

* LDAP (url start with ``ldap://``)
* LDAPs (url start with ``ldaps://``)
* STARTTLS (url with ``ldap://``, and ``mode=LDAPSession.STARTTLS``)

You can also provide ``cert`` and ``key`` arguments to provide a client certificate negociation. This is required
to perform ``AUTH_SASL_EXTERNAL`` authentication.

.. code-block:: python
    :caption: Plain LDAP session

    session = LDAPSession(backend='ldap://localhost:1389/')

.. code-block:: python
    :caption: LDAPS session

    session = LDAPSession(backend='ldaps://localhost:1636/')

.. code-block:: python
    :caption: StartTLS session

    session = LDAPSession(backend='ldap://localhost:1389/', mode=LDAPSession.STARTTLS)

.. code-block:: python
    :caption: StartTLS with client certificate

    session = LDAPSession(backend='ldap://localhost:1389/',
                          mode=LDAPSession.STARTTLS,
                          cert='/home/asyd/Downloads/bbonfils-test.pem',
                          key='/home/asyd/Downloads/bbonfils-test.pem')


Authentication
--------------

And then, you need to authenticate to the server.

The following authentication methods are available:

* Anonymous binding (no ``bind_dn`` and ``credential`` provided)
* Simple bind (``bind_dn`` and ``credential`` must be set)
* SASL EXTERNAL (define ``mode=LDAPSession.AUTH_SASL_EXTERNAL``, ``cert`` and ``key`` must be provided at the session layer)

.. code-block:: python
    :caption: Simple bind authentication

    session.authenticate(bind_dn='cn=LDAP Manager,ou=Services,dc=OpenCSI,dc=com',
                         credential='password')


.. code-block:: python
    :caption: SASL EXTERNAL authentication

    session.authenticate(mode=LDAPSession.AUTH_SASL_EXTERNAL)


Search
------

Finally, you can now performs some search. For example by ``uid`` attribute, and print the user's
dn using the following code:


.. code-block:: python

    user = LDAPUser(session).by_attr('uid', 'asyd')
    print(user.dn)



Accessing attributes
--------------------


=============================== ================== ==========
Attribute OID                   Attribute desc.    Conversion
=============================== ================== ==========
1.3.6.1.4.1.1466.115.121.1.12   DN                 str
1.3.6.1.4.1.1466.115.121.1.15   Directory String   str
1.3.6.1.4.1.1466.115.121.1.26   IA String          str
1.3.6.1.4.1.1466.115.121.1.27   Integer            str
1.3.6.1.4.1.1466.115.121.1.37   Object Class       str
1.3.6.1.4.1.1466.115.121.1.38   OID                str
1.3.6.1.4.1.1466.115.121.1.50   Telephone number   str
=============================== ================== ==========

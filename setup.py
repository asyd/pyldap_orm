from setuptools import setup

setup(name='pyldap_orm',
      version='0.0.1',
      description='A simple LDAP ORM to make LDAP access using Python Objects',
      url='http://github.com/storborg/funniest',
      author='Bruno Bonfils',
      author_email='bbonfils@gmail.com',
      license='MIT',
      packages=['pyldap_orm'],
      install_requires=[
          'pyldap',
          'pyasn1'
      ],
      zip_safe=False)

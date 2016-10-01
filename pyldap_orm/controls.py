# Authors: Bruno Bonfils
# Copyright: Bruno Bonfils
# License: Apache License version2
import ldap.controls
import pyasn1.type.univ
import pyasn1.codec.ber.encoder
import pyasn1.type.namedtype
import pyasn1.type.tag


class ServerSideSort(ldap.controls.LDAPControl):
    """
    Implements RFC 2891, LDAP Control Extension for Server Side Sorting of Search Results

    Reference: https://www.ietf.org/rfc/rfc2891.txt
    """
    controlType = '1.2.840.113556.1.4.473'

    def __init__(self, attributes):
        self.criticality = False
        self.attributes = attributes

    def encodeControlValue(self):
        """
        The RFC define the following structure:

              SortKeyList ::= SEQUENCE OF SEQUENCE {
                 attributeType   AttributeDescription,
                 orderingRule    [0] MatchingRuleId OPTIONAL,
                 reverseOrder    [1] BOOLEAN DEFAULT FALSE }

        However, is in this implementation, only attributeType can be used.

        :return: BER encoded value of attributes
        """
        sort_key_list = ServerSideSort.SortKeyList()
        i = 0
        for attribute in self.attributes:
            sort_key = ServerSideSort.SortKey()
            sort_key.setComponentByName('attributeType', attribute)
            sort_key_list.setComponentByPosition(i, sort_key)
            i += 1
        return pyasn1.codec.ber.encoder.encode(sort_key_list)

    class SortKeyList(pyasn1.type.univ.SequenceOf):
        componentType = pyasn1.type.univ.Sequence()

    class SortKey(pyasn1.type.univ.Sequence):
        componentType = pyasn1.type.namedtype.NamedTypes(
            pyasn1.type.namedtype.NamedType('attributeType', pyasn1.type.univ.OctetString()),
        )


class PasswordModify(ldap.extop.ExtendedRequest):
    """
    Implements RFC 3062, LDAP Password Modify Extended Operation

    Reference: https://www.ietf.org/rfc/rfc3062.txt
    """

    def __init__(self, identity, new, current=None):
        self.requestName = '1.3.6.1.4.1.4203.1.11.1'
        self.identity = identity
        self.new = new
        self.current = current

    def encodedRequestValue(self):
        request = self.PasswdModifyRequestValue()
        request.setComponentByName('userIdentity', self.identity)
        if self.current is not None:
            request.setComponentByName('oldPasswd', self.current)
        request.setComponentByName('newPasswd', self.new)
        return pyasn1.codec.ber.encoder.encode(request)

    class PasswdModifyRequestValue(pyasn1.type.univ.Sequence):
        """
        PyASN1 representation of:
            PasswdModifyRequestValue ::= SEQUENCE {
            userIdentity    [0]  OCTET STRING OPTIONAL
            oldPasswd       [1]  OCTET STRING OPTIONAL
            newPasswd       [2]  OCTET STRING OPTIONAL }
        """
        componentType = pyasn1.type.namedtype.NamedTypes(
            pyasn1.type.namedtype.OptionalNamedType(
                'userIdentity',
                pyasn1.type.univ.OctetString().subtype(
                    implicitTag=pyasn1.type.tag.Tag(pyasn1.type.tag.tagClassContext, pyasn1.type.tag.tagFormatSimple, 0)
                )),
            pyasn1.type.namedtype.OptionalNamedType(
                'oldPasswd',
                pyasn1.type.univ.OctetString().subtype(
                    implicitTag=pyasn1.type.tag.Tag(pyasn1.type.tag.tagClassContext, pyasn1.type.tag.tagFormatSimple, 1)
                )),
            pyasn1.type.namedtype.OptionalNamedType(
                'newPasswd',
                pyasn1.type.univ.OctetString().subtype(
                    implicitTag=pyasn1.type.tag.Tag(pyasn1.type.tag.tagClassContext, pyasn1.type.tag.tagFormatSimple, 2)
                )),
        )

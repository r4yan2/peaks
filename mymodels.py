from peewee import *

database = MySQLDatabase('gpg_keyserver', **{'charset': 'utf8', 'use_unicode': True, 'user': 'root', 'host': '172.17.0.2'})

class UnknownField(object):
    def __init__(self, *_, **__): pass

class BaseModel(Model):
    class Meta:
        database = database

class Keystatus(BaseModel):
    fingerprint = CharField()
    version = IntegerField()
    vulnerabilitycode = IntegerField(column_name='vulnerabilityCode')
    vulnerabilitydescription = CharField(column_name='vulnerabilityDescription', null=True)

    class Meta:
        table_name = 'KeyStatus'
        indexes = (
            (('version', 'fingerprint', 'vulnerabilitycode'), True),
        )
        primary_key = CompositeKey('fingerprint', 'version', 'vulnerabilitycode')

class Pubkey(BaseModel):
    prifingerprint = CharField(column_name='PriFingerprint', null=True)
    creationtime = DateTimeField(column_name='creationTime')
    curveoid = TextField(column_name='curveOID')
    e = TextField(null=True)
    expirationtime = DateTimeField(column_name='expirationTime', null=True)
    fingerprint = CharField(index=True)
    g = TextField(null=True)
    is_analyzed = IntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    keyid = BigIntegerField(column_name='keyId')
    n = TextField(index=True, null=True)
    p = TextField(index=True, null=True)
    pubalgorithm = IntegerField(column_name='pubAlgorithm')
    q = TextField(index=True, null=True)
    revocationtime = DateTimeField(column_name='revocationTime', null=True)
    sccindex = IntegerField(column_name='sccIndex', index=True, null=True)
    version = IntegerField()
    y = TextField(index=True, null=True)

    class Meta:
        table_name = 'Pubkey'
        indexes = (
            (('keyid', 'fingerprint'), False),
            (('version', 'fingerprint'), True),
            (('version', 'prifingerprint'), False),
        )
        primary_key = CompositeKey('fingerprint', 'version')

class Signaturestatus(BaseModel):
    signature = IntegerField(column_name='signature_id')
    vulnerabilitycode = IntegerField(column_name='vulnerabilityCode')
    vulnerabilitydescription = CharField(column_name='vulnerabilityDescription', null=True)

    class Meta:
        table_name = 'SignatureStatus'
        indexes = (
            (('signature', 'vulnerabilitycode'), True),
        )
        primary_key = CompositeKey('signature', 'vulnerabilitycode')

class Signatures(BaseModel):
    creationtime = DateTimeField(column_name='creationTime', index=True)
    expirationtime = DateTimeField(column_name='expirationTime', null=True)
    flags = TextField(null=True)
    hashalgorithm = IntegerField(column_name='hashAlgorithm', index=True)
    hashheader = CharField(column_name='hashHeader', null=True)
    hashmismatch = IntegerField(column_name='hashMismatch', constraints=[SQL("DEFAULT 0")], index=True, null=True)
    isexpired = IntegerField(column_name='isExpired', constraints=[SQL("DEFAULT 0")])
    isexportable = IntegerField(column_name='isExportable')
    isrevocable = IntegerField(column_name='isRevocable', constraints=[SQL("DEFAULT 1")])
    isrevocation = IntegerField(column_name='isRevocation', constraints=[SQL("DEFAULT 0")], index=True)
    isrevoked = IntegerField(column_name='isRevoked', constraints=[SQL("DEFAULT 0")])
    isvalid = IntegerField(column_name='isValid', constraints=[SQL("DEFAULT 0")])
    is_analyzed = IntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    issuingfingerprint = CharField(column_name='issuingFingerprint', index=True, null=True)
    issuingkeyid = BigIntegerField(column_name='issuingKeyId', index=True)
    issuingusername = CharField(column_name='issuingUsername', index=True, null=True)
    keyexpirationtime = DateTimeField(column_name='keyExpirationTime', null=True)
    pubalgorithm = IntegerField(column_name='pubAlgorithm')
    r = TextField(index=True, null=True)
    regex = CharField(null=True)
    revocationcode = IntegerField(column_name='revocationCode', null=True)
    revocationreason = CharField(column_name='revocationReason', null=True)
    revocationsigid = IntegerField(column_name='revocationSigId', null=True)
    s = TextField(index=True, null=True)
    sign_uatt = IntegerField(column_name='sign_Uatt_id', null=True)
    signedfingerprint = CharField(column_name='signedFingerprint', index=True)
    signedhash = TextField(column_name='signedHash', null=True)
    signedkeyid = BigIntegerField(column_name='signedKeyId', index=True)
    signedusername = CharField(column_name='signedUsername', index=True, null=True)
    type = IntegerField(index=True)
    version = IntegerField(index=True)

    class Meta:
        table_name = 'Signatures'
        indexes = (
            (('issuingkeyid', 'issuingfingerprint'), False),
            (('issuingkeyid', 'signedkeyid', 'issuingfingerprint', 'signedfingerprint', 'signedusername'), False),
            (('issuingkeyid', 'signedkeyid', 'signedusername', 'creationtime'), False),
            (('r', 's'), True),
            (('sign_uatt', 'signedfingerprint'), False),
            (('signedkeyid', 'signedfingerprint'), False),
        )

class UnpackerErrors(BaseModel):
    error = TextField()
    fingerprint = CharField()
    idx = AutoField()
    version = IntegerField()

    class Meta:
        table_name = 'Unpacker_errors'
        indexes = (
            (('version', 'fingerprint'), False),
        )

class Userattribute(BaseModel):
    encoding = IntegerField(null=True)
    fingerprint = CharField()
    id = IntegerField()
    image = TextField(null=True)
    name = CharField()

    class Meta:
        table_name = 'UserAttribute'
        indexes = (
            (('fingerprint', 'name'), False),
            (('fingerprint', 'name', 'image'), True),
            (('id', 'fingerprint', 'name'), True),
        )
        primary_key = CompositeKey('fingerprint', 'id', 'name')

class Userid(BaseModel):
    bindingauthentic = IntegerField(column_name='bindingAuthentic')
    email = CharField(index=True, null=True)
    fingerprint = CharField()
    is_analyze = IntegerField(null=True)
    name = CharField(index=True)
    ownerkeyid = BigIntegerField(column_name='ownerkeyID')

    class Meta:
        table_name = 'UserID'
        indexes = (
            (('fingerprint', 'name'), True),
            (('ownerkeyid', 'fingerprint'), False),
        )
        primary_key = CompositeKey('fingerprint', 'name')

class BrokenKeys(BaseModel):
    certificate = TextField(null=True)
    log = CharField(null=True)

    class Meta:
        table_name = 'broken_keys'

class GpgKeyserver(BaseModel):
    id = BigIntegerField(column_name='ID')
    certificate = TextField(null=True)
    error_code = IntegerField(constraints=[SQL("DEFAULT 0")])
    fingerprint = CharField()
    hash = CharField(index=True)
    is_synchronized = IntegerField(constraints=[SQL("DEFAULT 0")])
    is_unpacked = IntegerField(constraints=[SQL("DEFAULT 0")])
    version = IntegerField()

    class Meta:
        table_name = 'gpg_keyserver'
        indexes = (
            (('id', 'fingerprint'), False),
            (('version', 'fingerprint'), True),
        )
        primary_key = CompositeKey('fingerprint', 'version')

class Ptree(BaseModel):
    leaf = IntegerField()
    node_elements = TextField()
    node_key = CharField(primary_key=True)
    node_svalues = TextField()
    num_elements = IntegerField()

    class Meta:
        table_name = 'ptree'

class RemovedHash(BaseModel):
    hash = CharField(primary_key=True)

    class Meta:
        table_name = 'removed_hash'

class Revocationsignatures(BaseModel):
    issuingkeyid = BigIntegerField(column_name='issuingKeyId', constraints=[SQL("DEFAULT 0")])
    signedfingerprint = CharField(column_name='signedFingerprint')
    signedusername = CharField(column_name='signedUsername', constraints=[SQL("DEFAULT ''")])

    class Meta:
        table_name = 'revocationSignatures'
        indexes = (
            (('issuingkeyid', 'signedfingerprint', 'signedusername'), True),
        )
        primary_key = CompositeKey('issuingkeyid', 'signedfingerprint', 'signedusername')

class Selfsignaturesmetadata(BaseModel):
    hashalgorithm = IntegerField(column_name='hashAlgorithm', index=True)
    isprimaryuserid = IntegerField(column_name='isPrimaryUserId')
    issuingfingerprint = CharField(column_name='issuingFingerprint')
    issuingkeyid = BigIntegerField(column_name='issuingKeyId')
    keyexpirationtime = DateTimeField(column_name='keyExpirationTime', null=True)
    preferedcompression = TextField(column_name='preferedCompression', null=True)
    preferedhash = TextField(column_name='preferedHash', null=True)
    preferedsymmetric = TextField(column_name='preferedSymmetric', null=True)
    pubalgorithm = IntegerField(column_name='pubAlgorithm')
    signeduserid = CharField(column_name='signedUserId', index=True, null=True)
    trustlevel = IntegerField(column_name='trustLevel', null=True)
    type = IntegerField(index=True)
    userrole = CharField(column_name='userRole', null=True)
    version = IntegerField()

    class Meta:
        table_name = 'selfSignaturesMetadata'
        indexes = (
            (('issuingfingerprint', 'signeduserid'), False),
            (('issuingkeyid', 'issuingfingerprint'), False),
            (('version', 'issuingfingerprint', 'trustlevel', 'isprimaryuserid'), False),
        )


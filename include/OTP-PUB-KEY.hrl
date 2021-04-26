%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:57
%%%-------------------------------------------------------------------
-author("root").
-record('AttributePKCS-7', {type, values}).

-record('AlgorithmIdentifierPKCS-7',
{algorithm, parameters = asn1_NOVALUE}).

-record('AlgorithmIdentifierPKCS-10',
{algorithm, parameters = asn1_NOVALUE}).

-record('AttributePKCS-10', {type, values}).

-record('SubjectPublicKeyInfo-PKCS-10',
{algorithm, subjectPublicKey}).

-record('ECPrivateKey',
{version,
  privateKey,
  parameters = asn1_NOVALUE,
  publicKey = asn1_NOVALUE}).

-record('DSAPrivateKey', {version, p, q, g, y, x}).

-record('DHParameter',
{prime, base, privateValueLength = asn1_NOVALUE}).

-record('DigestInfoNull', {digestAlgorithm, digest}).

-record('DigestInfoPKCS-1', {digestAlgorithm, digest}).

-record('RSASSA-PSS-params',
{hashAlgorithm,
  maskGenAlgorithm,
  saltLength = asn1_DEFAULT,
  trailerField = asn1_DEFAULT}).

-record('AlgorithmNull', {algorithm, parameters}).

-record('Algorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('OtherPrimeInfo',
{prime, exponent, coefficient}).

-record('RSAPrivateKey',
{version,
  modulus,
  publicExponent,
  privateExponent,
  prime1,
  prime2,
  exponent1,
  exponent2,
  coefficient,
  otherPrimeInfos = asn1_NOVALUE}).

-record('RSAPublicKey', {modulus, publicExponent}).

-record('Curve', {a, b, seed = asn1_NOVALUE}).

-record('ECParameters',
{version,
  fieldID,
  curve,
  base,
  order,
  cofactor = asn1_NOVALUE}).

-record('Pentanomial', {k1, k2, k3}).

-record('Characteristic-two', {m, basis, parameters}).

-record('ECDSA-Sig-Value', {r, s}).

-record('FieldID', {fieldType, parameters}).

-record('ValidationParms', {seed, pgenCounter}).

-record('DomainParameters',
{p,
  g,
  q,
  j = asn1_NOVALUE,
  validationParms = asn1_NOVALUE}).

-record('Dss-Sig-Value', {r, s}).

-record('Dss-Parms', {p, q, g}).

-record('ACClearAttrs', {acIssuer, acSerial, attrs}).

-record('AAControls',
{pathLenConstraint = asn1_NOVALUE,
  permittedAttrs = asn1_NOVALUE,
  excludedAttrs = asn1_NOVALUE,
  permitUnSpecified = asn1_DEFAULT}).

-record('SecurityCategory', {type, value}).

-record('Clearance',
{policyId,
  classList = asn1_DEFAULT,
  securityCategories = asn1_NOVALUE}).

-record('RoleSyntax',
{roleAuthority = asn1_NOVALUE, roleName}).

-record('SvceAuthInfo',
{service, ident, authInfo = asn1_NOVALUE}).

-record('IetfAttrSyntax',
{policyAuthority = asn1_NOVALUE, values}).

-record('TargetCert',
{targetCertificate,
  targetName = asn1_NOVALUE,
  certDigestInfo = asn1_NOVALUE}).

-record('AttCertValidityPeriod',
{notBeforeTime, notAfterTime}).

-record('IssuerSerial',
{issuer, serial, issuerUID = asn1_NOVALUE}).

-record('V2Form',
{issuerName = asn1_NOVALUE,
  baseCertificateID = asn1_NOVALUE,
  objectDigestInfo = asn1_NOVALUE}).

-record('ObjectDigestInfo',
{digestedObjectType,
  otherObjectTypeID = asn1_NOVALUE,
  digestAlgorithm,
  objectDigest}).

-record('Holder',
{baseCertificateID = asn1_NOVALUE,
  entityName = asn1_NOVALUE,
  objectDigestInfo = asn1_NOVALUE}).

-record('AttributeCertificateInfo',
{version,
  holder,
  issuer,
  signature,
  serialNumber,
  attrCertValidityPeriod,
  attributes,
  issuerUniqueID = asn1_NOVALUE,
  extensions = asn1_NOVALUE}).

-record('AttributeCertificate',
{acinfo, signatureAlgorithm, signatureValue}).

-record('IssuingDistributionPoint',
{distributionPoint = asn1_NOVALUE,
  onlyContainsUserCerts = asn1_DEFAULT,
  onlyContainsCACerts = asn1_DEFAULT,
  onlySomeReasons = asn1_NOVALUE,
  indirectCRL = asn1_DEFAULT,
  onlyContainsAttributeCerts = asn1_DEFAULT}).

-record('AccessDescription',
{accessMethod, accessLocation}).

-record('DistributionPoint',
{distributionPoint = asn1_NOVALUE,
  reasons = asn1_NOVALUE,
  cRLIssuer = asn1_NOVALUE}).

-record('PolicyConstraints',
{requireExplicitPolicy = asn1_NOVALUE,
  inhibitPolicyMapping = asn1_NOVALUE}).

-record('GeneralSubtree',
{base, minimum = asn1_DEFAULT, maximum = asn1_NOVALUE}).

-record('NameConstraints',
{permittedSubtrees = asn1_NOVALUE,
  excludedSubtrees = asn1_NOVALUE}).

-record('BasicConstraints',
{cA = asn1_DEFAULT, pathLenConstraint = asn1_NOVALUE}).

-record('EDIPartyName',
{nameAssigner = asn1_NOVALUE, partyName}).

-record('AnotherName', {'type-id', value}).

-record('PolicyMappings_SEQOF',
{issuerDomainPolicy, subjectDomainPolicy}).

-record('NoticeReference',
{organization, noticeNumbers}).

-record('UserNotice',
{noticeRef = asn1_NOVALUE,
  explicitText = asn1_NOVALUE}).

-record('PolicyQualifierInfo',
{policyQualifierId, qualifier}).

-record('PolicyInformation',
{policyIdentifier, policyQualifiers = asn1_NOVALUE}).

-record('PrivateKeyUsagePeriod',
{notBefore = asn1_NOVALUE, notAfter = asn1_NOVALUE}).

-record('AuthorityKeyIdentifier',
{keyIdentifier = asn1_NOVALUE,
  authorityCertIssuer = asn1_NOVALUE,
  authorityCertSerialNumber = asn1_NOVALUE}).

-record('EncryptedData',
{version, encryptedContentInfo}).

-record('DigestedData',
{version, digestAlgorithm, contentInfo, digest}).

-record('SignedAndEnvelopedData',
{version,
  recipientInfos,
  digestAlgorithms,
  encryptedContentInfo,
  certificates = asn1_NOVALUE,
  crls = asn1_NOVALUE,
  signerInfos}).

-record('RecipientInfo',
{version,
  issuerAndSerialNumber,
  keyEncryptionAlgorithm,
  encryptedKey}).

-record('EncryptedContentInfo',
{contentType,
  contentEncryptionAlgorithm,
  encryptedContent = asn1_NOVALUE}).

-record('EnvelopedData',
{version, recipientInfos, encryptedContentInfo}).

-record('DigestInfoPKCS-7', {digestAlgorithm, digest}).

-record('SignerInfo',
{version,
  issuerAndSerialNumber,
  digestAlgorithm,
  authenticatedAttributes = asn1_NOVALUE,
  digestEncryptionAlgorithm,
  encryptedDigest,
  unauthenticatedAttributes = asn1_NOVALUE}).

-record('SignerInfo_unauthenticatedAttributes_uaSet_SETOF',
{type, values}).

-record('SignerInfo_unauthenticatedAttributes_uaSequence_SEQOF',
{type, values}).

-record('SignedData',
{version,
  digestAlgorithms,
  contentInfo,
  certificates = asn1_NOVALUE,
  crls = asn1_NOVALUE,
  signerInfos}).

-record('ContentInfo',
{contentType, content = asn1_NOVALUE}).

-record('KeyEncryptionAlgorithmIdentifier',
{algorithm, parameters = asn1_NOVALUE}).

-record('IssuerAndSerialNumber',
{issuer, serialNumber}).

-record('DigestEncryptionAlgorithmIdentifier',
{algorithm, parameters = asn1_NOVALUE}).

-record('DigestAlgorithmIdentifier',
{algorithm, parameters = asn1_NOVALUE}).

-record('ContentEncryptionAlgorithmIdentifier',
{algorithm, parameters = asn1_NOVALUE}).

-record('SignerInfoAuthenticatedAttributes_aaSet_SETOF',
{type, values}).

-record('SignerInfoAuthenticatedAttributes_aaSequence_SEQOF',
{type, values}).

-record('CertificationRequest',
{certificationRequestInfo,
  signatureAlgorithm,
  signature}).

-record('CertificationRequest_signatureAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('CertificationRequestInfo',
{version, subject, subjectPKInfo, attributes}).

-record('CertificationRequestInfo_subjectPKInfo',
{algorithm, subjectPublicKey}).

-record('CertificationRequestInfo_subjectPKInfo_algorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('CertificationRequestInfo_attributes_SETOF',
{type, values}).

-record('TeletexDomainDefinedAttribute', {type, value}).

-record('PresentationAddress',
{pSelector = asn1_NOVALUE,
  sSelector = asn1_NOVALUE,
  tSelector = asn1_NOVALUE,
  nAddresses}).

-record('ExtendedNetworkAddress_e163-4-address',
{number, 'sub-address' = asn1_NOVALUE}).

-record('PDSParameter',
{'printable-string' = asn1_NOVALUE,
  'teletex-string' = asn1_NOVALUE}).

-record('UnformattedPostalAddress',
{'printable-address' = asn1_NOVALUE,
  'teletex-string' = asn1_NOVALUE}).

-record('TeletexPersonalName',
{surname,
  'given-name' = asn1_NOVALUE,
  initials = asn1_NOVALUE,
  'generation-qualifier' = asn1_NOVALUE}).

-record('ExtensionAttribute',
{'extension-attribute-type',
  'extension-attribute-value'}).

-record('BuiltInDomainDefinedAttribute', {type, value}).

-record('PersonalName',
{surname,
  'given-name' = asn1_NOVALUE,
  initials = asn1_NOVALUE,
  'generation-qualifier' = asn1_NOVALUE}).

-record('BuiltInStandardAttributes',
{'country-name' = asn1_NOVALUE,
  'administration-domain-name' = asn1_NOVALUE,
  'network-address' = asn1_NOVALUE,
  'terminal-identifier' = asn1_NOVALUE,
  'private-domain-name' = asn1_NOVALUE,
  'organization-name' = asn1_NOVALUE,
  'numeric-user-identifier' = asn1_NOVALUE,
  'personal-name' = asn1_NOVALUE,
  'organizational-unit-names' = asn1_NOVALUE}).

-record('ORAddress',
{'built-in-standard-attributes',
  'built-in-domain-defined-attributes' = asn1_NOVALUE,
  'extension-attributes' = asn1_NOVALUE}).

-record('AlgorithmIdentifier',
{algorithm, parameters = asn1_NOVALUE}).

-record('TBSCertList',
{version = asn1_NOVALUE,
  signature,
  issuer,
  thisUpdate,
  nextUpdate = asn1_NOVALUE,
  revokedCertificates = asn1_NOVALUE,
  crlExtensions = asn1_NOVALUE}).

-record('TBSCertList_revokedCertificates_SEQOF',
{userCertificate,
  revocationDate,
  crlEntryExtensions = asn1_NOVALUE}).

-record('CertificateList',
{tbsCertList, signatureAlgorithm, signature}).

-record('Extension',
{extnID, critical = asn1_DEFAULT, extnValue}).

-record('SubjectPublicKeyInfo',
{algorithm, subjectPublicKey}).

-record('Validity', {notBefore, notAfter}).

-record('TBSCertificate',
{version = asn1_DEFAULT,
  serialNumber,
  signature,
  issuer,
  validity,
  subject,
  subjectPublicKeyInfo,
  issuerUniqueID = asn1_NOVALUE,
  subjectUniqueID = asn1_NOVALUE,
  extensions = asn1_NOVALUE}).

-record('Certificate',
{tbsCertificate, signatureAlgorithm, signature}).

-record('AttributeTypeAndValue', {type, value}).

-record('Attribute', {type, values}).

-record('Extension-Any',
{extnID, critical = asn1_DEFAULT, extnValue}).

-record('OTPExtension',
{extnID, critical = asn1_DEFAULT, extnValue}).

-record('OTPExtensionAttribute',
{extensionAttributeType, extensionAttributeValue}).

-record('OTPCharacteristic-two',
{m, basis, parameters}).

-record('OTPFieldID', {fieldType, parameters}).

-record('PublicKeyAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('SignatureAlgorithm-Any',
{algorithm, parameters = asn1_NOVALUE}).

-record('SignatureAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('OTPSubjectPublicKeyInfo-Any',
{algorithm, subjectPublicKey}).

-record('OTPSubjectPublicKeyInfo',
{algorithm, subjectPublicKey}).

-record('OTPOLDSubjectPublicKeyInfo',
{algorithm, subjectPublicKey}).

-record('OTPOLDSubjectPublicKeyInfo_algorithm',
{algo, parameters = asn1_NOVALUE}).

-record('OTPAttributeTypeAndValue', {type, value}).

-record('OTPTBSCertificate',
{version = asn1_DEFAULT,
  serialNumber,
  signature,
  issuer,
  validity,
  subject,
  subjectPublicKeyInfo,
  issuerUniqueID = asn1_NOVALUE,
  subjectUniqueID = asn1_NOVALUE,
  extensions = asn1_NOVALUE}).

-record('OTPCertificate',
{tbsCertificate, signatureAlgorithm, signature}).
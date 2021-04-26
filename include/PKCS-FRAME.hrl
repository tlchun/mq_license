%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:58
%%%-------------------------------------------------------------------
-author("root").
-record('AlgorithmIdentifierPKCS5v2-0',
{algorithm, parameters = asn1_NOVALUE}).

-record('PKAttribute',
{type, values, valuesWithContext = asn1_NOVALUE}).

-record('PKAttribute_valuesWithContext_SETOF',
{value, contextList}).

-record('AlgorithmIdentifierPKCS-8',
{algorithm, parameters = asn1_NOVALUE}).

-record('RC5-CBC-Parameters',
{version, rounds, blockSizeInBits, iv = asn1_NOVALUE}).

-record('RC2-CBC-Parameter',
{rc2ParameterVersion = asn1_NOVALUE, iv}).

-record('PBMAC1-params',
{keyDerivationFunc, messageAuthScheme}).

-record('PBMAC1-params_keyDerivationFunc',
{algorithm, parameters = asn1_NOVALUE}).

-record('PBMAC1-params_messageAuthScheme',
{algorithm, parameters = asn1_NOVALUE}).

-record('PBES2-params',
{keyDerivationFunc, encryptionScheme}).

-record('PBES2-params_keyDerivationFunc',
{algorithm, parameters = asn1_NOVALUE}).

-record('PBES2-params_encryptionScheme',
{algorithm, parameters = asn1_NOVALUE}).

-record('PBEParameter', {salt, iterationCount}).

-record('PBKDF2-params',
{salt,
  iterationCount,
  keyLength = asn1_NOVALUE,
  prf = asn1_DEFAULT}).

-record('PBKDF2-params_salt_otherSource',
{algorithm, parameters = asn1_NOVALUE}).

-record('PBKDF2-params_prf',
{algorithm, parameters = asn1_NOVALUE}).

-record('Context',
{contextType, contextValues, fallback = asn1_DEFAULT}).

-record('EncryptedPrivateKeyInfo',
{encryptionAlgorithm, encryptedData}).

-record('EncryptedPrivateKeyInfo_encryptionAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record('Attributes_SETOF',
{type, values, valuesWithContext = asn1_NOVALUE}).

-record('Attributes_SETOF_valuesWithContext_SETOF',
{value, contextList}).

-record('PrivateKeyInfo',
{version,
  privateKeyAlgorithm,
  privateKey,
  attributes = asn1_NOVALUE}).

-record('PrivateKeyInfo_privateKeyAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).
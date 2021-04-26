%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:56
%%%-------------------------------------------------------------------
-author("root").
-record('SubjectPublicKeyInfoAlgorithm',
{algorithm, parameters = asn1_NOVALUE}).

-record(path_validation_state,
{valid_policy_tree,
  explicit_policy,
  inhibit_any_policy,
  policy_mapping,
  cert_num,
  last_cert = false,
  permitted_subtrees = no_constraints,
  excluded_subtrees = [],
  working_public_key_algorithm,
  working_public_key,
  working_public_key_parameters,
  working_issuer_name,
  max_path_length,
  verify_fun,
  user_state}).

-record(policy_tree_node,
{valid_policy,
  qualifier_set,
  criticality_indicator,
  expected_policy_set}).

-record(revoke_state,
{reasons_mask,
  cert_status,
  interim_reasons_mask,
  valid_ext,
  details}).

-record('ECPoint', {point}).
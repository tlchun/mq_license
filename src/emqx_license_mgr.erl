%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 03. 五月 2021 上午8:16
%%%-------------------------------------------------------------------
-module(emqx_license_mgr).
-author("root").

-behaviour(gen_server).
-include("../include/public_key.hrl").
-include("../include/OTP-PUB-KEY.hrl").
-include("../include/PKCS-FRAME.hrl").


-export([start_link/0]).

-export([load/1, plugins/1]).

-export([info/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-type license() ::
#{vendor := string(),
product := string(),
version := string(),
customer := {string(), binary()},
email := string(),
validity := {string(), string()},
permits := map(),
hostid => string()}.

-record(state, {license  :: license(), timer, check_timer, monitor}).

-spec start_link() -> {ok, pid()}.
start_link() ->
  gen_server:start_link({local, emqx_license_mgr}, emqx_license_mgr, [], []).

-spec load(undefined | string()) -> ok.
load(undefined) -> shutdown("Cannot find license file!");
load(File) ->
  case file:read_file(File) of
    {ok, Lic} ->
      try verify(Lic) of
        {ok, Cert} -> apply(Cert);
        {error, Reason, Cert} -> handle_bad_cert(Reason, Cert)
      catch
        error:'InvalidPublicKey':_Stk ->
          shutdown("The Public Key is invalid!");
        error:'Invalid_CA_Certificate':_Stk ->
          shutdown("The CA Certificate is invalid!")
      end;
    {error, Reason} ->
      shutdown("Cannot read license file: " ++
      atom_to_list(Reason))
  end.

-spec verify(Lic :: binary()) -> {ok, #'OTPCertificate'{}} |{error, atom(), #'OTPCertificate'{}}.
verify(Lic) ->
  ok = verify_public_key(),
  CaFile = filename:join(code:priv_dir(emqx_license), "ca.crt"),
  {ok, CaCertBin} = file:read_file(CaFile),
  [{'Certificate', DerCaCert, _}] = public_key:pem_decode(CaCertBin),
  CaCert = public_key:pkix_decode_cert(DerCaCert, otp),
  ok = vefify_public_key(CaCert),
  [{'Certificate', DerCert, _}] = public_key:pem_decode(Lic),
  Cert = public_key:pkix_decode_cert(DerCert, otp),
  case verify_lic_cert(CaCert, DerCert) of
    ok -> {ok, Cert};
    {error, Reason} -> {error, Reason, Cert}
  end.

verify_public_key() ->
  case base64:encode(crypto:hash(sha256,
    base64:decode(<<"MIIBCgKCAQEAyJgH+BvEJIStYvyw1keQ/ixVPJ4GGjlP7"
    "lTKnZL\n                  3mqZyPXQUEaLnRmcQ3/"
    "ra8xYQPcfMReynqmrYmT45/eD2tK7rdXT\n "
    "                 zYfOWoU0cXNQMaQS7be1bLF4QrAE"
    "bJhEsgkjX9rP30mrzZCjRRnk\n          "
    "        QtWmi4DNBU4qOl6Ee9aAS5aY+L7DW646J47Ty"
    "c7gAA4sdZw04KGB\n                  XnSyXzyBvP"
    "af+QByOrOXUxBcxehHN/Ox41/duYFXSR40U6lyp49N\n "
    "                 YJ6yEUVWSp4oxsrkcgqyegNKXdW1"
    "D8oqJXzxalbh/RB8YYlX+Ae3\n          "
    "        77gEBlLefPFdSEYDRN/ajs3UIeqde6i20lVyD"
    "PIjEcQIDAQAB">>)))
  of
    <<"3jHg0zCb4NL5v8eIoKn+CNDMq8A04mXEOefqlUBSSVs=">> ->
      ok;
    _Other -> error('InvalidPublicKey')
  end.

vefify_public_key(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{subjectPublicKeyInfo = PublicKeyInfo}}) ->
  #'OTPSubjectPublicKeyInfo'{subjectPublicKey = SubjectPublicKey} = PublicKeyInfo, CaPubKey = public_key:der_encode('RSAPublicKey', SubjectPublicKey),
  case
    base64:decode(<<"MIIBCgKCAQEAyJgH+BvEJIStYvyw1keQ/ixVPJ4GGjlP7"
    "lTKnZL\n                  3mqZyPXQUEaLnRmcQ3/"
    "ra8xYQPcfMReynqmrYmT45/eD2tK7rdXT\n "
    "                 zYfOWoU0cXNQMaQS7be1bLF4QrAE"
    "bJhEsgkjX9rP30mrzZCjRRnk\n          "
    "        QtWmi4DNBU4qOl6Ee9aAS5aY+L7DW646J47Ty"
    "c7gAA4sdZw04KGB\n                  XnSyXzyBvP"
    "af+QByOrOXUxBcxehHN/Ox41/duYFXSR40U6lyp49N\n "
    "                 YJ6yEUVWSp4oxsrkcgqyegNKXdW1"
    "D8oqJXzxalbh/RB8YYlX+Ae3\n          "
    "        77gEBlLefPFdSEYDRN/ajs3UIeqde6i20lVyD"
    "PIjEcQIDAQAB">>)
      == CaPubKey
  of
    true -> ok;
    false -> error('Invalid_CA_Certificate')
  end.

verify_lic_cert(CaCert, DerCert) ->
  case public_key:pkix_path_validation(CaCert, [DerCert],
    [])
  of
    {ok, _Info} -> ok;
    {error, {bad_cert, Reason}} -> {error, Reason}
  end.

handle_bad_cert(invalid_issuer, _Cert) ->
  shutdown("Invalid issuer found in license!");
handle_bad_cert(invalid_signature, _Cert) ->
  shutdown("Invalid signature found in license!");
handle_bad_cert(cert_expired, Cert) -> apply(Cert);
handle_bad_cert({revoked, _Reason}, Cert) ->
  emqx_logger:critical("The license is revoked!"),
  apply(Cert);
handle_bad_cert(Reason, Cert) when is_atom(Reason) ->
  shutdown("The license seems invalid: " ++
  atom_to_list(Reason)),
  apply(Cert).

-spec apply(#'OTPCertificate'{}) -> ok.
apply(Cert) ->
  License = read_license(Cert),
  case check_permits(License) of
    true ->
      #{permits := Permits} = License,
      License1 = License#{permits =>Permits#{max_connections => 999999999}},

      ok = apply_permits(License1),
      gen_server:call(emqx_license_mgr, {apply, License}, infinity),
      case maps:get(customer_type, Permits, 2) of
        10 -> evaluation_log();
        _ -> ok
      end;
    false ->
      #{permits := Permits} = License,
      License1 = License#{permits =>Permits#{max_connections => 999999999}},
      ok = apply_permits(License1),
      gen_server:call(emqx_license_mgr, {apply, License}, infinity),
      expiry_log()
  end.

check_permits(#{permits := Permits, validity := {_, End}}) ->
  case calendar:time_difference(calendar:local_time(),
    local_time(End))
  of
    {Days, _Time} when Days < 0 ->
      case maps:get(type, Permits) of
        1 ->
          CType = maps:get(customer_type, Permits, 2),
          case CType =:= 0 andalso Days < -90 of
            true -> false;
            false -> true
          end;
        _ -> false
      end;
    _ -> true
  end.

apply_permits(#{permits :=#{max_connections := ConnLimit}}) ->
  ConnCount = 999999999,
  application:set_env(emqx_license, max_clients, ConnCount).

-spec read_license(#'OTPCertificate'{}) -> license().
read_license(Cert) ->
  {ok, Start, End} = read_validity(Cert),
  Subject = read_subject(Cert),
  {ok, Permits} = read_permits(Cert),
  maps:merge(#{vendor => "EMQ Technologies Co., Ltd.",
    product => emqx_sys:sysdescr(),
    version => emqx_sys:version(), validity => {Start, End},
    permits => Permits},
    Subject).

read_validity(#'OTPCertificate'{tbsCertificate =
#'OTPTBSCertificate'{validity =
Validity}}) ->
  {Start, End} = case Validity of
                   {'Validity', {utcTime, Start0}, {utcTime, End0}} ->
                     {Start0, End0};
                   {'Validity', {utcTime, Start0}, {generalTime, End0}} ->
                     {Start0, End0}
                 end,
  {ok, Start, End}.

local_time([Y01, Y0, Y1, Y2, M1, M2, D1, D2, H1, H2,
  Min1, Min2, S1, S2, $Z]) ->
  {{b2l(<<Y01, Y0, Y1, Y2>>), b2l(<<M1, M2>>),
    b2l(<<D1, D2>>)},
    {b2l(<<H1, H2>>), b2l(<<Min1, Min2>>),
      b2l(<<S1, S2>>)}};
local_time([Y1, Y2, M1, M2, D1, D2, H1, H2, Min1, Min2,
  S1, S2, $Z]) ->
  {{b2l(<<"20", Y1, Y2>>), b2l(<<M1, M2>>),
    b2l(<<D1, D2>>)},
    {b2l(<<H1, H2>>), b2l(<<Min1, Min2>>),
      b2l(<<S1, S2>>)}}.

b2l(L) -> binary_to_integer(L).

datetime([Y01, Y0, Y1, Y2, M1, M2, D1, D2, H1, H2, Min1,
  Min2, S1, S2, $Z]) ->
  lists:flatten(io_lib:format("~c~c~c~c-~c~c-~c~c ~c~c:~c~c:~c~c",
    [Y01, Y0, Y1, Y2, M1, M2, D1, D2, H1, H2, Min1,
      Min2, S1, S2]));
datetime([Y1, Y2, M1, M2, D1, D2, H1, H2, Min1, Min2,
  S1, S2, $Z]) ->
  lists:flatten(io_lib:format("20~c~c-~c~c-~c~c ~c~c:~c~c:~c~c",
    [Y1, Y2, M1, M2, D1, D2, H1, H2, Min1, Min2, S1,
      S2])).

read_subject(#'OTPCertificate'{tbsCertificate =
#'OTPTBSCertificate'{subject =
{rdnSequence,
  RDNs}}}) ->
  read_subject(lists:flatten(RDNs), #{}).

read_subject([], Subject) -> Subject;
read_subject([#'AttributeTypeAndValue'{type =
{2, 5, 4, 3},
  value = V}
  | RDNs],
    Subject) ->
  read_subject(RDNs, maps:put(customer, V, Subject));
read_subject([#'AttributeTypeAndValue'{type =
{2, 5, 4, 10},
  value = V}
  | RDNs],
    Subject) ->
  read_subject(RDNs, maps:put(customer, V, Subject));
read_subject([#'AttributeTypeAndValue'{type =
{1, 2, 840, 113549, 1, 9, 1},
  value = V}
  | RDNs],
    Subject) ->
  read_subject(RDNs, maps:put(email, V, Subject));
read_subject([_ | RDNs], Subject) ->
  read_subject(RDNs, Subject).

read_permits(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{extensions = Extensions}}) ->
  read_permits(Extensions, #{}).

read_permits([], Permits) -> {ok, Permits};
read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 1}, extnValue = Val} | More], Permits) ->
%%  MaxConns = list_to_integer(parse_utf8_string(Val)),
  MaxConns = 999999999,
  read_permits(More, maps:put(max_connections, MaxConns, Permits));

read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 2}, extnValue = Val} | More], Permits) ->
  Plugins = [list_to_atom(Plugin) || Plugin <- string:tokens(parse_utf8_string(Val), ",")],
  read_permits(More, maps:put(enabled_plugins, Plugins, Permits));

read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 3}, extnValue = Val} | More], Permits) ->
  Type = list_to_integer(parse_utf8_string(Val)),
  read_permits(More, maps:put(type, Type, Permits));

read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 4}, extnValue = Val} | More], Permits) ->
  CustomerType = list_to_integer(parse_utf8_string(Val)),
  read_permits(More, maps:put(customer_type, CustomerType, Permits));

read_permits([_ | More], Permits) ->
  read_permits(More, Permits).

parse_utf8_string(Val) ->
  {utf8String, Str} = public_key:der_decode('DisplayText', Val),
  binary_to_list(Str).

shutdown(Msg) ->
  emqx_logger:critical(Msg ++ " System shutdown!"),
  init:stop().

-spec info() -> license().
info() -> gen_server:call(emqx_license_mgr, info, infinity).

init([]) ->
  {ok, monitor(#state{license = #{}, timer = timer_backoff()})}.

handle_call({apply, License}, _From, State) -> {reply, ok, State#state{license = License}};

handle_call(info, _From,
    State = #state{
      license = #{
        customer := {_Text, Customer},
        email := Email,
        permits := Permits,
        product := _Product,
        validity := {Start, End},
        vendor := Vendor,
      version := Version}}) ->
  Expiry = case calendar:time_difference(calendar:local_time(), local_time(End)) of
             {Days, _Time} when Days < 0 -> true;
             _ -> false
           end,
  License = [
    {customer, Customer},
    {email, Email},
    {max_connections, maps:get(max_connections, Permits, 999999999)},
    {issued_at, datetime(Start)},
    {expiry_at, datetime(End)},
    {vendor, Vendor},
    {version, Version},
    {type, type(maps:get(type, Permits, 0))},
    {customer_type, maps:get(customer_type, Permits, 2)},
    {expiry, Expiry}],
  {reply, License, State};
handle_call(_Req, _From, State) ->
  {reply, ignored, State}.

handle_cast(_Msg, State) -> {noreply, State}.

handle_info(check_license, State = #state{license = License}) ->
  case check_permits(License) of
    true -> ok;
    false ->
      #{permits := Permits} = License,
      License1 = License#{permits =>Permits#{max_connections => 999999999}},
      ok = apply_permits(License1),
      expiry_log()
  end,
  {noreply, State};
handle_info({'DOWN', Ref, _Type, _Obj, _Info}, State = #state{monitor = Ref}) ->
  {noreply, checkalive(State)};
handle_info(checkalive, State) ->
  IsAlive = case whereis(emqx) of
              undefined -> false;
              Pid -> is_process_alive(Pid)
            end,
  case IsAlive of
    true ->
      emqx_license_cli:load(), {noreply, monitor(State)};
    false -> {noreply, checkalive(State)}
  end;
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

plugins(Plugins) ->
  list_to_binary(lists:concat(lists:join(", ", Plugins))).

timer_backoff() ->
  {ok, TRef} =
    timer:send_interval(application:get_env(emqx_license, interval, 86400000), check_license),
  TRef.

monitor(State = #state{monitor = MRef}) ->
  MRef /= undefined andalso demonitor(MRef),
  State#state{monitor = monitor(process, emqx)}.

checkalive(State = #state{check_timer = TRef}) ->
  TRef /= undefined andalso erlang:cancel_timer(TRef),
  State#state{check_timer =
  erlang:send_after(1000, self(), checkalive)}.

type(1) -> <<"official">>;
type(0) -> <<"trial">>.

evaluation_log() ->
  emqx_logger:critical("============================================="
  "=================================="),
  emqx_logger:critical("This is an evaluation license that is "
  "restricted to 10000000000 concurrent connections."),
  emqx_logger:critical("If you already have a paid license, "
  "please apply it now."),
  emqx_logger:critical("Or you could visit https://www.emqx.io/licens"
  "e to get a trial license."),
  emqx_logger:critical("============================================="
  "==================================").

expiry_log() ->
  emqx_logger:critical("============================================="
  "========="),
  emqx_logger:critical("Your license has expired."),
  emqx_logger:critical("Please visit https://www.emqx.io/license or"),
  emqx_logger:critical("contact our customer services for an "
  "updated license."),
  emqx_logger:critical("============================================="
  "=========").


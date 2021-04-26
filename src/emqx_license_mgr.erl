%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_license_mgr).
-author("root").
-include("../include/OTP-PUB-KEY.hrl").
-include("../include/PKCS-FRAME.hrl").
-include("../include/public_key.hrl").


-behaviour(gen_server).

-export([start_link/0]).
-export([load/1]).
-export([info/0]).
-export([plugins/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-type license() :: #{
vendor := string(), %% 供应商
product := string(), %% 产品
version := string(), %% 版本
customer := {string(), binary()},
email := string(), %% 邮件
validity := {string(), string()}, %% 有效日期
permits := map(), %% 证书
hostid => string()}.%% 服务器ID

-record(state, {license :: license(), timer, check_timer, monitor}).

%% 启动license 管理服务
-spec start_link() -> {ok, pid()}.
start_link() -> gen_server:start_link({local, emqx_license_mgr}, emqx_license_mgr, [], []).

%% 载入文件
-spec load(undefined | string()) -> ok.
load(undefined) -> shutdown("Cannot find license file!");
%% 传入文件名 载入文件
load(File) ->
%%  读取文件
  case file:read_file(File) of
%%    返回license 信息
    {ok, Lic} ->
%%   公钥验证
      try verify(Lic) of
%%        应用证书
        {ok, Cert} -> apply(Cert);
%%        验证错误
        {error, Reason, Cert} -> handle_bad_cert(Reason, Cert)
      catch
%%        公钥非法
        error:'InvalidPublicKey':_Stk -> shutdown("The Public Key is invalid!");
%%        ca证书非法
        error:'Invalid_CA_Certificate':_Stk -> shutdown("The CA Certificate is invalid!")
      end;
    {error, Reason} ->
      shutdown("Cannot read license file: " ++ atom_to_list(Reason))
  end.

%% 核实 license 信息
-spec verify(Lic :: binary()) -> {ok, #'OTPCertificate'{}} |{error, atom(), #'OTPCertificate'{}}.
verify(Lic) ->
%%  核实公钥
  ok = verify_public_key(),
%%  获取ca文件
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
  #'OTPSubjectPublicKeyInfo'{subjectPublicKey = SubjectPublicKey} = PublicKeyInfo,
  CaPubKey = public_key:der_encode('RSAPublicKey', SubjectPublicKey),
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
  case public_key:pkix_path_validation(CaCert, [DerCert], []) of
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

%% 应用证书
-spec apply(#'OTPCertificate'{}) -> ok.
apply(Cert) ->
%%  读取License
  License = read_license(Cert),
%%  检查证书时间
  case check_permits(License) of
%%    有效期内
    true ->
%%      提取 许可证 Permits
      #{permits := Permits} = License,
%%      应用证书
      ok = apply_permits(License),
%%      进程存储License 信息到state 中
      gen_server:call(emqx_license_mgr, {apply, License}, infinity),
%%      从Permits 获取 customer_type 数据
      case maps:get(customer_type, Permits, 2) of
        10 -> evaluation_log();
        _ -> ok
      end;
%%    时间失效
    false ->
%%      重置License 信息 max_connections 设置为0
      #{permits := Permits} = License, License1 = License#{permits => Permits#{max_connections => 0}},
%%      重新设置 License
      ok = apply_permits(License1),
%%     修改进程的License 信息
      gen_server:call(emqx_license_mgr, {apply, License}, infinity),
%%      打印过期日志
      expiry_log()
  end.

%% 检查许可证
check_permits(#{permits := Permits, validity := {_, End}}) ->
%% T1和T2相差的时间，格式{Days, {Hour, Minute, Seconds}
  case calendar:time_difference(calendar:local_time(), local_time(End)) of
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

%% 应用许可
apply_permits(#{permits := #{max_connections := ConnLimit}}) ->
  io:format("apply_permits: ~p~n", [ConnLimit]),
  ConnCount = 999999999,
%%  设置应用的最大连接数据
  application:set_env(emqx_license, max_clients, ConnCount).

-spec read_license(#'OTPCertificate'{}) -> license().
read_license(Cert) ->
%%  读证书
  {ok, Start, End} = read_validity(Cert),
%%
  Subject = read_subject(Cert),

  {ok, Permits} = read_permits(Cert),
%%  组合一个map
  maps:merge(
    #{vendor => "量子科技", %% 销售公司
    product => emqx_sys:sysdescr(), %% 系统描述
    version => emqx_sys:version(), %% 软件版本
    validity => {Start, End},  %% 有效时间{开始时间，结束时间}
    permits => Permits}, %% 许可证
    Subject).

read_validity(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{validity = Validity}}) ->
  {Start, End} = case Validity of
                   {'Validity', {utcTime, Start0}, {utcTime, End0}} ->
                     {Start0, End0};
                   {'Validity', {utcTime, Start0}, {generalTime, End0}} ->
                     {Start0, End0}
                 end,
  {ok, Start, End}.

%% 本地时间
local_time([Y01,
  Y0,
  Y1,
  Y2,
  M1,
  M2,
  D1,
  D2,
  H1,
  H2,
  Min1,
  Min2,
  S1,
  S2,
  $Z]) ->
  {{b2l(<<Y01, Y0, Y1, Y2>>),
    b2l(<<M1, M2>>),
    b2l(<<D1, D2>>)},
    {b2l(<<H1, H2>>),
      b2l(<<Min1, Min2>>),
      b2l(<<S1, S2>>)}};
local_time([Y1,
  Y2,
  M1,
  M2,
  D1,
  D2,
  H1,
  H2,
  Min1,
  Min2,
  S1,
  S2,
  $Z]) ->
  {{b2l(<<"20", Y1, Y2>>),
    b2l(<<M1, M2>>),
    b2l(<<D1, D2>>)},
    {b2l(<<H1, H2>>),
      b2l(<<Min1, Min2>>),
      b2l(<<S1, S2>>)}}.

b2l(L) -> binary_to_integer(L).

datetime([Y01, Y0, Y1, Y2, M1, M2, D1, D2, H1, H2, Min1, Min2, S1, S2, $Z]) ->
  lists:flatten(io_lib:format("~c~c~c~c-~c~c-~c~c ~c~c:~c~c:~c~c", [Y01, Y0, Y1, Y2, M1, M2, D1, D2, H1, H2, Min1, Min2, S1, S2]));
datetime([Y1,
  Y2,
  M1,
  M2,
  D1,
  D2,
  H1,
  H2,
  Min1,
  Min2,
  S1,
  S2,
  $Z]) ->
  lists:flatten(io_lib:format("20~c~c-~c~c-~c~c ~c~c:~c~c:~c~c",
    [Y1,
      Y2,
      M1,
      M2,
      D1,
      D2,
      H1,
      H2,
      Min1,
      Min2,
      S1,
      S2])).

read_subject(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{subject = {rdnSequence, RDNs}}}) ->
  read_subject(lists:flatten(RDNs), #{}).

read_subject([], Subject) -> Subject;
read_subject([#'AttributeTypeAndValue'{type = {2, 5, 4, 3}, value = V} | RDNs], Subject) ->
  read_subject(RDNs, maps:put(customer, V, Subject));
read_subject([#'AttributeTypeAndValue'{type = {2, 5, 4, 10}, value = V} | RDNs], Subject) ->
  read_subject(RDNs, maps:put(customer, V, Subject));
read_subject([#'AttributeTypeAndValue'{type =
{1, 2, 840, 113549, 1, 9, 1}, value = V} | RDNs], Subject) ->
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

%% 读插件
read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 2}, extnValue = Val} | More], Permits) ->
  Plugins = [list_to_atom(Plugin) || Plugin <- string:tokens(parse_utf8_string(Val), ",")],
  read_permits(More, maps:put(enabled_plugins, Plugins, Permits));
%% 读类型
read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 3}, extnValue = Val} | More], Permits) ->
  Type = list_to_integer(parse_utf8_string(Val)),
  read_permits(More, maps:put(type, Type, Permits));
%% 读CustomerType
read_permits([#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 52509, 4}, extnValue = Val} | More], Permits) ->
  CustomerType = list_to_integer(parse_utf8_string(Val)),
  read_permits(More, maps:put(customer_type, CustomerType, Permits));

read_permits([_ | More], Permits) -> read_permits(More, Permits).

parse_utf8_string(Val) ->
  {utf8String, Str} = public_key:der_decode('DisplayText', Val),
  binary_to_list(Str).

shutdown(Msg) ->
  emqx_logger:critical(Msg ++ " System shutdown!"),
  init:stop().

%% {"data":
%% {
%% "version":"4.2.5",
%% "vendor":"EMQ Technologies Co., Ltd.",
%% "type":"official",
%% "max_connections":10,
%% "issued_at":"2020-06-20 03:02:52",
%% "expiry_at":"2049-01-01 03:02:52",
%% "expiry":false,
%% "email":"contact@emqx.io",
%% "customer_type":10,
%% "customer":"EMQ X Evaluation"},
%% "code":0
%% }
%% 获取 license 信息
-spec info() -> license().
info() -> gen_server:call(emqx_license_mgr, info, infinity).

%% 初始化 {license信息,时间倒退}
init([]) ->
  {ok, monitor(#state{license = #{}, timer = timer_backoff()})}.

%% 进程状态存储License 信息
handle_call({apply, License}, _From, State) ->
  {reply, ok, State#state{license = License}};

handle_call(info, _From, State = #state{license = #{customer := {_Text, Customer}, email := Email, permits := Permits, product := _Product, validity := {Start, End}, vendor := Vendor, version := Version}}) ->
  Expiry = case calendar:time_difference(calendar:local_time(), local_time(End)) of
             {Days, _Time} when Days < 0 -> true;
             _ -> false
           end,
  License = [
    {customer, Customer},
    {email, Email},
    {max_connections, maps:get(max_connections, Permits, 0)}, %% 取最大连接数据
    {issued_at, datetime(Start)}, %% 取最大连接数据
    {expiry_at, datetime(End)}, %% 过期时间
    {vendor, Vendor}, %% 供应商
    {version, Version},%% 版本
    {type, type(maps:get(type, Permits, 0))}, %% 官方
    {customer_type, maps:get(customer_type, Permits, 2)},
    {expiry, Expiry}], %% 是否过期
  {reply, License, State};

handle_call(_Req, _From, State) -> {reply, ignored, State}.
handle_cast(_Msg, State) -> {noreply, State}.

%% 检查证书
handle_info(check_license, State = #state{license = License}) ->
  case check_permits(License) of
    true -> ok;
    false ->
      #{permits := Permits} = License,
      License1 = License#{permits => Permits#{max_connections => 0}},
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
      emqx_license_cli:load(),
      {noreply, monitor(State)};
    false -> {noreply, checkalive(State)}
  end;
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

plugins(Plugins) -> list_to_binary(lists:concat(lists:join(", ", Plugins))).

timer_backoff() ->
%%  使用timer:send_interval/3设置事件间隔 {timer,check_license-事件}
  {ok, TRef} = timer:send_interval(application:get_env(emqx_license, interval, 86400000), check_license),
  TRef.

monitor(State = #state{monitor = MRef}) ->
  MRef /= undefined andalso demonitor(MRef),
  State#state{monitor = monitor(process, emqx)}.

checkalive(State = #state{check_timer = TRef}) ->
  TRef /= undefined andalso erlang:cancel_timer(TRef),
  State#state{check_timer = erlang:send_after(1000, self(), checkalive)}.

type(1) -> <<"official">>;
type(0) -> <<"trial">>.

%% 评审 日志
evaluation_log() ->
  emqx_logger:critical("============================================="
  "=================================="),
  emqx_logger:critical("This is an evaluation license that is "
  "restricted to 10 concurrent connections."),
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


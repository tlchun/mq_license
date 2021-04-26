%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_license).
-author("root").

-export([logger_header/0]).
-include("../include/logger.hrl").
-include("../include/emqx_mqtt.hrl").


-export([load/0, unload/0]).
-export([check/2]).


load() -> emqx:hook('client.connect', fun emqx_license:check/2, []).

unload() -> emqx:unhook('client.connect', fun emqx_license:check/2).

check(_ConnInfo, AckProps) ->
%% 检查最大客户端
  case check_max_clients() of
%%    返回数true
    true ->
%%      获取配置文件max_clients 的参数，默认 999999999
      case application:get_env(emqx_license, max_clients, 999999999) of
        0 ->
          begin
            logger:log(error, #{}, #{report_cb => fun (_) -> {logger_header() ++ "Connection rejected due to the license expiration", []} end, mfa => {emqx_license, check, 2}, line => 26})
          end;
        _ ->
          begin
            logger:log(error, #{}, #{report_cb => fun (_) -> {logger_header() ++ "Connection rejected due to max clients limitation", []} end, mfa => {emqx_license, check, 2}, line => 27})
          end
      end,
      {stop, {error, 151}};
    false -> {ok, AckProps}
  end.

%% 检查最大客户端连接
check_max_clients() ->
%%  当期连接信息
  CurrentClientSize = ets:info(emqx_channel_conn, size),
%%  最大客户端连接
  MaxClients = application:get_env(emqx_license, max_clients, 999999999),
  io:format("----------------------------------MaxClients ~p~n",[MaxClients]),
%%  当期连接 大于 客户端最大连接
  CurrentClientSize >= MaxClients.

logger_header() -> "".


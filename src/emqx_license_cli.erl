%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_license_cli).
-author("root").

-export([load/0, license/1, unload/0]).

%% 注册一个命令服务进程
load() ->
  emqx_ctl:register_command(license, {emqx_license_cli, license}, []).

%% 加载license 文件
license(["reload", File]) ->
%%  管理加载license 文件
  case emqx_license_mgr:load(File) of
%%    成功
    ok -> io:format("ok~n");
%%   失败
    {error, Reason} -> io:format("Error: ~p~n", [Reason])
  end;

%%
license(["info"]) ->
  lists:foreach(fun ({K, V}) when is_binary(V); is_atom(V); is_list(V) ->
    io:format("~-16s: ~s~n", [K, V]);
    ({K, V}) -> io:format("~-16s: ~p~n", [K, V]) end,
    emqx_license_mgr:info());

license(_) ->
  emqx_ctl:usage([{"license info", "Show license info"}, {"license reload <File>", "Load a new license file"}]).

%% 注销命令进程
unload() -> emqx_ctl:unregister_command(license).

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


load() ->
  emqx_ctl:register_command(license, {emqx_license_cli, license}, []).

license(["reload", File]) ->
  case emqx_license_mgr:load(File) of
    ok -> io:format("ok~n");
    {error, Reason} -> io:format("Error: ~p~n", [Reason])
  end;

license(["info"]) ->
  lists:foreach(fun ({K, V}) when is_binary(V); is_atom(V); is_list(V) ->
    io:format("~-16s: ~s~n", [K, V]);
    ({K, V}) -> io:format("~-16s: ~p~n", [K, V]) end,
    emqx_license_mgr:info());

license(_) ->
  emqx_ctl:usage([{"license info", "Show license info"}, {"license reload <File>", "Load a new license file"}]).

unload() -> emqx_ctl:unregister_command(license).

%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_license_app).
-author("root").

-behaviour(application).
-export([start/2, stop/1]).


start(_Type, _Args) ->
  {ok, Sup} = emqx_license_sup:start_link(),
  emqx_license_mgr:load(application:get_env(emqx, license_file, undefined)),
  emqx_license:load(),
  emqx_license_cli:load(),
  {ok, Sup}.

stop(_State) ->
  emqx_license:load(),
  emqx_license_cli:unload(),
  ok.


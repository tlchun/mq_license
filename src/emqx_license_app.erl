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

%% 启动应用
start(_Type, _Args) ->
%%  启动应用监听器
  {ok, Sup} = emqx_license_sup:start_link(),
%%  载入license 管理
  emqx_license_mgr:load(application:get_env(emqx, license_file, undefined)),
%%  载入license 管理
  emqx_license:load(),
%%  license服务客户端
  emqx_license_cli:load(),
  {ok, Sup}.

stop(_State) ->
  emqx_license:load(),
  emqx_license_cli:unload(),
  ok.


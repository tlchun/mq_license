%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_license_sup).
-author("root").

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).


start_link() ->
  supervisor:start_link({local, emqx_license_sup}, emqx_license_sup, []).

init([]) ->
  {ok,
    {{one_for_one, 10, 100},
      [#{id => license_mgr, start => {emqx_license_mgr, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [emqx_license_mgr]}]}}.


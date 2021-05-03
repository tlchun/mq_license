%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2021, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. 4月 2021 上午9:50
%%%-------------------------------------------------------------------
-module(emqx_exhook_entr).
-author("root").
-export([logger_header/0]).
-include("../include/emqx.hrl").
-include("../include/logger.hrl").


-export([on_message_publish/1, on_message_dropped/3, on_message_delivered/2, on_message_acked/2]).
-import(emqx_exhook, [cast/2, call_fold/3]).
-import(emqx_exhook_handler, [message/1, assign_to_message/2, clientinfo/1, stringfy/1]).

-exhooks([{'message.publish', {emqx_exhook_entr, on_message_publish, []}},
  {'message.delivered', {emqx_exhook_entr, on_message_delivered, []}},
  {'message.acked', {emqx_exhook_entr, on_message_acked, []}},
  {'message.dropped', {emqx_exhook_entr, on_message_dropped, []}}]).

%% 推送系统主题消息
on_message_publish(#message{topic = <<"$SYS/", _/binary>>}) -> ok;
on_message_publish(Message) ->
  Req = #{message => message(Message)},
  case call_fold('message.publish', Req, fun emqx_exhook_handler:merge_responsed_message/2) of
    {StopOrOk, #{message := NMessage}} ->
      {StopOrOk, assign_to_message(NMessage, Message)};
    _ -> {ok, Message}
  end.

%% 系统消息落地
on_message_dropped(#message{topic = <<"$SYS/", _/binary>>}, _By, _Reason) -> ok;
on_message_dropped(Message, _By, Reason) ->
  Req = #{message => message(Message), reason => stringfy(Reason)},
  cast('message.dropped', Req).

%% 系统消息投递
on_message_delivered(_ClientInfo, #message{topic = <<"$SYS/", _/binary>>}) -> ok;
on_message_delivered(ClientInfo, Message) ->
  Req = #{clientinfo => clientinfo(ClientInfo), message => message(Message)},
  cast('message.delivered', Req).

%% 系统消息回复
on_message_acked(_ClientInfo, #message{topic = <<"$SYS/", _/binary>>}) -> ok;
on_message_acked(ClientInfo, Message) ->
  Req = #{clientinfo => clientinfo(ClientInfo), message => message(Message)},
  cast('message.acked', Req).

logger_header() -> "".


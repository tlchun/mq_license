{application,emqx_license,
             [{description,"EMQ X License"},
              {vsn,"4.2.5"},
              {modules,
                [emqx_exhook_entr,
                  emqx_license,
                  emqx_license_app,
                  emqx_license_cli,
                  emqx_license_mgr,
                  emqx_license_sup]},
              {registered,[emqx_license_sup]},
              {applications,[kernel,stdlib]},
              {mod,{emqx_license_app,[]}},
              {relup_deps,[emqx]}]}.


%% {ok,{_,[{abstract_code,{_,AC}}]}} = beam_lib:chunks(emqx_license_mgr,[abstract_code]).
%% io:fwrite("~s~n", [erl_prettypr:format(erl_syntax:form_list(AC))]).

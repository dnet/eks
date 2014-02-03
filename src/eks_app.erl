%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Callbacks for the eks application.

-module(eks_app).
-author('author <author@example.com>').

-behaviour(application).
-export([start/2,stop/1]).


%% @spec start(_Type, _StartArgs) -> ServerRet
%% @doc application start callback for eks.
start(_Type, _StartArgs) ->
    eks_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for eks.
stop(_State) ->
    ok.

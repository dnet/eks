%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc eks startup code

-module(eks).
-author('author <author@example.com>').
-export([start/0, start_link/0, stop/0]).

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

%% @spec start_link() -> {ok,Pid::pid()}
%% @doc Starts the app for inclusion in a supervisor tree
start_link() ->
    ensure_started(inets),
    ensure_started(asn1),
    ensure_started(crypto),
    ensure_started(public_key),
    ensure_started(ssl),
    ensure_started(xmerl),
    ensure_started(compiler),
    ensure_started(syntax_tools),
    ensure_started(mochiweb),
    mnesia:create_schema([node()]),
    ensure_started(mnesia),
    pgp_keystore:init_schema(),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    eks_sup:start_link().

%% @spec start() -> ok
%% @doc Start the eks server.
start() ->
    ensure_started(inets),
    ensure_started(asn1),
    ensure_started(crypto),
    ensure_started(public_key),
    ensure_started(ssl),
    ensure_started(xmerl),
    ensure_started(compiler),
    ensure_started(syntax_tools),
    ensure_started(mochiweb),
    mnesia:create_schema([node()]),
    ensure_started(mnesia),
    pgp_keystore:init_schema(),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    application:start(eks).

%% @spec stop() -> ok
%% @doc Stop the eks server.
stop() ->
    Res = application:stop(eks),
    application:stop(webmachine),
    application:stop(mnesia),
    application:stop(mochiweb),
    application:stop(crypto),
    application:stop(inets),
    Res.

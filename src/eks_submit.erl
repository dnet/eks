-module(eks_submit).
-export([init/1, allowed_methods/2, process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) -> {['POST'], ReqData, State}.

process_post(ReqData, State) ->
	QS = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
	{_, KeyText} = lists:keyfind("keytext", 1, QS),
	Key = pgp_parse:decode_stream(list_to_binary(KeyText), [armor]),
	io:format("K: ~p\n", [Key]),
	{true, ReqData, State}.

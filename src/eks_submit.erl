-module(eks_submit).
-export([init/1, allowed_methods/2, process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) -> {['POST'], ReqData, State}.

process_post(ReqData, State) ->
	QS = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
	{_, KeyText} = lists:keyfind("keytext", 1, QS),
	KeyBody = keylines(binary:split(list_to_binary(KeyText), <<$\n>>, [global])),
	Key = base64:decode(KeyBody),
	io:format("K: ~p\n", [Key]),
	{true, ReqData, State}.

keylines([<<"-----BEGIN PGP PUBLIC KEY BLOCK-----">> | Rest]) -> keylines(Rest, <<>>);
keylines([_ | Lines]) -> keylines(Lines);
keylines([]) -> missing_header.

keylines([], Acc) -> Acc;
keylines([<<>> | Rest], Acc) -> keylines(Rest, Acc);
keylines([<<"Version: ", _/binary>> | Rest], Acc) -> keylines(Rest, Acc);
keylines([<<$=, _/binary>> | Rest], Acc) -> keylines(Rest, Acc);
keylines([<<"-----END PGP PUBLIC KEY BLOCK-----">> | _], Acc) -> Acc;
keylines([Line | Rest], Acc) -> keylines(Rest, <<Acc/binary, Line/binary>>).

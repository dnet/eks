-module(eks_lookup).
-export([init/1, to_html/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

to_html(ReqData, Ctx) ->
	SearchTerm = wrq:get_qs_value("search", ReqData),
	case wrq:get_qs_value("op", ReqData) of
		"get" ->
			case pgp_keystore:find_keys(parse_keyid(SearchTerm)) of
				[] ->
					{ok, HTML} = no_results_dtl:render([{title, "No results found"}]),
					Headers = [{"Content-Type", "text/html; charset=utf-8"}],
					RD404 = wrq:set_resp_body(HTML, wrq:set_resp_headers(Headers, ReqData)),
					{{halt, 404}, RD404, Ctx};
				Keys ->
					Payload = io_lib:format("~p\n", [Keys]), %% TODO
					Title = ["Public Key Server -- Get ``", string:to_lower(SearchTerm), " ''"],
					{ok, HTML} = results_dtl:render([{payload, Payload}, {title, Title}]),
					{HTML, ReqData, Ctx}
			end
		%% "search" -> TODO
	end.

parse_keyid([$0, $x | HexID]) -> mochihex:to_bin(HexID).
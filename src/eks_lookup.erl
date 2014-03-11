-module(eks_lookup).
-export([init/1, to_html/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

to_html(ReqData, Ctx) ->
	SearchTerm = wrq:get_qs_value("search", ReqData),
	case wrq:get_qs_value("op", ReqData) of
		"get" ->
			case pgp_keystore:find_keys(parse_keyid(SearchTerm), [parents]) of
				[] ->
					{ok, HTML} = no_results_dtl:render([{title, "No results found"}]),
					Headers = [{"Content-Type", "text/html; charset=utf-8"}],
					RD404 = wrq:set_resp_body(HTML, wrq:set_resp_headers(Headers, ReqData)),
					{{halt, 404}, RD404, Ctx};
				Keys ->
					Payload = pgp_armor:encode(<< <<(pgp_parse:encode_key(K))/binary>> || K <- Keys >>),
					Title = ["Public Key Server -- Get ``", string:to_lower(SearchTerm), " ''"],
					{ok, HTML} = results_dtl:render([{payload, Payload}, {title, Title}]),
					{HTML, ReqData, Ctx}
			end;
		"index" ->
			Title = ["Search results for '", SearchTerm, "'"],
			Results = [{"ID32ID32", "ID64ID64ID64ID64", "YYYY-MM-DD", "4096R",
						["First UID for testing <test@test.hu>",
						 "Second UID in another row <foo@bar.hu>"]}], %% TODO use keystore
			{ok, HTML} = index_dtl:render([{title, Title}, {results, Results}]),
			{HTML, ReqData, Ctx}
	end.

parse_keyid([$0, $x | HexID]) -> mochihex:to_bin(HexID).

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
			Title = ["Search results for '", string:to_lower(SearchTerm), "'"],
			KeysByID = try pgp_keystore:find_keys(parse_keyid(SearchTerm), [parents]) of
				K -> K
			catch
				_:_ -> []
			end,
			KeysByText = pgp_keystore:search_keys(list_to_binary(SearchTerm)),
			Results = [format_key(Key, false) || Key <- KeysByID ++ KeysByText], %% TODO efficiency, SMP
			{ok, HTML} = index_dtl:render([{title, Title}, {results, Results}]),
			{HTML, ReqData, Ctx};
		"vindex" ->
			Title = ["Search results for '", string:to_lower(SearchTerm), "'"],
			KeysByID = try pgp_keystore:find_keys(parse_keyid(SearchTerm), [parents]) of
				K -> K
			catch
				_:_ -> []
			end,
			KeysByText = pgp_keystore:search_keys(list_to_binary(SearchTerm)),
			Results = [format_key(Key, true) || Key <- KeysByID ++ KeysByText], %% TODO efficiency, SMP
			{ok, HTML} = vindex_dtl:render([{title, Title}, {results, Results}]),
			{HTML, ReqData, Ctx}
	end.

format_key(Key, IncludeSignatures) ->
	{Timestamp, ParsedKey} = pgp_parse:decode_public_key(Key),
	KeyID = pgp_parse:key_id(pgp_parse:c14n_pubkey(Key)),
	{ID32, ID64} = pgp_keystore:short_ids(KeyID),
	KeyParams = case ParsedKey of
		{rsa, [_, N]} -> [bit_size(N), $R];
		{dss, [P | _]} -> [bit_size(P), $D]
	end,
	KeyInfo = io_lib:format("~B~c", KeyParams),
	SignatureMapper = case IncludeSignatures of
		true -> fun ({UID, Sigs}) -> {UID, [format_sig(S, ID64, Timestamp) || S <- Sigs]} end;
		false -> fun ({UID, _}) -> UID end
	end,
	UIDs = lists:map(SignatureMapper, pgp_keystore:get_signatures(KeyID)),
	{upperhex(ID32), upperhex(ID64), unix_to_iso_date(Timestamp), KeyInfo, UIDs}.

format_sig(Signature, Parent, KeyCre) ->
	[SigExp, SigCre, PolicyURI, Issuer, KeyExp, SigLevel | _] = pgp_parse:decode_signature_packet(Signature),
	<<_:4/binary, ID32:4/binary>> = Issuer,
	IssuerName = case Issuer of
		Parent -> <<"[selfsig]">>;
		_ ->
			case pgp_keystore:get_signatures(Issuer) of
				[{UID, _} | _] -> UID;
				_ -> undefined
			end
	end,
	{upperhex(ID32), upperhex(Issuer), unix_to_iso_date(SigExp, SigCre),
		unix_to_iso_date(SigCre), unix_to_iso_date(KeyExp, KeyCre),
		SigLevel, PolicyURI, IssuerName}.

unix_to_iso_date(Timestamp) -> unix_to_iso_date(Timestamp, 0).
unix_to_iso_date(Timestamp, Base) when is_integer(Timestamp), is_integer(Base) ->
	{{Y, M, D}, _} = calendar:now_to_datetime({0, Timestamp + Base, 0}),
	io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B", [Y, M, D]);
unix_to_iso_date(_, _) -> "__________".

upperhex(Value) -> string:to_upper(mochihex:to_hex(Value)).

parse_keyid([$0, $x | HexID]) -> mochihex:to_bin(HexID).

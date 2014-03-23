-module(eks_lookup).
-export([init/1, to_html/2]).

-include_lib("webmachine/include/webmachine.hrl").

-define(MACHINE_READABLE, "mr").

init([]) -> {ok, undefined}.

to_html(ReqData, Ctx) ->
	SearchTerm = wrq:get_qs_value("search", ReqData),
	Options = wrq:get_qs_value("options", ReqData),
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
					case Options of
						?MACHINE_READABLE ->
							Headers = [{"X-HKP-Results-Count", integer_to_list(length(Keys))},
									   {"Content-Type", "application/pgp-keys; charset=UTF-8"},
									   {"Content-disposition", "attachment; filename=gpgkey.asc"}],
							{Payload, wrq:set_resp_headers(Headers, ReqData), Ctx};
						_ ->
							Title = ["Public Key Server -- Get ``", string:to_lower(SearchTerm), " ''"],
							{ok, HTML} = results_dtl:render([{payload, Payload}, {title, Title}]),
							{HTML, ReqData, Ctx}
					end
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
	SF = case IncludeSignatures of true -> fun format_sig/3; false -> undefined end,
	{HexID32, HexID64, UnixTS, KeyType, KeyLength, UIDs} = parse_key(Key, SF),
	KeyInfo = io_lib:format("~B~c", [KeyLength, hd(string:to_upper(atom_to_list(KeyType)))]),
	{HexID32, HexID64, unix_to_iso_date(UnixTS), KeyInfo, UIDs}.

parse_key(Key, SignatureFormatter) ->
	{Timestamp, ParsedKey} = pgp_parse:decode_public_key(Key),
	KeyID = pgp_parse:key_id(pgp_parse:c14n_pubkey(Key)),
	{ID32, ID64} = pgp_keystore:short_ids(KeyID),
	KeyLength = case ParsedKey of
		{rsa, [_, N]} -> bit_size(N);
		{dss, [P | _]} -> bit_size(P)
	end,
	SignatureMapper = case is_function(SignatureFormatter) of
		true -> fun ({UID, Sigs}) -> {UID, [SignatureFormatter(S, ID64, Timestamp) || S <- prepare_sigs(Sigs)]} end;
		false -> fun ({UID, _}) -> UID end
	end,
	UIDs = lists:map(SignatureMapper, pgp_keystore:get_signatures(KeyID)),
	{upperhex(ID32), upperhex(ID64), Timestamp, element(1, ParsedKey), KeyLength, UIDs}.

prepare_sigs(Signatures) ->
	Fetched = [begin [SE, SC, PU, I, KE, SL | _] = pgp_parse:decode_signature_packet(Signature),
		{SE, SC, PU, I, KE, SL} end || Signature <- Signatures],
	lists:keysort(2, Fetched).

format_sig({SigExp, SigCre, PolicyURI, Issuer, KeyExp, SigLevel}, Parent, KeyCre) ->
	<<_:4/binary, ID32:4/binary>> = Issuer,
	IssuerName = case Issuer of
		Parent -> <<"[selfsig]">>;
		_ ->
			case pgp_keystore:get_signatures(Issuer) of
				[{UID, _} | _] -> UID;
				_ -> undefined
			end
	end,
	SigExpired = case {SigExp, SigCre} of
		{E, C} when is_integer(E), is_integer(C) ->
			{MS, S, _} = os:timestamp(),
			MS * 1000000 + S >= E + C;
		_ -> false
	end,
	{upperhex(ID32), upperhex(Issuer), unix_to_iso_date(SigExp, SigCre),
		unix_to_iso_date(SigCre), unix_to_iso_date(KeyExp, KeyCre),
		SigLevel, SigExpired, PolicyURI, IssuerName}.

unix_to_iso_date(Timestamp) -> unix_to_iso_date(Timestamp, 0).
unix_to_iso_date(Timestamp, Base) when is_integer(Timestamp), is_integer(Base) ->
	{{Y, M, D}, _} = calendar:now_to_datetime({0, Timestamp + Base, 0}),
	io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B", [Y, M, D]);
unix_to_iso_date(_, _) -> "__________".

upperhex(Value) -> string:to_upper(mochihex:to_hex(Value)).

parse_keyid([$0, $x | HexID]) -> mochihex:to_bin(HexID).

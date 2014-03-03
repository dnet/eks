-module(eks_submit).
-export([init/1, allowed_methods/2, process_post/2, decode_pubkey/2, decode_pubkey/1]).

-include_lib("webmachine/include/webmachine.hrl").

-define(PUBKEY_PACKET, 6).
-define(PGP_VERSION, 4).

-define(CRC24_INIT, 16#B704CE).
-define(CRC24_POLY, 16#1864CFB).

-define(PK_ALGO_RSA_ES, 1).
-define(PK_ALGO_RSA_E, 2).
-define(PK_ALGO_RSA_S, 3).
-define(PK_ALGO_ELGAMAL, 16).
-define(PK_ALGO_DSA, 17).

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) -> {['POST'], ReqData, State}.

process_post(ReqData, State) ->
	QS = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
	{_, KeyText} = lists:keyfind("keytext", 1, QS),
	{KeyBody64, CRC} = keylines(binary:split(list_to_binary(KeyText), <<$\n>>, [global])),
	KeyBody = base64:decode(KeyBody64),
	CRC = base64:encode(<<(crc24(KeyBody)):24/integer-big>>),
	Key = decode_pubkey(KeyBody),
	io:format("K: ~p\n", [Key]),
	{true, ReqData, State}.

decode_pubkey(Data, []) -> decode_pubkey(Data);
decode_pubkey(Data, Opts) ->
	case lists:delete(file, Opts) of
		Opts ->
			case lists:delete(armor, Opts) of
				Opts -> decode_pubkey(Data, []);
				NewOpts -> decode_pubkey(decode_armor(Data), NewOpts)
			end;
		NewOpts ->
			{ok, Contents} = file:read_file(Data),
			decode_pubkey(Contents, NewOpts)
	end.
decode_pubkey(<<F:2/integer-big, ?PUBKEY_PACKET:4/integer-big, LenBits:2/integer-big, Body/binary>>) ->
	{<<?PGP_VERSION, Timestamp:32/integer-big, Algorithm, KeyRest/binary>>, S2Rest} = case LenBits of
		0 -> <<Length, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		1 -> <<Length:16/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		2 -> <<Length:32/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest}
	end,
	Key = decode_pubkey_algo(Algorithm, KeyRest),
	io:format("~p\n", [{F, Timestamp, Algorithm, Key}]),
	decode_pubkey(S2Rest);
decode_pubkey(Data) ->
	io:format("~p\n", [mochihex:to_hex(Data)]).

decode_pubkey_algo(RSA, <<NLen:16/integer-big, NRest/binary>>)
  when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_E; RSA =:= ?PK_ALGO_RSA_S ->
	NBytes = ((NLen + 7) div 8) * 8,
	<<N:NBytes/integer-big, ELen:16/integer-big, ERest/binary>> = NRest,
	EBytes = ((ELen + 7) div 8) * 8,
	<<E:EBytes/integer-big>> = ERest,
	{rsa_public, [E, N]}.

decode_armor(KeyText) ->
	{KeyBody64, CRC} = keylines(binary:split(list_to_binary(KeyText), <<$\n>>, [global])),
	KeyBody = base64:decode(KeyBody64),
	CRC = base64:encode(<<(crc24(KeyBody)):24/integer-big>>),
	KeyBody.

keylines([<<"-----BEGIN PGP PUBLIC KEY BLOCK-----">> | Rest]) -> keylines(Rest, <<>>, no_sum);
keylines([_ | Lines]) -> keylines(Lines);
keylines([]) -> missing_header.

keylines([], Acc, CRC) -> {Acc, CRC};
keylines([<<>> | Rest], Acc, CRC) -> keylines(Rest, Acc, CRC);
keylines([<<"Version: ", _/binary>> | Rest], Acc, CRC) -> keylines(Rest, Acc, CRC);
keylines([<<$=, CRC/binary>> | Rest], Acc, _) -> keylines(Rest, Acc, CRC);
keylines([<<"-----END PGP PUBLIC KEY BLOCK-----">> | _], Acc, CRC) -> {Acc, CRC};
keylines([Line | Rest], Acc, CRC) -> keylines(Rest, <<Acc/binary, Line/binary>>, CRC).

crc24(Data) -> crc24(Data, ?CRC24_INIT).
crc24(<<>>, Acc) -> Acc;
crc24(<<Byte, Rest/binary>>, Acc) ->
	NewAcc = Acc bxor (Byte bsl 16),
	crc24(Rest, crc24_shift(NewAcc, 8)).

crc24_shift(CRC, Count) when CRC band 16#1000000 =/= 0 ->
	crc24_shift(CRC bxor ?CRC24_POLY, Count);
crc24_shift(CRC, 0) -> CRC;
crc24_shift(CRC, Count) -> crc24_shift(CRC bsl 1, Count - 1).

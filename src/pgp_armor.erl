-module(pgp_armor).
-export([decode/1]).

-define(CRC24_INIT, 16#B704CE).
-define(CRC24_POLY, 16#1864CFB).

-define(PGP_PUBKEY_HEADER, <<"-----BEGIN PGP PUBLIC KEY BLOCK-----">>).
-define(PGP_PUBKEY_FOOTER, <<"-----END PGP PUBLIC KEY BLOCK-----">>).
-define(PGP_VERSION_PREFIX, "Version: ").

decode(KeyText) ->
	{KeyBody64, CRC} = keylines(binary:split(KeyText, <<$\n>>, [global])),
	KeyBody = base64:decode(KeyBody64),
	CRC = base64:encode(<<(crc24(KeyBody)):24/integer-big>>),
	KeyBody.

keylines([?PGP_PUBKEY_HEADER | Rest]) -> keylines(Rest, <<>>, no_sum);
keylines([_ | Lines]) -> keylines(Lines);
keylines([]) -> missing_header.

keylines([], Acc, CRC) -> {Acc, CRC};
keylines([<<>> | Rest], Acc, CRC) -> keylines(Rest, Acc, CRC);
keylines([<<?PGP_VERSION_PREFIX, _/binary>> | Rest], Acc, CRC) -> keylines(Rest, Acc, CRC);
keylines([<<$=, CRC/binary>> | Rest], Acc, _) -> keylines(Rest, Acc, CRC);
keylines([?PGP_PUBKEY_FOOTER | _], Acc, CRC) -> {Acc, CRC};
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

-module(eks_submit).
-export([init/1, allowed_methods/2, process_post/2, decode_stream/2, decode_stream/1]).

-include_lib("webmachine/include/webmachine.hrl").

-define(OLD_PACKET_FORMAT, 2).
-define(SIGNATURE_PACKET, 2).
-define(PUBKEY_PACKET, 6).
-define(UID_PACKET, 13).
-define(SUBKEY_PACKET, 14).
-define(PGP_VERSION, 4).

-define(CRC24_INIT, 16#B704CE).
-define(CRC24_POLY, 16#1864CFB).

-define(PK_ALGO_RSA_ES, 1).
-define(PK_ALGO_RSA_E, 2).
-define(PK_ALGO_RSA_S, 3).
-define(PK_ALGO_ELGAMAL, 16).
-define(PK_ALGO_DSA, 17).

-define(HASH_ALGO_MD5, 1).
-define(HASH_ALGO_SHA1, 2).
-define(HASH_ALGO_RIPEMD160, 3).
-define(HASH_ALGO_SHA256, 8).
-define(HASH_ALGO_SHA384, 9).
-define(HASH_ALGO_SHA512, 10).
-define(HASH_ALGO_SHA224, 11).

-record(decoder_ctx, {primary_key, subkey, uid}).

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) -> {['POST'], ReqData, State}.

process_post(ReqData, State) ->
	QS = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
	{_, KeyText} = lists:keyfind("keytext", 1, QS),
	Key = decode_stream(list_to_binary(KeyText), [armor]),
	io:format("K: ~p\n", [Key]),
	{true, ReqData, State}.

decode_stream(Data) -> decode_packets(Data, #decoder_ctx{}).
decode_stream(Data, []) -> decode_stream(Data);
decode_stream(Data, Opts) ->
	case lists:delete(file, Opts) of
		Opts ->
			case lists:delete(armor, Opts) of
				Opts -> decode_stream(Data, []);
				NewOpts -> decode_stream(decode_armor(Data), NewOpts)
			end;
		NewOpts ->
			{ok, Contents} = file:read_file(Data),
			decode_stream(Contents, NewOpts)
	end.
decode_packets(<<?OLD_PACKET_FORMAT:2/integer-big, Tag:4/integer-big,
				LenBits:2/integer-big, Body/binary>>, Context) ->
	{PacketData, S2Rest} = case LenBits of
		0 -> <<Length, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		1 -> <<Length:16/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		2 -> <<Length:32/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest}
	end,
	NewContext = decode_packet(Tag, PacketData, Context),
	decode_packets(S2Rest, NewContext);
decode_packets(Data, _) ->
	io:format("~p\n", [mochihex:to_hex(Data)]).

decode_packet(?SIGNATURE_PACKET, <<?PGP_VERSION, SigType, PubKeyAlgo, HashAlgo,
								   HashedLen:16/integer-big, HashedData:HashedLen/binary,
								   UnhashedLen:16/integer-big, UnhashedData:UnhashedLen/binary,
								   HashLeft16:2/binary, Signature/binary>>, Context) ->
	HashCtx = crypto:hash_init(pgp_to_crypto_hash_algo(HashAlgo)),
	FinalCtx = case SigType of
		%% 0x18: Subkey Binding Signature
		%% 0x19: Primary Key Binding Signature
		KeyBinding when KeyBinding =:= 16#18; KeyBinding =:= 16#19 ->
			crypto:hash_update(crypto:hash_update(HashCtx,
				Context#decoder_ctx.primary_key), Context#decoder_ctx.subkey);
		%% 0x10: Generic certification of a User ID and Public-Key packet.
		%% 0x11: Persona certification of a User ID and Public-Key packet.
		%% 0x12: Casual certification of a User ID and Public-Key packet.
		%% 0x13: Positive certification of a User ID and Public-Key packet.
		Cert when Cert >= 16#10, Cert =< 16#13 ->
			crypto:hash_update(crypto:hash_update(HashCtx,
				Context#decoder_ctx.primary_key), Context#decoder_ctx.uid);
		_ -> io:format("Unknown SigType ~p\n", [SigType]), HashCtx %% XXX
	end,
	FinalData = <<?PGP_VERSION, SigType, PubKeyAlgo, HashAlgo,
				  HashedLen:16/integer-big, HashedData/binary>>,
	Trailer = <<?PGP_VERSION, 16#FF, (byte_size(FinalData)):32/integer-big>>,
	Expected = crypto:hash_final(crypto:hash_update(crypto:hash_update(FinalCtx, FinalData), Trailer)),
	<<HashLeft16:2/binary, _/binary>> = Expected,
	io:format("Hashed: ~s\n", [mochihex:to_hex(HashedData)]),
	decode_signed_subpackets(HashedData),
	decode_signed_subpackets(UnhashedData),
	io:format("SIGNATURE: ~p\n", [{SigType, PubKeyAlgo, HashAlgo, HashedLen, UnhashedLen,
								   HashLeft16}]),
	Context;
decode_packet(Tag, <<?PGP_VERSION, Timestamp:32/integer-big, Algorithm, KeyRest/binary>> = KeyData, Context)
  when Tag =:= ?PUBKEY_PACKET; Tag =:= ?SUBKEY_PACKET ->
	Key = decode_pubkey_algo(Algorithm, KeyRest),
	Subject = <<16#99, (byte_size(KeyData)):16/integer-big, KeyData/binary>>,
	KeyID = crypto:hash(sha, Subject),
	io:format("PUBKEY: ~p\n", [{Timestamp, Key, mochihex:to_hex(KeyID)}]),
	case Tag of
		?PUBKEY_PACKET -> Context#decoder_ctx{primary_key = Subject};
		?SUBKEY_PACKET -> Context#decoder_ctx{subkey = Subject}
	end;
decode_packet(?UID_PACKET, UID, Context) ->
	io:format("UID: ~p\n", [UID]),
	Context#decoder_ctx{uid = <<16#B4, (byte_size(UID)):32/integer-big, UID/binary>>}.

decode_signed_subpackets(<<>>) -> ok;
decode_signed_subpackets(<<Length, Payload:Length/binary, Rest/binary>>) when Length < 192 ->
	decode_signed_subpacket(Payload),
	decode_signed_subpackets(Rest);
decode_signed_subpackets(<<LengthHigh, LengthLow, PayloadRest/binary>>) when LengthHigh < 255 ->
	Length = ((LengthHigh - 192) bsl 8) bor LengthLow,
	<<Payload:Length/binary, Rest/binary>> = PayloadRest,
	decode_signed_subpacket(Payload),
	decode_signed_subpackets(Rest);
decode_signed_subpackets(<<255, Length:32/integer-big, Payload:Length/binary, Rest/binary>>) ->
	decode_signed_subpacket(Payload),
	decode_signed_subpackets(Rest).

%% 2 = Signature Creation Time
decode_signed_subpacket(<<2, Timestamp:32/integer-big>>) ->
	io:format("Signature Creation Time: ~p\n", [Timestamp]);
%% 9 = Key Expiration Time
decode_signed_subpacket(<<9, Timestamp:32/integer-big>>) ->
	io:format("Key Expiration Time: ~p\n", [Timestamp]);
%% 11 = Preferred Symmetric Algorithms
decode_signed_subpacket(<<11, Algorithms/binary>>) ->
	io:format("Preferred Symmetric Algorithms: ~p\n", [Algorithms]);
%% 16 = Issuer
decode_signed_subpacket(<<16, Issuer:8/binary>>) ->
	io:format("Issuer: ~p\n", [mochihex:to_hex(Issuer)]);
%% 21 = Preferred Hash Algorithms
decode_signed_subpacket(<<21, Algorithms/binary>>) ->
	io:format("Preferred Hash Algorithms: ~p\n", [Algorithms]);
%% 22 = Preferred Compression Algorithms
decode_signed_subpacket(<<22, Algorithms/binary>>) ->
	io:format("Preferred Compression Algorithms: ~p\n", [Algorithms]);
%% 23 = Key Server Preferences
decode_signed_subpacket(<<23, NoModify:1/integer, _/bits>>) ->
	io:format("Key Server Preferences: ~p\n", [{NoModify}]);
%% 27 = Key Flags
decode_signed_subpacket(<<27, SharedPrivKey:1/integer, _:2/integer, SplitPrivKey:1/integer,
						  CanEncryptStorage:1/integer, CanEncryptComms:1/integer,
						  CanSign:1/integer, CanCertify:1/integer, _/binary>>) ->
	io:format("Key Flags: ~p\n", [{SharedPrivKey, SplitPrivKey, CanEncryptStorage,
								   CanEncryptComms, CanSign, CanCertify}]);
%% 30 = Features
decode_signed_subpacket(<<30, _:7/integer, ModificationDetection:1/integer, _/binary>>) ->
	io:format("Features: ~p\n", [{ModificationDetection}]);
decode_signed_subpacket(<<Tag, _/binary>>) -> io:format("Ingored ~p\n", [Tag]).

pgp_to_crypto_hash_algo(?HASH_ALGO_MD5) -> md5;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA1) -> sha;
pgp_to_crypto_hash_algo(?HASH_ALGO_RIPEMD160) -> ripemd160;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA256) -> sha256;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA384) -> sha384;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA512) -> sha512;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA224) -> sha224.

decode_pubkey_algo(RSA, <<NLen:16/integer-big, NRest/binary>>)
  when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_E; RSA =:= ?PK_ALGO_RSA_S ->
	NBytes = ((NLen + 7) div 8) * 8,
	<<N:NBytes/integer-big, ELen:16/integer-big, ERest/binary>> = NRest,
	EBytes = ((ELen + 7) div 8) * 8,
	<<E:EBytes/integer-big>> = ERest,
	{rsa_public, [E, N]}.

decode_armor(KeyText) ->
	{KeyBody64, CRC} = keylines(binary:split(KeyText, <<$\n>>, [global])),
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

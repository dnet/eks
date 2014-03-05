-module(pgp_parse).
-export([decode_stream/2, decode_stream/1, key_id/1]).

-define(OLD_PACKET_FORMAT, 2).
-define(SIGNATURE_PACKET, 2).
-define(PUBKEY_PACKET, 6).
-define(UID_PACKET, 13).
-define(SUBKEY_PACKET, 14).
-define(ISSUER_SUBPACKET, 16).
-define(PGP_VERSION, 4).

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

-record(decoder_ctx, {primary_key, subkey, uid, issuer, handler, handler_state}).

decode_stream(Data) -> decode_stream(Data, []).
decode_stream(Data, Opts) ->
	Contents = case proplists:get_bool(file, Opts) of
		true -> {ok, D} = file:read_file(Data), D;
		false -> Data
	end,
	Decoded = case proplists:get_bool(armor, Opts) of
		true -> pgp_armor:decode(Contents);
		false -> Contents
	end,
	Handler = proplists:get_value(handler, Opts, fun (_, _, D) -> D end),
	HS = proplists:get_value(handler_state, Opts),
	decode_packets(Decoded, #decoder_ctx{handler = Handler, handler_state = HS}).

decode_packets(<<>>, _) -> ok;
decode_packets(<<?OLD_PACKET_FORMAT:2/integer-big, Tag:4/integer-big,
				LenBits:2/integer-big, Body/binary>>, Context) ->
	{PacketData, S2Rest} = case LenBits of
		0 -> <<Length, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		1 -> <<Length:16/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		2 -> <<Length:32/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest}
	end,
	NewContext = decode_packet(Tag, PacketData, Context),
	decode_packets(S2Rest, NewContext).

decode_packet(?SIGNATURE_PACKET, <<?PGP_VERSION, SigType, PubKeyAlgo, HashAlgo,
								   HashedLen:16/integer-big, HashedData:HashedLen/binary,
								   UnhashedLen:16/integer-big, UnhashedData:UnhashedLen/binary,
								   HashLeft16:2/binary, Signature/binary>> = SigData, Context) ->
	Expected = hash_signature_packet(SigType, PubKeyAlgo, HashAlgo, HashedData, Context),
	<<HashLeft16:2/binary, _/binary>> = Expected,
	ContextAfterHashed = decode_signed_subpackets(HashedData, Context),
	ContextAfterUnhashed = decode_signed_subpackets(UnhashedData, ContextAfterHashed),
	verify_signature_packet(PubKeyAlgo, HashAlgo, Expected, Signature, SigType, ContextAfterUnhashed),
	Handler = ContextAfterUnhashed#decoder_ctx.handler,
	HS = Handler(signature, [SigData], ContextAfterUnhashed#decoder_ctx.handler_state),
	ContextAfterUnhashed#decoder_ctx{handler_state = HS};
decode_packet(Tag, <<?PGP_VERSION, Timestamp:32/integer-big, Algorithm, KeyRest/binary>> = KeyData, Context)
  when Tag =:= ?PUBKEY_PACKET; Tag =:= ?SUBKEY_PACKET ->
	Key = decode_pubkey_algo(Algorithm, KeyRest),
	Subject = <<16#99, (byte_size(KeyData)):16/integer-big, KeyData/binary>>,
	Handler = Context#decoder_ctx.handler,
	SK = {Subject, Key},
	PHS = Context#decoder_ctx.handler_state,
	case Tag of
		?PUBKEY_PACKET ->
			HS = Handler(primary_key, [SK, KeyData, Timestamp], PHS),
			Context#decoder_ctx{primary_key = SK, handler_state = HS};
		?SUBKEY_PACKET ->
			HS = Handler(subkey, [SK, KeyData, Timestamp, Context#decoder_ctx.primary_key], PHS),
			Context#decoder_ctx{subkey = SK, handler_state = HS}
	end;
decode_packet(?UID_PACKET, UID, C) ->
	HS = (C#decoder_ctx.handler)(uid, [UID], C#decoder_ctx.handler_state),
	C#decoder_ctx{uid = <<16#B4, (byte_size(UID)):32/integer-big, UID/binary>>, handler_state=HS}.

hash_signature_packet(SigType, PubKeyAlgo, HashAlgo, HashedData, Context) ->
	HashCtx = crypto:hash_init(pgp_to_crypto_hash_algo(HashAlgo)),
	FinalCtx = case SigType of
		%% 0x18: Subkey Binding Signature
		%% 0x19: Primary Key Binding Signature
		KeyBinding when KeyBinding =:= 16#18; KeyBinding =:= 16#19 ->
			{PK, _} = Context#decoder_ctx.primary_key,
			{SK, _} = Context#decoder_ctx.subkey,
			crypto:hash_update(crypto:hash_update(HashCtx, PK), SK);
		%% 0x10: Generic certification of a User ID and Public-Key packet.
		%% 0x11: Persona certification of a User ID and Public-Key packet.
		%% 0x12: Casual certification of a User ID and Public-Key packet.
		%% 0x13: Positive certification of a User ID and Public-Key packet.
		Cert when Cert >= 16#10, Cert =< 16#13 ->
			{PK, _} = Context#decoder_ctx.primary_key,
			UID = Context#decoder_ctx.uid,
			crypto:hash_update(crypto:hash_update(HashCtx, PK), UID);
		_ -> io:format("Unknown SigType ~p\n", [SigType]), HashCtx %% XXX
	end,
	FinalData = <<?PGP_VERSION, SigType, PubKeyAlgo, HashAlgo,
				  (byte_size(HashedData)):16/integer-big, HashedData/binary>>,
	Trailer = <<?PGP_VERSION, 16#FF, (byte_size(FinalData)):32/integer-big>>,
	crypto:hash_final(crypto:hash_update(crypto:hash_update(FinalCtx, FinalData), Trailer)).

verify_signature_packet(PubKeyAlgo, HashAlgo, Hash, Signature, SigType, Context) ->
	CHA = pgp_to_crypto_hash_algo(HashAlgo),
	CS = case PubKeyAlgo of
		RSA when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_S ->
			{S, <<>>} = read_mpi(Signature), S;
		_ -> unknown %% XXX
	end,
	case SigType of
		16#18 ->
			{_, {CPA, CryptoPK}} = Context#decoder_ctx.primary_key,
			true = crypto:verify(CPA, CHA, {digest, Hash}, CS, CryptoPK);
		C when C >= 16#10, C =< 16#13 ->
			I = Context#decoder_ctx.issuer,
			{HPK, {CPA, CryptoPK}} = Context#decoder_ctx.primary_key,
			case binary:longest_common_suffix([I, key_id(HPK)]) =:= byte_size(I) of
				true ->
					true = crypto:verify(CPA, CHA, {digest, Hash}, CS, CryptoPK);
				false -> needs_keystore %% TODO
			end;
		_ -> unknown
	end.

read_mpi(<<Length:16/integer-big, Rest/binary>>) ->
	ByteLen = (Length + 7) div 8,
	<<Data:ByteLen/binary, Trailer/binary>> = Rest,
	{Data, Trailer}.

key_id(Subject) -> crypto:hash(sha, Subject).

decode_signed_subpackets(<<>>, Context) -> Context;
decode_signed_subpackets(<<Length, Payload:Length/binary, Rest/binary>>, C) when Length < 192 ->
	NC = decode_signed_subpacket(Payload, C),
	decode_signed_subpackets(Rest, NC);
decode_signed_subpackets(<<LengthHigh, LengthLow, PayloadRest/binary>>, C) when LengthHigh < 255 ->
	Length = ((LengthHigh - 192) bsl 8) bor LengthLow,
	<<Payload:Length/binary, Rest/binary>> = PayloadRest,
	NC = decode_signed_subpacket(Payload, C),
	decode_signed_subpackets(Rest, NC);
decode_signed_subpackets(<<255, Length:32/integer-big, Payload:Length/binary, Rest/binary>>, C) ->
	NC = decode_signed_subpacket(Payload, C),
	decode_signed_subpackets(Rest, NC).

decode_signed_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, C) -> C#decoder_ctx{issuer = Issuer};
decode_signed_subpacket(<<_Tag, _/binary>>, C) -> C.

pgp_to_crypto_hash_algo(?HASH_ALGO_MD5) -> md5;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA1) -> sha;
pgp_to_crypto_hash_algo(?HASH_ALGO_RIPEMD160) -> ripemd160;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA256) -> sha256;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA384) -> sha384;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA512) -> sha512;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA224) -> sha224.

decode_pubkey_algo(RSA, Data)
  when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_E; RSA =:= ?PK_ALGO_RSA_S ->
	{N, Rest} = read_mpi(Data),
	{E, <<>>} = read_mpi(Rest),
	{rsa, [E, N]}.

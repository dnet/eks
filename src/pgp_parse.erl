-module(pgp_parse).
-export([decode_stream/2, decode_stream/1, decode_public_key/1, decode_signature_packet/1]).
-export([key_id/1, encode_key/1, c14n_pubkey/1]).
-include("OpenSSL.hrl").

-define(OLD_PACKET_FORMAT, 2).
-define(NEW_PACKET_FORMAT, 3).

-define(SIGNATURE_PACKET, 2).
-define(PUBKEY_PACKET, 6).
-define(UID_PACKET, 13).
-define(SUBKEY_PACKET, 14).
-define(USER_ATTR_PACKET, 17).

-define(SIG_CREATED_SUBPACKET, 2).
-define(SIG_EXPIRATION_SUBPACKET, 3).
-define(KEY_EXPIRATION_SUBPACKET, 9).
-define(ISSUER_SUBPACKET, 16).
-define(POLICY_URI_SUBPACKET, 26).

-define(PGP_VERSION_4, 4).
-define(PGP_VERSION_3, 3).

-define(SIGNED_PARAM(X), ContextAfterHashed#decoder_ctx.X).
-define(UNSIGNED_PARAM(X), ContextAfterUnhashed#decoder_ctx.X).

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

-record(decoder_ctx, {primary_key, subkey, uid, user_attr, issuer, handler, handler_state,
	sig_created, sig_expiration, key_expiration, policy_uri, skip_sig_check=false,
	critical_subpacket=false}).

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

decode_signature_packet(Packet) ->
	DecodeResult = decode_packet(?SIGNATURE_PACKET, Packet, #decoder_ctx{
		handler = (fun dsp_handler/3), handler_state = [], skip_sig_check = true}),
	DecodeResult#decoder_ctx.handler_state.

dsp_handler(signature, [_ | Params], []) -> Params;
dsp_handler(_, _, State) -> State.

encode_key(KeyData) -> encode_key(KeyData, ?PUBKEY_PACKET).
encode_key(KeyData, KeyTag) ->
	ID = key_id(c14n_pubkey(KeyData)),
	PK = encode_packet(KeyTag, KeyData),
	Signatures = <<
		<<(encode_packet(?UID_PACKET, UID))/binary, (encode_signatures(US))/binary>>
		|| {UID, US} <- pgp_keystore:get_signatures(ID) >>,
	Subkeys = << <<(encode_key(SK, ?SUBKEY_PACKET))/binary>> || SK <- pgp_keystore:get_subkeys(ID) >>,
	<<PK/binary, Signatures/binary, Subkeys/binary>>.

encode_signatures(Signatures) ->
	<< <<(encode_packet(?SIGNATURE_PACKET, S))/binary>> || S <- Signatures >>.

encode_packet(_, undefined) -> <<>>;
encode_packet(Tag, Body) ->
	{LenBits, Length} = case byte_size(Body) of
		S when S < 16#100       -> {0, <<S>>};
		M when M < 16#10000     -> {1, <<M:16/integer-big>>};
		L when L < 16#100000000 -> {2, <<L:32/integer-big>>}
	end,
	<<?OLD_PACKET_FORMAT:2/integer-big, Tag:4/integer-big,
	  LenBits:2/integer-big, Length/binary, Body/binary>>.

decode_packets(<<>>, _) -> ok;
decode_packets(<<?NEW_PACKET_FORMAT:2/integer-big, Tag:6/integer-big, Rest/binary>>, Context) ->
	{PacketData, S2Rest} = decode_new_packet(Rest),
	NewContext = decode_packet(Tag, PacketData, Context),
	decode_packets(S2Rest, NewContext);
decode_packets(<<?OLD_PACKET_FORMAT:2/integer-big, Tag:4/integer-big,
				LenBits:2/integer-big, Body/binary>>, Context) ->
	{PacketData, S2Rest} = case LenBits of
		0 -> <<Length, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		1 -> <<Length:16/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest};
		2 -> <<Length:32/integer-big, Object:Length/binary, SRest/binary>> = Body, {Object, SRest}
	end,
	NewContext = decode_packet(Tag, PacketData, Context),
	decode_packets(S2Rest, NewContext).

decode_new_packet(<<Length, Payload:Length/binary, Rest/binary>>) when Length < 192 ->
	{Payload, Rest};
decode_new_packet(<<LengthHigh, LengthLow, PayloadRest/binary>>) when LengthHigh < 255 ->
	Length = ((LengthHigh - 192) bsl 8) bor LengthLow + 192,
	<<Payload:Length/binary, Rest/binary>> = PayloadRest,
	{Payload, Rest};
decode_new_packet(<<255, Length:32/integer-big, Payload:Length/binary, Rest/binary>>) ->
	{Payload, Rest}.

decode_packet(?SIGNATURE_PACKET, <<?PGP_VERSION_4, SigType, PubKeyAlgo, HashAlgo,
								   HashedLen:16/integer-big, HashedData:HashedLen/binary,
								   UnhashedLen:16/integer-big, UnhashedData:UnhashedLen/binary,
								   HashLeft16:2/binary, Signature/binary>> = SigData, Context) ->
	Expected = case Context#decoder_ctx.skip_sig_check of
		true -> <<HashLeft16:2/binary>>;
		false -> hash_signature_packet(SigType, PubKeyAlgo, HashAlgo, HashedData, Context)
	end,
	<<HashLeft16:2/binary, _/binary>> = Expected,
	ContextAfterHashed = decode_signed_subpackets(HashedData, Context),
	ContextAfterUnhashed = decode_signed_subpackets(UnhashedData, ContextAfterHashed),
	verify_signature_packet(PubKeyAlgo, HashAlgo, Expected, Signature, SigType, ContextAfterUnhashed),
	Handler = ContextAfterUnhashed#decoder_ctx.handler,
	SigLevel = sig_type_to_sig_level(SigType),
	HS = Handler(signature, [SigData, ?SIGNED_PARAM(sig_expiration), ?SIGNED_PARAM(sig_created),
		?SIGNED_PARAM(policy_uri), ?UNSIGNED_PARAM(issuer), ?SIGNED_PARAM(key_expiration), SigLevel],
		ContextAfterUnhashed#decoder_ctx.handler_state),
	ContextAfterUnhashed#decoder_ctx{handler_state = HS};
decode_packet(?SIGNATURE_PACKET, <<?PGP_VERSION_3, 5, SigType, Timestamp:32/integer-big,
								   Issuer:8/binary, PubKeyAlgo, HashAlgo,
								   HashLeft16:2/binary, Signature/binary>> = SigData, Context) ->
	%% TODO verify
	Handler = Context#decoder_ctx.handler,
	HS = Handler(signature, [SigData, undefined, Timestamp, undefined, Issuer],
		Context#decoder_ctx.handler_state),
	Context#decoder_ctx{handler_state = HS};
decode_packet(Tag, KeyData, Context) when Tag =:= ?PUBKEY_PACKET; Tag =:= ?SUBKEY_PACKET ->
	{Timestamp, Key} = decode_public_key(KeyData),
	Handler = Context#decoder_ctx.handler,
	SK = {c14n_pubkey(KeyData), Key},
	PHS = Context#decoder_ctx.handler_state,
	case Tag of
		?PUBKEY_PACKET ->
			HS = Handler(primary_key, [SK, KeyData, Timestamp], PHS),
			Context#decoder_ctx{primary_key = SK, handler_state = HS, uid = undefined};
		?SUBKEY_PACKET ->
			HS = Handler(subkey, [SK, KeyData, Timestamp, Context#decoder_ctx.primary_key], PHS),
			Context#decoder_ctx{subkey = SK, handler_state = HS, uid = undefined}
	end;
decode_packet(?USER_ATTR_PACKET, UserAttr, C) ->
	C#decoder_ctx{user_attr = <<16#D1, (byte_size(UserAttr)):32/integer-big,  UserAttr/binary>>};
decode_packet(?UID_PACKET, UID, C) ->
	HS = (C#decoder_ctx.handler)(uid, [UID], C#decoder_ctx.handler_state),
	C#decoder_ctx{uid = <<16#B4, (byte_size(UID)):32/integer-big, UID/binary>>,
		handler_state=HS, user_attr = undefined}.

sig_type_to_sig_level(Cert) when Cert >= 16#11, Cert =< 16#13 -> [Cert - 16#10 + $0];
sig_type_to_sig_level(_) -> " ".

c14n_pubkey(KeyData) -> <<16#99, (byte_size(KeyData)):16/integer-big, KeyData/binary>>.

decode_public_key(<<?PGP_VERSION_4, Timestamp:32/integer-big, Algorithm, KeyRest/binary>>) ->
	Key = decode_pubkey_algo(Algorithm, KeyRest),
	{Timestamp, Key}.

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
		%% 0x30: Certification revocation signature
		Cert when Cert >= 16#10, Cert =< 16#13; Cert =:= 16#30 ->
			{PK, _} = Context#decoder_ctx.primary_key,
			UID = case Context#decoder_ctx.user_attr of
				undefined -> Context#decoder_ctx.uid;
				UA -> UA
			end,
			crypto:hash_update(crypto:hash_update(HashCtx, PK), UID);
		_ -> io:format("Unknown SigType ~p\n", [SigType]), HashCtx %% XXX
	end,
	FinalData = <<?PGP_VERSION_4, SigType, PubKeyAlgo, HashAlgo,
				  (byte_size(HashedData)):16/integer-big, HashedData/binary>>,
	Trailer = <<?PGP_VERSION_4, 16#FF, (byte_size(FinalData)):32/integer-big>>,
	crypto:hash_final(crypto:hash_update(crypto:hash_update(FinalCtx, FinalData), Trailer)).

verify_signature_packet(_, _, _, _, _, #decoder_ctx{skip_sig_check = true}) -> ok;
verify_signature_packet(PubKeyAlgo, HashAlgo, Hash, Signature, SigType, Context) ->
	CHA = pgp_to_crypto_hash_algo(HashAlgo),
	CS = case PubKeyAlgo of
		RSA when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_S ->
			read_mpi(Signature);
		?PK_ALGO_DSA ->
			[R, S] = [binary:decode_unsigned(X, big) || X <- read_mpi(Signature, 2)],
			{ok, Encoded} = 'OpenSSL':encode('DssSignature', #'DssSignature'{r = R, s = S}),
			Encoded;
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
				false ->
					case pgp_keystore:find_keys(I) of
						[] -> no_issuer;
						Keys ->
							true = lists:any(fun (Key) ->
								{_, {ICPA, ICryptoPK}} = decode_public_key(Key),
								crypto:verify(ICPA, CHA, {digest, Hash}, CS, ICryptoPK)
							end, Keys)
					end
			end;
		_ -> unknown
	end.

read_mpi(Data) -> [Value] = read_mpi(Data, 1), Value.
read_mpi(Data, Count) -> read_mpi(Data, Count, []).
read_mpi(<<>>, 0, Acc) -> lists:reverse(Acc);
read_mpi(<<Length:16/integer-big, Rest/binary>>, Count, Acc) ->
	ByteLen = (Length + 7) div 8,
	<<Data:ByteLen/binary, Trailer/binary>> = Rest,
	read_mpi(Trailer, Count - 1, [Data | Acc]).

key_id(Subject) -> crypto:hash(sha, Subject).

decode_signed_subpackets(<<>>, Context) -> Context;
decode_signed_subpackets(Packets, C) ->
	{Payload, Rest} = decode_new_packet(Packets),
	NC = decode_signed_subpacket(Payload, C),
	decode_signed_subpackets(Rest, NC#decoder_ctx{critical_subpacket = false}).

decode_signed_subpacket(<<?SIG_CREATED_SUBPACKET, Timestamp:32/integer-big>>, C) ->
	C#decoder_ctx{sig_created = Timestamp};
decode_signed_subpacket(<<?SIG_EXPIRATION_SUBPACKET, Timestamp:32/integer-big>>, C) ->
	C#decoder_ctx{sig_expiration = Timestamp};
decode_signed_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32/integer-big>>, C) ->
	C#decoder_ctx{key_expiration = Timestamp};
decode_signed_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, C) -> C#decoder_ctx{issuer = Issuer};
decode_signed_subpacket(<<?POLICY_URI_SUBPACKET, URI/binary>>, C) -> C#decoder_ctx{policy_uri = URI};
decode_signed_subpacket(<<Tag, Rest/binary>>, C) when Tag band 128 =:= 128 ->
	decode_signed_subpacket(<<(Tag band 127), Rest/binary>>, C#decoder_ctx{critical_subpacket = true});
decode_signed_subpacket(<<_Tag, _/binary>>, C = #decoder_ctx{critical_subpacket = false}) -> C.

pgp_to_crypto_hash_algo(?HASH_ALGO_MD5) -> md5;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA1) -> sha;
pgp_to_crypto_hash_algo(?HASH_ALGO_RIPEMD160) -> ripemd160;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA256) -> sha256;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA384) -> sha384;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA512) -> sha512;
pgp_to_crypto_hash_algo(?HASH_ALGO_SHA224) -> sha224.

decode_pubkey_algo(?PK_ALGO_ELGAMAL, _) -> elgamal; %% encryption only -> don't care
decode_pubkey_algo(?PK_ALGO_DSA, Data) ->
	{dss, read_mpi(Data, 4)};
decode_pubkey_algo(RSA, Data)
  when RSA =:= ?PK_ALGO_RSA_ES; RSA =:= ?PK_ALGO_RSA_E; RSA =:= ?PK_ALGO_RSA_S ->
	{rsa, lists:reverse(read_mpi(Data, 2))}.

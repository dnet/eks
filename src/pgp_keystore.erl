-module(pgp_keystore).
-export([import_stream/2, init_schema/0, find_keys/1, find_keys/2,
		 get_signatures/1, get_subkeys/1, short_ids/1, search_keys/1]).

-define(ID_BYTES, 20).
-define(ID64_BYTES, 8).
-define(ID32_BYTES, 4).

-include_lib("stdlib/include/qlc.hrl").

-record(pgp_pubkey, {id, id64, id32, data, parent_id}).
-record(pgp_signature, {key_id, uid_hash, data}).
-record(pgp_uid, {hash, uid, c14n}).

-record(import_ctx, {key_id, uid_hash}).

init_schema() ->
	case mnesia:create_table(pgp_pubkey, [
		{index, [#pgp_pubkey.id64, #pgp_pubkey.id32, #pgp_pubkey.parent_id]},
		{attributes, record_info(fields, pgp_pubkey)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_pubkey}} -> ok
	end,
	case mnesia:create_table(pgp_signature, [{type, bag}, {index, [#pgp_signature.uid_hash]},
		{attributes, record_info(fields, pgp_signature)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_signature}} -> ok
	end,
	case mnesia:create_table(pgp_uid, [{index, [#pgp_uid.uid]},
		{attributes, record_info(fields, pgp_uid)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_uid}} -> ok
	end,
	ok = mnesia:wait_for_tables([pgp_pubkey, pgp_signature, pgp_uid], 5000).

import_stream(Data, Opts) ->
	{atomic, ok} = mnesia:transaction(fun () ->
		pgp_parse:decode_stream(Data,
			[{handler, fun import_handler/3},
			 {handler_state, #import_ctx{}} | Opts])
									  end).

import_handler(primary_key, [{Subject, _}, KeyData | _], State) ->
	KeyID = store_pubkey(#pgp_pubkey{data = KeyData}, Subject),
	State#import_ctx{key_id = KeyID, uid_hash = undefined};
import_handler(subkey, [{Subject, _}, KeyData, _, {ParentSubject, _} | _], State) ->
	ParentKeyID = pgp_parse:key_id(ParentSubject),
	KeyID = store_pubkey(#pgp_pubkey{data = KeyData, parent_id = ParentKeyID}, Subject),
	State#import_ctx{key_id = KeyID, uid_hash = undefined};
import_handler(uid, [UID | _], State) ->
	State#import_ctx{uid_hash = store_uid_hash(UID)};
import_handler(signature, [Data | _], State) ->
	mnesia:write(#pgp_signature{key_id = State#import_ctx.key_id,
		uid_hash = State#import_ctx.uid_hash, data = Data}),
	State;
import_handler(_, _, State) -> State.

store_pubkey(PK, Subject) ->
	KeyID = pgp_parse:key_id(Subject),
	{ID32, ID64} = short_ids(KeyID),
	mnesia:write(PK#pgp_pubkey{id = KeyID, id64 = ID64, id32 = ID32}),
	KeyID.

store_uid_hash(UID) ->
	{atomic, Hash} = mnesia:transaction(fun () ->
		mnesia:lock({table, pgp_uid}, write),
		case mnesia:index_read(pgp_uid, UID, #pgp_uid.uid) of
			[U] -> U#pgp_uid.hash;
			[] -> store_uid_hash(UID, erlang:phash2(UID))
		end
	end),
	Hash.
store_uid_hash(UID, NewHash) ->
	case mnesia:read(pgp_uid, NewHash) of
		[] ->
			mnesia:write(#pgp_uid{uid = UID, hash = NewHash, c14n = c14n_uid(UID)}),
			NewHash;
		_ -> store_uid_hash(UID, NewHash bxor erlang:phash2(now()))
	end.

short_ids(<<_:12/binary, ID64:?ID64_BYTES/binary>>) ->
	<<_:4/binary, ID32:?ID32_BYTES/binary>> = ID64,
	{ID32, ID64}.

find_keys(KeyID) -> find_keys(KeyID, []).
find_keys(KeyID, Opts) ->
	{atomic, Keys} = mnesia:transaction(fun () ->
		FoundKeys = case byte_size(KeyID) of
			?ID32_BYTES -> mnesia:index_read(pgp_pubkey, KeyID, #pgp_pubkey.id32);
			?ID64_BYTES -> mnesia:index_read(pgp_pubkey, KeyID, #pgp_pubkey.id64);
			?ID_BYTES -> mnesia:read(pgp_pubkey, KeyID)
		end,
		case proplists:get_bool(parents, Opts) of
			true -> [case K#pgp_pubkey.parent_id of
				undefined -> K;
				Parent -> [P] = mnesia:read(pgp_pubkey, Parent), P
			end || K <- FoundKeys];
			false -> FoundKeys
		end
	end),
	[K#pgp_pubkey.data || K <- Keys].

search_keys(Text) ->
	P = binary:compile_pattern(c14n_uid(Text)),
	{atomic, KeyGroups} = mnesia:transaction(fun () ->
		Hashes = qlc:eval(qlc:q([S#pgp_uid.hash || S <- mnesia:table(pgp_uid),
			binary:match(S#pgp_uid.c14n, P) =/= nomatch])),
		SigGroups = [mnesia:index_read(pgp_signature, H, #pgp_signature.uid_hash) || H <- Hashes],
		KeyIDs = ordsets:from_list([S#pgp_signature.key_id || SigGroup <- SigGroups, S <- SigGroup]),
		[mnesia:read(pgp_pubkey, KeyID) || KeyID <- KeyIDs]
	end),
	[K#pgp_pubkey.data || KeyGroup <- KeyGroups, K <- KeyGroup].

c14n_uid(UID) -> list_to_binary(string:to_lower(binary_to_list(UID))).

get_signatures(KeyID) ->
	{atomic, Signatures} = mnesia:transaction(fun () ->
		FullKeyID = case byte_size(KeyID) of
			?ID_BYTES -> KeyID;
			?ID64_BYTES ->
				case mnesia:index_read(pgp_pubkey, KeyID, #pgp_pubkey.id64) of
					[Key] -> Key#pgp_pubkey.id;
					[] -> no_pubkey
				end
		end,
		Grouped = lists:foldl(
			fun (#pgp_signature{uid_hash = U, data = D}, A) -> dict:append(U, D, A) end,
			dict:new(), mnesia:read(pgp_signature, FullKeyID)),
		[{get_uid(Hash), Sigs} || {Hash, Sigs} <- dict:to_list(Grouped)]
	end),
	Signatures.

get_uid(undefined) -> undefined;
get_uid(Hash) ->
	[UID] = mnesia:read(pgp_uid, Hash),
	UID#pgp_uid.uid.

get_subkeys(KeyID) ->
	{atomic, Keys} = mnesia:transaction(fun () ->
		mnesia:index_read(pgp_pubkey, KeyID, #pgp_pubkey.parent_id) end),
	[K#pgp_pubkey.data || K <- Keys].

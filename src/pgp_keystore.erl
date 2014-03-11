-module(pgp_keystore).
-export([import_stream/2, init_schema/0, find_keys/1, find_keys/2, get_signatures/1, get_subkeys/1]).

-define(ID_BYTES, 20).
-define(ID64_BYTES, 8).
-define(ID32_BYTES, 4).

-include_lib("stdlib/include/qlc.hrl").

-record(pgp_pubkey, {id, id64, id32, data, parent_id}).
-record(pgp_signature, {key_id, uid, data}).

-record(import_ctx, {key_id, uid}).

init_schema() ->
	case mnesia:create_table(pgp_pubkey, [
		{index, [#pgp_pubkey.id64, #pgp_pubkey.id32, #pgp_pubkey.parent_id]},
		{attributes, record_info(fields, pgp_pubkey)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_pubkey}} -> ok
	end,
	case mnesia:create_table(pgp_signature, [{type, bag},
		{attributes, record_info(fields, pgp_signature)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_signature}} -> ok
	end,
	ok = mnesia:wait_for_tables([pgp_pubkey, pgp_signature], 5000).

import_stream(Data, Opts) ->
	{atomic, ok} = mnesia:transaction(fun () ->
		pgp_parse:decode_stream(Data,
			[{handler, fun import_handler/3},
			 {handler_state, #import_ctx{}} | Opts])
									  end).

import_handler(primary_key, [{Subject, _}, KeyData | _], State) ->
	KeyID = store_pubkey(#pgp_pubkey{data = KeyData}, Subject),
	State#import_ctx{key_id = KeyID, uid = undefined};
import_handler(subkey, [{Subject, _}, KeyData, _, {ParentSubject, _} | _], State) ->
	ParentKeyID = pgp_parse:key_id(ParentSubject),
	KeyID = store_pubkey(#pgp_pubkey{data = KeyData, parent_id = ParentKeyID}, Subject),
	State#import_ctx{key_id = KeyID, uid = undefined};
import_handler(uid, [UID | _], State) ->
	State#import_ctx{uid = UID};
import_handler(signature, [Data | _], State) ->
	mnesia:write(#pgp_signature{key_id = State#import_ctx.key_id, uid = State#import_ctx.uid, data = Data}),
	State;
import_handler(_, _, State) -> State.

store_pubkey(PK, Subject) ->
	<<_:12/binary, ID64:?ID64_BYTES/binary>> = KeyID = pgp_parse:key_id(Subject),
	<<_:4/binary, ID32:?ID32_BYTES/binary>> = ID64,
	mnesia:write(PK#pgp_pubkey{id = KeyID, id64 = ID64, id32 = ID32}),
	KeyID.

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

get_signatures(KeyID) ->
	{atomic, Signatures} = mnesia:transaction(fun () -> mnesia:read(pgp_signature, KeyID) end),
	Grouped = lists:foldl(
		fun (#pgp_signature{uid = U, data = D}, A) -> dict:append(U, D, A) end,
		dict:new(), Signatures),
	dict:to_list(Grouped).

get_subkeys(KeyID) ->
	{atomic, Keys} = mnesia:transaction(fun () ->
		mnesia:index_read(pgp_pubkey, KeyID, #pgp_pubkey.parent_id) end),
	[K#pgp_pubkey.data || K <- Keys].

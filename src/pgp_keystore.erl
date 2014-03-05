-module(pgp_keystore).
-export([import_stream/2, init_schema/0]).

-record(pgp_pubkey, {id, data, parent_id}).
-record(pgp_uid, {key_id, uid}).
-record(pgp_signature, {uid, data}).

-record(import_ctx, {key_id, uid}).

init_schema() ->
	case mnesia:create_table(pgp_pubkey, [{index, [#pgp_pubkey.parent_id]},
		{attributes, record_info(fields, pgp_pubkey)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_pubkey}} -> ok
	end,
	case mnesia:create_table(pgp_uid, [{type, bag},
		{attributes, record_info(fields, pgp_uid)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_uid}} -> ok
	end,
	case mnesia:create_table(pgp_signature, [{type, bag},
		{attributes, record_info(fields, pgp_signature)}, {disc_copies, [node()]}]) of
		{atomic, ok} -> ok;
		{aborted, {already_exists, pgp_signature}} -> ok
	end,
	ok = mnesia:wait_for_tables([pgp_pubkey, pgp_uid, pgp_signature], 5000).

import_stream(Data, Opts) ->
	{atomic, ok} = mnesia:transaction(fun () ->
		pgp_parse:decode_stream(Data,
			[{handler, fun import_handler/3},
			 {handler_state, #import_ctx{}} | Opts])
									  end).

import_handler(primary_key, [{Subject, _}, KeyData | _], State) ->
	KeyID = pgp_parse:key_id(Subject),
	mnesia:write(#pgp_pubkey{id = KeyID, data = KeyData}),
	State#import_ctx{key_id = KeyID};
import_handler(subkey, [{Subject, _}, KeyData, _, {ParentSubject, _} | _], State) ->
	KeyID = pgp_parse:key_id(Subject),
	ParentKeyID = pgp_parse:key_id(ParentSubject),
	mnesia:write(#pgp_pubkey{id = KeyID, data = KeyData, parent_id = ParentKeyID}),
	State#import_ctx{key_id = KeyID};
import_handler(uid, [UID | _], State) ->
	mnesia:write(#pgp_uid{key_id = State#import_ctx.key_id, uid = UID}),
	State#import_ctx{uid = UID};
import_handler(signature, [Data | _], State) ->
	mnesia:write(#pgp_signature{uid = State#import_ctx.uid, data = Data}),
	State;
import_handler(_, _, State) -> State.

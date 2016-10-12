%% @author <ruel@ruel.me>
%% @copyright 2016 Ruel Pagayon
%% @doc The google_token application verifies the integrity of
%% Google ID tokens in accordance with Google's criterias.
%% See: https://developers.google.com/identity/sign-in/web/backend-auth
-module(google_token).
-behaviour(gen_server).

%% API
-export([
  validate/1,
  validate/2
]).

%% External functions
-export([
  start_link/0
]).

%% gen_server callbacks
-export([
  init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3
]).

-record(state, {keys = [], error = unknown_error}).


%% ----------------------------------------------------------------------------
%% External functions
%% ----------------------------------------------------------------------------

%% @private
%% @doc Start gen_server
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ----------------------------------------------------------------------------
%% API
%% ----------------------------------------------------------------------------

-spec validate(binary()) -> {valid, map()} | {invalid, term()}.
%% @doc Validates the ID token
validate(IdToken) ->
  gen_server:call(?MODULE, {verify_without_ids, IdToken}).

-spec validate(binary(), list()) -> {valid, map()} | {invalid, term()}.
%% @doc Validates the ID token and it's aud against the client IDs specified
validate(IdToken, ClientIds) ->
  gen_server:call(?MODULE, {verify_with_ids, [IdToken, ClientIds]}).

%% ----------------------------------------------------------------------------
%% gen_server callbacks
%% ----------------------------------------------------------------------------

%% @private
init(_Args) ->
  {state, State} = get_cert_state(),
  {ok, State}.

%% @private
handle_call({verify_without_ids, IdToken}, _From, State) ->
  Reply = do_verify(IdToken, State),
  {reply, Reply, State};
handle_call({verify_with_ids, [IdToken, ClientIds]}, _From, State) ->
  Reply = case do_verify(IdToken, State) of
    {valid, Payload} ->
      check_audience(Payload, ClientIds);
    Error ->
      Error 
  end,
  {reply, Reply, State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%% @private
handle_cast(_Message, State) ->
  {noreply, State}.

%% @private
handle_info(_Info, State) ->
  {noreply, State}.

%% @private
terminate(_Reason, _State) ->
  ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% ----------------------------------------------------------------------------
%% Internal functions
%% ----------------------------------------------------------------------------

-spec do_verify(binary(), #state{}) -> {valid, map()} | 
                                       {invalid, term()} | 
                                       {error, term()}.
%% @private
%% @doc Abstracts the JWT validation
do_verify(IdToken, State) ->
  case get_kid(IdToken) of
    {kid, KId} ->
      Keys = State#state.keys,
      try_verify(IdToken, KId, State, Keys, false);
    {error, not_found} ->
      {invalid, malformed_token}
  end.

-spec get_kid(binary()) -> {kid, binary()} | {error, not_found}.
%% @private
%% @doc Gets the kid parameter from the IdToken
get_kid(IdToken) ->
  Protected = jose_jwt:peek_protected(IdToken),
  {_M, Map} = jose_jws:to_map(Protected),
  case maps:is_key(<<"kid">>, Map) of
    true ->
      {kid, maps:get(<<"kid">>, Map)};
    false ->
      {error, not_found}
  end.

-spec try_verify(binary(), binary(), #state{}, list(), boolean()) -> 
                                                        {valid, map()} | 
                                                        {invalid, term()} | 
                                                        {error, term()}.
%% @private
%% @doc Performs error checking and key matching
try_verify(IdToken, KId, _State, [], false) ->
  {state, State} = get_cert_state(),
  Keys = State#state.keys,
  try_verify(IdToken, KId, State, Keys, true);
try_verify(_IdToken, _KId, #state{error = Error}, [], true) ->
  {error, Error};
try_verify(IdToken, KId, _State, Keys, _Retried) ->
  case find_key(KId, Keys) of
    {key, Key} ->
      validate_jwt(Key, IdToken);
    _Error ->
      {invalid, no_verifier} 
  end.

-spec validate_jwt(map(), binary()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Does the actual validation of JWT using given JWK
validate_jwt(Key, JWT) ->
  JWK = jose_jwk:from_map(Key), 
  case jose_jwt:verify(JWK, JWT) of
    {true, {jose_jwt, Payload}, _JWS} ->
      validate_claims(Payload);
    {false, _Payload, _JWS} ->
      {invalid, unverified}
  end.

-spec validate_claims(map()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Validate expiry and issuer claims
validate_claims(Payload) ->
  Expiry = maps:get(<<"exp">>, Payload, 0), 
  Now    = erlang:round(erlang:system_time() / 1000000000),
  if
    Now < Expiry ->
      check_issuer(Payload);
    true ->
      {invalid, expired}
  end.
  
-spec check_issuer(map()) -> {valid, map()} | {invalid, term()}. 
%% @private
%% @doc Check iss and match with Google's known iss
check_issuer(Payload) ->
  Issuer = maps:get(<<"iss">>, Payload, <<>>), 
  if
    Issuer =:= <<"accounts.google.com">> orelse
    Issuer =:= <<"https://accounts.google.com">> ->
      {valid, Payload};
    true ->
      {invalid, wrong_iss} 
  end.

-spec check_audience(map(), list()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Check aud claim and match with given ids
check_audience(Payload, Ids) ->
  Audience = maps:get(<<"aud">>, Payload, <<>>), 
  Found = lists:foldl(fun(Id, Found) ->
    BinId = ensure_binary(Id),
    Found orelse Audience =:= BinId
  end, false, Ids),
  if
    Found ->
      {valid, Payload};
    true ->
      {invalid, wrong_aud}
  end.
    

-spec find_key(binary(), list()) -> {key, map()} | {error, not_found}.
%% @private 
%% @doc Search Google's key / cert list for kid
find_key(KId, Keys) ->
  find_key(KId, Keys, no_match).
find_key(_KId, _Keys, {match, Key}) ->
  {key, Key};
find_key(_KId, [], _Match) ->
  {error, not_found};
find_key(KId, [Key | Keys], no_match) ->
  MKId = maps:get(<<"kid">>, Key, undefined),
  Res = case MKId of
    KId ->
      {match, Key};
    MKId ->
      nomatch
  end,
  find_key(KId, Keys, Res).
        
-spec get_cert_state() -> {state, #state{}}.
%% @private
%% @doc Performs get_certs() and returns the state
get_cert_state() ->
  case get_certs() of
    {keys, Keys} ->
      {state, #state{keys = Keys}};
    Error ->
      {state, #state{error = Error}}
  end.
  
-spec get_certs() -> {certs, list()}.
%% @private
%% @doc Gets the latest JWK from Google's certificate repository
get_certs() ->
  Url = "https://www.googleapis.com/oauth2/v3/certs",
  case httpc:request(Url) of
    {ok, {{_Version, 200, _Phrase}, _Headers, Body}} ->
      BodyMap = jsx:decode(ensure_binary(Body), [return_maps]),
      Keys    = maps:get(<<"keys">>, BodyMap, []),
      {keys, Keys};
    Error ->
      {get_certs_error, Error}
  end.

-spec ensure_binary(term()) -> binary().
%% @private
%% @doc Converts a list, atom, or integer to binary if necessary
ensure_binary(Term) when is_binary(Term) ->
  Term;
ensure_binary(Term) when is_integer(Term) ->
  integer_to_binary(Term);
ensure_binary(Term) when is_list(Term) ->
  list_to_binary(Term);
ensure_binary(Term) when is_atom(Term) ->
  atom_to_binary(Term, utf8).

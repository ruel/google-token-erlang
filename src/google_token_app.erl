%% @author <ruel@ruel.me>
%% @copyright 2016 Ruel Pagayon
%% @doc Application module for google_token
-module(google_token_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    google_token_sup:start_link().

stop(_State) ->
    ok.

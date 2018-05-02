%% @author <ruel@ruel.me>
%% @copyright 2016 Ruel Pagayon
%% @doc Supervisor for the main google_token server
-module(google_token_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
  {ok, {{one_for_one, 1000, 1}, [
    {
      google_token,
      {google_token, start_link, []},
      permanent,
      5000,
      worker,
      [google_token]
    }
  ]}}.

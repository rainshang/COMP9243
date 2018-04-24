-module(router).
-export([start/1]).

start(RouterName) ->
    spawn(
        fun() ->
        init()
        end).

init() ->
    ganshahao.
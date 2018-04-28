-module(control).
-export([graphToNetwork/1, extendNetwork/4]).

graphToNetwork([]) ->
    empty_graph;

graphToNetwork(Graph) ->
    % init name_pid map
    NamePidMap = ets:new('NamePidMap', []),
    % foreach to start node and set name_Pid in table
    lists:foreach(
        fun({Name, _}) ->
            ets:insert(NamePidMap, startNode(Name))
        end,
        Graph),
    % send init control sequence to each router directly
    lists:foreach(
        fun({Name, Edges}) ->
            Pid = getPidByName(Name, NamePidMap),
            Pid ! {control, self(), self(), 0,
                fun(Name, Table) ->
                    lists:foreach(
                        fun({Next, Dests}) ->
                            NextPid = getPidByName(Next, NamePidMap),
                            lists:foreach(
                                fun(Dest) ->
                                    ets:insert(Table, {Dest, NextPid})
                                end,
                            Dests)
                        end,
                        Edges),
                    []
                end},
            receive
                {committed, Pid, SeqNum} ->
                    ok
            end
        end,
        Graph),
    % using first key to update $NoInEdges'
    FristPid = getPidByName(ets:first(NamePidMap), NamePidMap),
    FristPid ! {control, self(), self(), 1,
                fun(Name, Table) ->
                    []
                end},
    receive
        {committed, FristPid, InitSeqNum} ->
            io:format ("*** ...done.~n");
        {abort , FristPid, InitSeqNum} ->
            io:format ("*** ERROR: Configuration failed!~n")
    after 5000 ->
        io:format ("*** ERROR: Configuration timed out!~n")
    end,
    FristPid.

startNode(Name) ->
    Pid = router:start(Name),
    % io:format("~w:~w~n", [Name, Pid]),
    {Name, Pid}.

getPidByName(Name, NamePidMap) ->
    ets:lookup_element(NamePidMap, Name, 2).

% convert {Next, Dests} to {Pid, Dests}
% edgesHelper(Edge) ->
%     {Next, Dests} = Edge,
%     {getPidByName(Next), Dests}.

extendNetwork(RootPid, SeqNum, From, {NodeName, Edges}) ->
    
    1.
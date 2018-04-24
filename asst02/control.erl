-module(control).
-export([simpleNetworkGraph/0, graphToNetwork/1, extendNetwork/4]).

simpleNetworkGraph() ->
  [{red  , [{white, [white, green]}, {blue , [blue]}]},
   {white, [{red, [blue]}, {blue, [green, red]}]},
   {blue , [{green, [white, green, red]}]},
   {green, [{red, [red, blue, white]}]}].

graphToNetwork([]) ->
    case lists:member(namePidMap, ets:all()) of
        true -> ets:delete(namePidMap);
        false -> not_existing
    end,
    ets:new(namePidMap, [named_table, set]);

graphToNetwork(Graph) ->
    graphToNetwork([]),
    lists:foreach(
        fun(Node) ->
            ets:insert(namePidMap, startNode(Node))
        end,
        Graph),
    ets:tab2list(namePidMap).

startNode(Node) ->
    {Name, Edges} = Node,
    Pid = router:start(Name),
    {Name, Pid}.

% generateNodeNamePidMap(_, Name, Pid) ->
%     #{Name => Pid}.

% generateNodeNamePidMap(Map, Name, Pid) ->
%     Map#{Name => Pid}.

% % {red  , [{white, [white, green]}, {blue , [blue]}]}
% processNode(Node) ->
%     {Name, Edges} = Node,
%     Pid = router:start(Name),
%     processEdges(Pid, Edges).
%     % Pid.

% % send generateRouteTable to Pid
% processEdges(Pid, Edges) ->
%     ets:new()
%     generateRouteTable(Edges).

% generateRouteTable(Edges) ->

%     lists:foreach(, Edges).

%     [H|T] = Edges,
%     [processNextNode(H)|generateRouteTable(T)].

% processNextNode(NextNodeTuple) ->
%     {NextNode, DestNodes} = Tuple,

% generateNextNodeRouteTable(NextNode, DestNodes) ->

% generateNextNodeRouteTable(NextNode, DestNodes) ->




extendNetwork(RootPid, SeqNum, From, {NodeName, Edges}) ->
    1.
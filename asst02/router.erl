-module(router).
-export([start/1]).

start(RouterName) ->
    spawn(
        fun() ->
        init(RouterName)
        end).

init(RouterName) ->
    % init routing table and temp table
    RoutingTable = ets:new('RoutingTable', []),
    ets:insert(RoutingTable, {'$NoInEdges', 0}),
    RoutingTableTemp = ets:new('RoutingTableTemp', []),

    % init edge in set
    EdgeInSet = ets:new('EdgeInSet', []),
    % init the table of the control seqence received and where it came from
    CtrlSeqReceivedTable = ets:new('CtrlSeqReceivedTable', []),
    % init the table of the control seqence received and where it is sent to
    CtrlSeqForwardingTable = ets:new('CtrlSeqForwardingTable', []),
    
    % loop listen
    listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable).

listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable) ->
    receive
        {control, From, Pid, SeqNum, ControlFun} ->
            % two 2PC must abort one
            % here I give up the new one
            case ets:first(CtrlSeqReceivedTable) of
                '$end_of_table' ->
                    % empty, go on
                    focusOneControl(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable,
                        control, From, Pid, SeqNum, ControlFun);
                _ ->
                    case ets:member(CtrlSeqReceivedTable, SeqNum) of
                        % same, go on
                        true ->
                            focusOneControl(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable,
                                control, From, Pid, SeqNum, ControlFun);
                        false ->
                            % not same, give up new one
                            From ! {abort, self(), SeqNum}
                    end
            end,
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {committed, From, Pid, SeqNum, ControlFun, IsMock} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            case IsMock of
                true ->
                    ets:delete(ForwardingSet, From);
                false ->
                    % log From returned 
                    ets:update_element(ForwardingSet, From, {2, true})
            end,
            % check all return with &&
            AllCommitted = ets:foldl(
                fun({Node, Status}, Acc) ->
                    Status and Acc
                end,
                true,
                ForwardingSet),
            case AllCommitted of
                % all the sent has return committed
                true ->
                    % get who sent this SeqNum
                    Parent = ets:lookup_element(CtrlSeqReceivedTable, SeqNum, 2),
                    copyTable(RoutingTable, RoutingTableTemp),
                    case ControlFun(RouterName, RoutingTableTemp) of
                        % failed
                        abort ->
                            if
                                Pid == Parent ->
                                    Parent ! {abort, self (), SeqNum};
                                true ->
                                    Parent ! {abort, self (), Pid, SeqNum, ControlFun}
                            end,
                            self() ! {doAbort, SeqNum};
                        % success
                        _ ->
                            if
                                Pid == Parent ->
                                    Parent ! {committed, self (), SeqNum},
                                    self() ! {doCommit, SeqNum};
                                true ->
                                    Parent ! {committed, self (), Pid, SeqNum, ControlFun, false}
                            end
                    end;
                false ->
                    go_on
            end,
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {abort, From, Pid, SeqNum, ControlFun} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doAbort to all the routers who have committed
            lists:foreach(
                fun({Node, Status}) ->
                    case Status of
                        true ->
                            Node ! {doAbort, SeqNum};
                        false ->
                            false
                    end
                end,
                ets:tab2list(ForwardingSet)),

            Parent = ets:lookup_element(CtrlSeqReceivedTable, SeqNum, 2),
            if
                Pid == Parent ->
                    Parent ! {abort, self (), SeqNum};
                true ->
                    Parent ! {abort, self (), Pid, SeqNum, ControlFun}
            end,
            ets:delete(CtrlSeqForwardingTable, SeqNum),
            ets:delete(CtrlSeqReceivedTable, SeqNum),
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {doAbort, SeqNum} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doAbort to all the routers who have committed
            lists:foreach(
                fun({Node, Status}) ->
                    case Status of
                        true ->
                            Node ! {doAbort, SeqNum};
                        false ->
                            false
                    end
                end,
                ets:tab2list(ForwardingSet)),
            ets:delete(CtrlSeqForwardingTable, SeqNum),
            ets:delete(CtrlSeqReceivedTable, SeqNum),
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {doCommit, SeqNum} ->
            copyTable(RoutingTableTemp, RoutingTable),
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doCommit
            lists:foreach(
                fun({Node, _}) ->
                    Node ! {doCommit, SeqNum}
                end,
                ets:tab2list(ForwardingSet)),
            ets:delete(CtrlSeqForwardingTable, SeqNum),
            ets:delete(CtrlSeqReceivedTable, SeqNum),
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {message, Dest, From, Pid, Trace} ->
            if
                % arrive
                Dest == RouterName ->
                    Pid ! {trace, self(), lists:append(Trace, [RouterName])};
                true ->
                    case ets:member(RoutingTable, Dest) of
                        true ->
                            ForwardPid = ets:lookup_element(RoutingTable, Dest, 2),
                            ForwardPid ! {message, Dest, self(), Pid, lists:append(Trace, [RouterName])};
                        false ->
                            not_reachable
                    end
            end,
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {dump, From} ->
            From ! {table, self(), ets:match(RoutingTable, '$1')},
            listen(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        stop ->
            case ets:first(CtrlSeqReceivedTable) of
                '$end_of_table' ->
                    exit(stop);
                _ ->
                    engaged2PC
            end
    end.

focusOneControl(RouterName, RoutingTable, RoutingTableTemp, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable,
    control, From, Pid, SeqNum, ControlFun) ->
    if
        % initialisation, callback the func directly, without any 2PC
        SeqNum == 0 ->
            copyTable(RoutingTable, RoutingTableTemp),
            case ControlFun(RouterName, RoutingTableTemp) of
                abort ->
                    From ! {abort, self(), SeqNum};
                _ ->
                    % doCommit
                    copyTable(RoutingTableTemp, RoutingTable),
                    % io:format("~w(~w)'s routing table:", [RouterName, self()]),
                    % lists:foreach(
                    %     fun(Element) ->
                    %         io:format(" ~w", [Element])
                    %     end,
                    %     ets:tab2list(RoutingTable)),
                    % io:format("~n"),
                    From ! {committed, self(), SeqNum}
            end;
            
        % normal control sequence
        true ->
            % update $NoInEdges
            if
                % coming from controller
                Pid == From ->
                    % reset EdgeInSet
                    ets:delete_all_objects(EdgeInSet);
                % coming from other router
                true ->
                    % whether in EdgeInSet
                    case ets:member(EdgeInSet, From) of
                        false ->
                            % no, log this in edge, in++
                            ets:insert(EdgeInSet, {From}),
                            % io:format("~w's in degree: ~w~n", [RouterName, ets:lookup_element(RoutingTable, '$NoInEdges', 2) + 1]),
                            ets:update_counter(RoutingTable, '$NoInEdges', 1);
                        true ->
                            already_count
                    end
            end,
    
            % check whether already received this control seqence
            case ets:member(CtrlSeqReceivedTable, SeqNum) of
                % yes, has received, using the forwarding chain, give back a mock committed result
                true ->
                    From ! {committed, self(), Pid, SeqNum, ControlFun, true};
                % no, new control seqence coming in
                false ->
                    % log the SeqNum and From
                    ets:insert(CtrlSeqReceivedTable, {SeqNum, From}),
                    % log the routers which sequence is being forwarded to 
                    ForwardingSet = ets:new('ForwardingSet', []),
                    ets:insert(CtrlSeqForwardingTable, {SeqNum, ForwardingSet}),
                    % forward to the routers in routing table
                    lists:foreach(
                        fun({Dest, NextPid}) ->
                            if
                                % ignore '$NoInEdges'
                                Dest == '$NoInEdges' ->
                                    Dest;
                                % real routing table element
                                true ->
                                    case ets:member(ForwardingSet, NextPid) of
                                        % already sent
                                        true ->
                                            true;
                                        false ->
                                            ets:insert(ForwardingSet, {NextPid, false}),
                                            NextPid ! {control, self(), Pid, SeqNum, ControlFun}
                                    end
                            end
                        end,
                        ets:tab2list(RoutingTable))
            end
    end.

copyTable(Src, Dest) ->
    ets:delete_all_objects(Dest),
    lists:foreach(
        fun(Element) ->
            ets:insert(Dest, Element)
        end,
        ets:tab2list(Src)).
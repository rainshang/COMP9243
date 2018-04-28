-module(router).
-export([start/1]).

start(RouterName) ->
    spawn(
        fun() ->
        init(RouterName)
        end).

init(RouterName) ->
    % init routing table and its backup
    RoutingTable = ets:new('RoutingTable', []),
    ets:insert(RoutingTable, {'$NoInEdges', 0}),
    RoutingTableBackup = ets:new('RoutingTableBackup', []),

    % init edge in set
    EdgeInSet = ets:new('EdgeInSet', []),
    % init the table of the control seqence received and where it came from
    CtrlSeqReceivedTable = ets:new('CtrlSeqReceivedTable', []),
    % init the table of the control seqence received and where it is sent to
    CtrlSeqForwardingTable = ets:new('CtrlSeqForwardingTable', []),
    
    % loop listen
    listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable).


listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable) ->
    receive
        {control, From, Pid, SeqNum, ControlFun} ->
            if
                % initialisation, callback the func directly, without any 2PC
                SeqNum == 0 ->
                    ControlFun(RouterName, RoutingTable),
                    io:format("~w(~w)'s routing table:", [RouterName, self()]),
                    lists:foreach(
                        fun(Element) ->
                            io:format(" ~w", [Element])
                        end,
                        ets:tab2list(RoutingTable)),
                    io:format("~n"),
                    From ! {committed, self(), SeqNum};
                % normal control sequence
                true ->
                    % update $NoInEdges
                    if
                        % coming from controller
                        Pid == From ->
                            next_step;
                        % coming from other router
                        true ->
                            % whether in EdgeInSet
                            case ets:member(EdgeInSet, From) of
                                false ->
                                    % no, log this in edge, in++
                                    ets:insert(EdgeInSet, {From}),
                                    io:format("~w's '$NoInEdges': ~w~n", [RouterName, ets:lookup_element(RoutingTable, '$NoInEdges', 2) + 1]),
                                    ets:update_counter(RoutingTable, '$NoInEdges', 1);
                                true ->
                                    already_count
                            end
                    end,

                    % check whether already received this control seqence
                    case ets:member(CtrlSeqReceivedTable, SeqNum) of
                        % yes, has received, using the forwarding chain, give back a mock committed result
                        true ->
                            From ! {committed, self(), Pid, SeqNum, ControlFun};
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
            end,
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {committed, From, Pid, SeqNum, ControlFun} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % log From returned 
            ets:update_element(ForwardingSet, From, {2, true}),
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
                    backupRoutingTable(RoutingTable, RoutingTableBackup),
                    case ControlFun(RouterName, RoutingTable) of
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
                                    Parent ! {committed, self (), Pid, SeqNum, ControlFun}
                            end
                    end;
                false ->
                    go_on
            end,
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {abort, From, Pid, SeqNum, ControlFun} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doAbort to all the routers who have committed
            lists:foreach(
                fun({Node, Status}) ->
                    case Status of
                        true ->
                            Node ! doAbort;
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
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {doAbort, SeqNum} ->
            % roll back
            recoverRoutingTable(RoutingTable, RoutingTableBackup),
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doAbort to all the routers who have committed
            lists:foreach(
                fun({Node, Status}) ->
                    case Status of
                        true ->
                            Node ! doAbort;
                        false ->
                            false
                    end
                end,
                ets:tab2list(ForwardingSet)),
            ets:delete(CtrlSeqForwardingTable, SeqNum),
            ets:delete(CtrlSeqReceivedTable, SeqNum),
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {doCommit, SeqNum} ->
            % get SeqNum's ForwardingSet
            ForwardingSet = ets:lookup_element(CtrlSeqForwardingTable, SeqNum, 2),
            % send doCommit
            lists:foreach(
                fun({Node, _}) ->
                    Node ! doCommit
                end,
                ets:tab2list(ForwardingSet)),
            ets:delete(CtrlSeqForwardingTable, SeqNum),
            ets:delete(CtrlSeqReceivedTable, SeqNum),
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {message, Dest, From, Pid, Trace} ->
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        {dump, From} ->
            listen(RouterName, RoutingTable, RoutingTableBackup, EdgeInSet, CtrlSeqReceivedTable, CtrlSeqForwardingTable);
        stop ->
            ok
    end. 

backupRoutingTable(RoutingTable, RoutingTableBackup) ->
    ets:delete_all_objects(RoutingTableBackup),
    lists:foreach(
        fun(Element) ->
            ets:insert(RoutingTableBackup, Element)
        end,
        ets:tab2list(RoutingTable)).

recoverRoutingTable(RoutingTable, RoutingTableBackup) ->
    ets:delete_all_objects(RoutingTable),
    lists:foreach(
        fun(Element) ->
            ets:insert(RoutingTable, Element)
        end,
        ets:tab2list(RoutingTableBackup)).
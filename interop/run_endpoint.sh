#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters
APPDIR="/usr/quic"
LOGDIR="/logs"
WWWDIR="/www"
DLDIR="/downloads"
if [ -z "$QLOGDIR" ]; then
    QLOGDIR="$LOGDIR"
fi
#MULTIPROCESS=1

case "$TESTCASE" in
    handshake | transfer | multiconnect | retry | chacha20 | resumption)
        echo "test case supported:" "$TESTCASE"
        ;;
    zerortt | http3)
        echo "test case not supported:" "$TESTCASE"
        exit 127
        ;;
    *)
        echo "test case unknown:" "$TESTCASE"
        exit 127
        ;;
esac

run_client() {
    CLIENT_PARAMS="$CLIENT_PARAMS -insecure -root $DLDIR -version 0xff00001d -v 3"
    case "$TESTCASE" in
    multiconnect)
        if [ "$MULTIPROCESS" = 1 ]; then
            # Fork a new process for each connection.
            for REQ in $REQUESTS; do
                NAME="$(basename $REQ)"
                PARAMS="$CLIENT_PARAMS -qlog $QLOGDIR/client-$NAME.qlog"
                echo "# CLIENT_PARAMS: $PARAMS"
                "$APPDIR/quiwi" client $PARAMS "$REQ" 2>>"$LOGDIR/client.txt" &
                sleep 2
            done
            wait
            return
        else
            CLIENT_PARAMS="$CLIENT_PARAMS -qlog $QLOGDIR/client.qlog"
        fi
        ;;
    resumption)
        CLIENT_PARAMS="$CLIENT_PARAMS -qlog $QLOGDIR/client.qlog"
        ;;
    chacha20)
        CLIENT_PARAMS="$CLIENT_PARAMS -cipher TLS_CHACHA20_POLY1305_SHA256 -multi -qlog $QLOGDIR/client.qlog"
        ;;
    *)
        CLIENT_PARAMS="$CLIENT_PARAMS -multi -qlog $QLOGDIR/client.qlog"
        ;;
    esac
    echo "# CLIENT_PARAMS:" "$CLIENT_PARAMS"
    "$APPDIR/quiwi" client $CLIENT_PARAMS $REQUESTS 2>"$LOGDIR/client.txt"
}

run_server() {
    SERVER_PARAMS="$SERVER_PARAMS -listen :443 -cert /certs/cert.pem -key /certs/priv.key -root $WWWDIR -qlog $QLOGDIR/server.qlog -v 3"
    case "$TESTCASE" in
    retry)
        SERVER_PARAMS="$SERVER_PARAMS -retry"
        ;;
    esac
    echo "# SERVER_PARAMS:" "$SERVER_PARAMS"
    "$APPDIR/quiwi" server $SERVER_PARAMS 2>"$LOGDIR/server.txt"
    # FIXME: no qlog transformation as the script is terminated
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    run_client
elif [ "$ROLE" == "server" ]; then
    run_server
fi

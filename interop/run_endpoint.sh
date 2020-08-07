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

case "$TESTCASE" in
    handshake | transfer | multiconnect | retry | chacha20)
        echo "test case supported:" "$TESTCASE"
        ;;
    resumption | zerortt | http3)
        echo "test case not supported:" "$TESTCASE"
        exit 127
        ;;
    *)
        echo "test case unknown:" "$TESTCASE"
        exit 127
        ;;
esac

run_client() {
    CLIENT_PARAMS="$CLIENT_PARAMS -insecure -v 3"
    if [ "$TESTCASE" == chacha20 ]; then
        CLIENT_PARAMS="$CLIENT_PARAMS -cipher 0x1303"
    fi
    cd "$APPDIR"
    echo "# CLIENT_PARAMS:" "$CLIENT_PARAMS"
    # TODO: Support multiple requests
    for REQ in $REQUESTS; do
        NAME="$(basename $REQ)"
        ./quince client $CLIENT_PARAMS "$REQ" 2>"$LOGDIR/client-$NAME.txt" 1>"$DLDIR/$NAME"
        ./quince qlog "$LOGDIR/client-$NAME.txt" >"$QLOGDIR/client-$NAME.qlog" || true
    done
}

run_server() {
    SERVER_PARAMS="$SERVER_PARAMS -listen 0.0.0.0:443 -cert cert.pem -key key.pem -root $WWWDIR -v 3"
    if [ "$TESTCASE" == retry ]; then
        SERVER_PARAMS="$SERVER_PARAMS -retry"
    fi
    cd "$APPDIR"
    echo "# SERVER_PARAMS:" "$SERVER_PARAMS"
    ./quince server $SERVER_PARAMS 2>"$LOGDIR/server.txt"
    # FIXME: no qlog transformation as the script is terminated
    ./quince qlog "$LOGDIR/server.txt" >"$QLOGDIR/server.qlog" || true
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    run_client
elif [ "$ROLE" == "server" ]; then
    run_server
fi

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
    CLIENT_PARAMS="$CLIENT_PARAMS -insecure -root $DLDIR -qlog "$QLOGDIR/client.qlog" -v 3"
    if [ "$TESTCASE" == chacha20 ]; then
        CLIENT_PARAMS="$CLIENT_PARAMS -cipher TLS_CHACHA20_POLY1305_SHA256"
    fi
    cd "$APPDIR"
    echo "# CLIENT_PARAMS:" "$CLIENT_PARAMS"
    ./quiwi client $CLIENT_PARAMS $REQUESTS 2>"$LOGDIR/client.txt"
}

run_server() {
    SERVER_PARAMS="$SERVER_PARAMS -listen 0.0.0.0:443 -cert cert.pem -key key.pem -root $WWWDIR -qlog "$QLOGDIR/server.qlog" -v 3"
    if [ "$TESTCASE" == retry ]; then
        SERVER_PARAMS="$SERVER_PARAMS -retry"
    fi
    cd "$APPDIR"
    echo "# SERVER_PARAMS:" "$SERVER_PARAMS"
    ./quiwi server $SERVER_PARAMS 2>"$LOGDIR/server.txt"
    # FIXME: no qlog transformation as the script is terminated
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    run_client
elif [ "$ROLE" == "server" ]; then
    run_server
fi

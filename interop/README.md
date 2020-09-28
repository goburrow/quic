# Testing

## Quiche

```
cd /path/to/quiche/tools/apps
cargo build --release
# Client
RUST_LOG=trace ./target/release/quiche-client --no-verify https://127.0.0.1:4433
# Server
RUST_LOG=trace ./target/release/quiche-server
```

## QUIC Interop

https://github.com/marten-seemann/quic-interop-runner/

```
# Build image
./build-docker.sh
# or with debug
./build-docker.sh -tags debug
```

```
cd /path/to/quic-interop-runner
# Install packages
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
./certs.sh .
# Run test cases
./run.py -s quiwi -c quiwi
```

## QUIC Tracker

https://github.com/QUIC-Tracker/quic-tracker

```
docker run -it --rm -v "$PWD:/traces" -w /traces -p 5000:5000 mpiraux/quictracker /bin/sh
# Start server
./quiwi server -cert cert.pem -key key.pem -root . -v 3 -qlog server.qlog 2>server.txt &
# Run single test case
/scenario_runner -debug -host 127.0.0.1:4433 -output 20200101.json -scenario multi_packet_client_hello
# Run all test cases
/test_suite -hosts ./ietf_quic_hosts.txt -debug -parallel-scenarios -output 20200101.json
# View results
flask run -h 0.0.0.0
```
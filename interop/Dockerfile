FROM martenseemann/quic-network-simulator-endpoint:latest

COPY quiwi cert.pem key.pem /usr/quic/
COPY run_endpoint.sh /

ENTRYPOINT [ "/run_endpoint.sh" ]

FROM alpine

RUN apk add --no-cache curl perl

ENTRYPOINT ["/bin/sh", "-c", "/mnt/client_traffic_test.sh; exec tail -f /dev/null"]
FROM debian:stable-slim

RUN adduser --system --no-create-home --disabled-login --group nginx && \
    mkdir --parents /usr/local/nginx/logs

CMD ["/bin/bash", "-c", "/mnt/monitor_overhead.sh & nginx -g 'daemon off;'"]
#!/bin/sh


[ -z "$NUM_UPLOADS" ] && NUM_UPLOADS=0
[ -z "$NUM_DOWNLOADS" ] && NUM_DOWNLOADS=0
[ -z "$BURST" ] && BURST=1
[ -z "$WAIT_TIME" ] && WAIT_TIME=0

if [ "$NUM_UPLOADS" -eq 0 ] && [ "$NUM_DOWNLOADS" -eq 0 ]; then
  echo "Neither NUM_UPLOADS nor NUM_DOWNLOADS is set."
  exit 1
fi


IP_ADDR=$(hostname -i | awk '{print $1}')
FOURTH_IP_OCTET=$(echo "$IP_ADDR" | awk -F. '{print $4}')
CLIENT_ID=$(expr "$FOURTH_IP_OCTET" - 2)
UPLOAD_FILE="/mnt/tmp_file.bin"

UPLOAD_URL="http://www.example-1.com/upload/upload.php"
DOWNLOAD_URL="http://www.example-1.com/tmp_file.bin"


if [ "$NUM_UPLOADS" -gt 0 ]; then

  i=1
  while [ "$i" -le "$NUM_UPLOADS" ]; do

    j=1
    while [ "$j" -le "$BURST" ] && [ "$i" -le "$NUM_UPLOADS" ]; do
      (
        TIMESTAMP=$(perl -MTime::HiRes=time -E 'printf("%.9f\n", time)')

        RES=$(curl --silent \
          --write-out "%{http_code},%{time_connect},%{time_starttransfer},%{time_total},%{size_upload},%{speed_upload}" \
          --output /dev/null \
          --form "file=@$UPLOAD_FILE" \
          "$UPLOAD_URL")

        CODE=$(echo "$RES" | cut -d',' -f1)
        CONNECT_TIME=$(echo "$RES" | cut -d',' -f2)
        STARTTRANSFER_TIME=$(echo "$RES" | cut -d',' -f3)
        RTT=$(echo "$RES" | cut -d',' -f4)
        SIZE_UPLOAD=$(echo "$RES" | cut -d',' -f5)
        SPEED_UPLOAD=$(echo "$RES" | cut -d',' -f6)

        echo "$CLIENT_ID, $i, $TIMESTAMP, $CODE, $CONNECT_TIME, $STARTTRANSFER_TIME, $RTT, $SIZE_UPLOAD, $SPEED_UPLOAD" >> /mnt/results/upload_results.csv
      ) &
      i=$((i + 1))
      j=$((j + 1))
    done

    sleep "$WAIT_TIME"
  done


else

  i=1
  while [ "$i" -le "$NUM_DOWNLOADS" ]; do

    j=1
    while [ "$j" -le "$BURST" ] && [ "$i" -le "$NUM_DOWNLOADS" ]; do
      (
        TIMESTAMP=$(perl -MTime::HiRes=time -E 'printf("%.9f\n", time)')

        RES=$(curl --silent \
          --write-out "%{http_code},%{time_connect},%{time_starttransfer},%{time_total},%{size_download},%{speed_download}" \
          --output /dev/null \
          "$DOWNLOAD_URL")

        CODE=$(echo "$RES" | cut -d',' -f1)
        CONNECT_TIME=$(echo "$RES" | cut -d',' -f2)
        STARTTRANSFER_TIME=$(echo "$RES" | cut -d',' -f3)
        RTT=$(echo "$RES" | cut -d',' -f4)
        SIZE_DOWNLOAD=$(echo "$RES" | cut -d',' -f5)
        SPEED_DOWNLOAD=$(echo "$RES" | cut -d',' -f6)

        echo "$CLIENT_ID, $i, $TIMESTAMP, $CODE, $CONNECT_TIME, $STARTTRANSFER_TIME, $RTT, $SIZE_DOWNLOAD, $SPEED_DOWNLOAD" >> /mnt/results/download_results.csv
      ) &
      i=$((i + 1))
      j=$((j + 1))
    done

    sleep "$WAIT_TIME"
  done
fi


wait
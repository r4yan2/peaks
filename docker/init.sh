#!/bin/sh

check_mysql(){
    wget -O - -T 2 "http://$MYSQL_HOST:$MYSQL_PORT" 2>&1 | grep -o mysql >/dev/null
    echo $?
}

while [ -z $(check_mysql) ]; do
    sleep 5s
    echo "Waiting for MySQL..."
done
if [ -f /etc/peaks/done_init ]; then
    return
fi
peaks import --init /etc/peaks/schema.sql
peaks build
touch /etc/peaks/done_init

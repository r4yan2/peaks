#!/bin/sh

check_mysql(){
    wget -O - -T 2 "http://$MYSQL_HOST:$MYSQL_PORT" 2>&1 | grep -o mysql >/dev/null
    echo $?
}

while ! check_mysql; do
    sleep 5s
    echo "Waiting for MySQL..."
done
if [ -f /etc/peaks/done_init ]; then
    return
fi
peaks -s import --init /etc/peaks/schema.sql
peaks -s build
touch /etc/peaks/done_init

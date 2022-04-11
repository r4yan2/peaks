#!/bin/sh
until mysqladmin ping -h$MYSQL_HOST --silent
do
    echo "Waiting for MySQL..."
    sleep 5s
done
if [ -f /etc/peaks/done_init ]; then
    return 0
fi
if [ ! -f /etc/peaks/peaks_config ]; then
    cp /srv/peaks/default_config /etc/peaks/peaks_config
    echo "db_host = $MYSQL_HOST" >> /etc/peaks/peaks_config
    echo "db_user = $MYSQL_USER" >> /etc/peaks/peaks_config
    echo "db_password = $MYSQL_PASSWORD" >> /etc/peaks/peaks_config
    echo "db_port = $MYSQL_PORT" >> /etc/peaks/peaks_config
    echo "# keyserver.linux.it 11370" >> /etc/peaks/membership
fi
peaks -s import --init /srv/peaks/schema.sql
peaks -s build
touch /etc/peaks/done_init
return 0

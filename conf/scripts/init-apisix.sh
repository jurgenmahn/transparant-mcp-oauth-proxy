#!/bin/bash

echo "apisix init"
/usr/bin/apisix init
echo "apisix init etcd"
/usr/bin/apisix init_etcd
chmod 666 /usr/local/apisix/conf/nginx.conf
echo "apisix start"
rm -f /usr/local/apisix/logs/worker_events.sock
/usr/local/openresty/bin/openresty -p /usr/local/apisix -g "daemon off;"

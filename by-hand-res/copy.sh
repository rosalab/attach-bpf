#!/usr/bin/bash
scp -O -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -P 64000 root@127.0.0.1:/linux-dev-env/iozone3_507/src/current/$1 ./$2

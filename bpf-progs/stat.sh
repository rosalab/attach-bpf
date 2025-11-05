#!/usr/bin/bash
#
start=$(date +%s%N)
for i in $(seq 1 100)
do
    stat alloclat.kern.c > /dev/null
done
end=$(date +%s%N)

echo $((end - start))

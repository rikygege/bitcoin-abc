#!/bin/bash - 

set -o nounset                              # Treat unset variables as an error

./bench_bitcoin &
./bench_bitcoin &
./bench_bitcoin &
./bench_bitcoin &
./bench_bitcoin 

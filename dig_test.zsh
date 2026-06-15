#!/bin/zsh

# clang++ src/*.cpp -I include -I bench -I /opt/homebrew/opt/boost/include -Wall -std=c++20 -o dns_server -O3
echo "compiled"
./dns_server &
METRICS_PID=$!

domains=(
    "ozyegin.edu.tr"
    "money.xyz"
    "para.net"
    "cloudflare.com"
    "www.brother.in"
    "music.youtube.com"
    "ozuplanner.com"
    "one.one.one.one.com"
    "edu."
    "gemini.google.com"
    "ai."
)

rrtypes=(
    "A"
    "AAAA"
    "MX"
    "NS"
    "TXT"
)

ITERATIONS=0
PORT=3270

run_dig() {
    local domain=$1
    local type=$2
    dig "@localhost" -p $PORT "$domain" "$type" +tries=1 +short # > /dev/null 2>&1
}

echo "Starting warm up..."
warmup_pids=()
for domain in $domains; do
    for type in $rrtypes; do
        run_dig "$domain" "$type" &
        warmup_pids+=($!)
    done
done

wait $warmup_pids
echo "warm up done"

for ((i=0; i<ITERATIONS; i++)); do
    dig_pids=()
    echo "iteration $i"
    for d in $domains; do
        for t in $rrtypes; do
            run_dig "$d" "$t" &
            dig_pids+=($!)
        done
    done
    wait $dig_pids
done

kill -INT $METRICS_PID
sleep 1

trap "kill -INT $METRICS_PID" SIGINT EXIT
echo "done"

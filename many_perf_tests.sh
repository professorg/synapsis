#!/usr/bin/env bash

OUT_PATH="./result/chat_deletion_performance_2"

mkdir -p $OUT_PATH

for i in {1..500}
do
  echo "$i"
  ./generate_test_data.py 0 0 0 100 $((1000*i)) 10
  cargo test count_chat_deletion_performance -j 1 -- --test-threads=1
  cp ./result/chat_deletion_performance.json "$OUT_PATH/$i.json"
  echo Done
done


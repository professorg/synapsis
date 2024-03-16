#!/usr/bin/env bash

mkdir ./result/chat_deletion_performance/

for i in {1..500}
do
  echo "$i"
  ./generate_test_data.py
  cargo test count_chat_deletion_performance -j 1 -- --test-threads=1
  cp ./result/chat_deletion_performance.json "./result/chat_deletion_performance/$i.json"
  echo Done
done


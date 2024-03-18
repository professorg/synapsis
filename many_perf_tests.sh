#!/usr/bin/env bash

OUT_PATH="./result/chat_redaction_performance_3"
TEST_NAME="count_chat_redaction_performance"

mkdir -p $OUT_PATH

for i in {1..100}
do
  success=false
  while [ $success = false ]
  do
    echo "$i"
    rm ./result/chat_redaction_performance.json
    ./generate_test_data.py 0 0 0 100 $((1000*i)) 10
    cargo test "$TEST_NAME" -j 1 -- --test-threads=1
    cp ./result/chat_redaction_performance.json "$OUT_PATH/$i.json"
    if [ $? -eq 0 ]
    then
      success=true
    fi
    echo Done
  done
done


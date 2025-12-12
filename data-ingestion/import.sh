#!/usr/bin/env bash

 python import_odc_to_neo4j.py \
      --target-dir "$(pwd)"/../version-scanner-odc/java-project \
      --project my_project \
      --neo4j-uri bolt://localhost:7687 \
      --neo4j-user neo4j \
      --neo4j-password password


python verify_neo4j.py
#!/usr/bin/env bash

podman run --rm -it \
  -v "$(pwd)/../version-scanner-odc":/workspace \
  ghcr.io/joernio/joern \
  joern-parse /workspace/apollo --language java --output /workspace/joern/apollo.cpg


podman run --rm -it \
  -v "$(pwd)/../version-scanner-odc":/workspace \
  ghcr.io/joernio/joern \
  joern-export \
    --repr neo4jcsv \
    --out /workspace/joern/neo4j-import \
    /workspace/joern/my-java-app.cpg

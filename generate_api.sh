#!/bin/bash

rm -rf ../photon-api && npx @openapitools/openapi-generator-cli generate -i src/openapi/specs/api.yaml -g rust -o ../photon-api

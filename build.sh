#!/bin/bash

# Check, build, test the hvclient. 

gofumports -d ./. &&
golint ./... &&
go build ./... &&
go test || {
    echo "hvclient build failed" 1>&2
    exit 1
}


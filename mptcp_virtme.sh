#!/bin/bash

docker run \
	-e INPUT_NO_BLOCK=1 \
	-e INPUT_PACKETDRILL_NO_SYNC=1 \
	-v "${PWD}:${PWD}:rw" -w "${PWD}" --privileged --rm -it \
        --pull always ghcr.io/multipath-tcp/mptcp-upstream-virtme-docker:latest \
	auto-btf-debug

#	<manual-normal | manual-debug | manual-btf | auto-normal | auto-debug | auto-btf | auto-all | auto-btf-debug>

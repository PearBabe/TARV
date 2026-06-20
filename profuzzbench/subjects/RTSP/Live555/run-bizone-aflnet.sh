#!/bin/bash

export TARGET_DIR=${TARGET_DIR:-"live555"}
export INPUTS=${INPUTS:-"${WORKDIR}/in-rtsp"}

export AFLNET_MONITOR_LOG_DIR=${AFLNET_MONITOR_LOG_DIR:-"${WORKDIR}/${TARGET_DIR}/testProgs/${OUTDIR}/bizone"}
mkdir -p "${AFLNET_MONITOR_LOG_DIR}"

export AFLNET_CAMPAIGN=${AFLNET_CAMPAIGN:-"profuzzbench"}
export AFLNET_SUBJECT=${AFLNET_SUBJECT:-"live555"}
export AFLNET_FUZZER_NAME=${AFLNET_FUZZER_NAME:-"bizone-aflnet"}

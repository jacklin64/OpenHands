#!/usr/bin/env bash
# SWE-Universe / Scale-SWE: repo may live under ``workdir`` (e.g. /workspace/repo) instead of /testbed.
# Leaves the tree at /workspace/<basename(workdir)> for OpenHands (_get_swebench_workspace_dir_name).

set -e

source ~/.bashrc
SWEUTIL_DIR=/swe_util

if [ -z "$SWE_INSTANCE_ID" ]; then
    echo "Error: SWE_INSTANCE_ID is not set." >&2
    exit 1
fi

item=$(jq --arg INSTANCE_ID "$SWE_INSTANCE_ID" '.[] | select(.instance_id == $INSTANCE_ID)' "$SWEUTIL_DIR/eval_data/instances/swe-bench-instance.json")

if [[ -z "$item" || "$item" == "null" ]]; then
    echo "No item found for the provided instance ID."
    exit 1
fi

workdir=$(echo "$item" | jq -r '.workdir // empty')
if [[ -n "$workdir" && "$workdir" != "null" ]]; then
    workdir="${workdir%/}"
    WORKSPACE_NAME=$(basename "$workdir")
else
    WORKSPACE_NAME=$(echo "$item" | jq -r '(.repo | tostring) + "__" + (.version | tostring) | gsub("/"; "__")')
fi

echo "WORKSPACE_NAME: $WORKSPACE_NAME"

if [ -d /testbed ] && [ -n "$(ls -A /testbed 2>/dev/null)" ]; then
    SRC=/testbed
elif [[ -n "$workdir" && "$workdir" != "null" && -d "$workdir" ]]; then
    SRC="$workdir"
else
    echo "Error: SWE-Universe setup needs a non-empty /testbed or an existing workdir path; workdir=${workdir:-<empty>}" >&2
    exit 1
fi

mkdir -p /workspace

# If the repo lives under /workspace, rm -rf /workspace/* would delete the source — stage first.
if [[ "$SRC" == /workspace/* ]]; then
    STAGING=$(mktemp -d)
    cp -a "$SRC"/. "$STAGING/"
    rm -rf /workspace/*
    mkdir -p "/workspace/$WORKSPACE_NAME"
    cp -a "$STAGING"/. "/workspace/$WORKSPACE_NAME/"
    rm -rf "$STAGING"
else
    rm -rf /workspace/*
    mkdir -p /workspace
    cp -a "$SRC" "/workspace/$WORKSPACE_NAME"
fi

if [ -d /opt/miniconda3 ]; then
    # shellcheck source=/dev/null
    . /opt/miniconda3/etc/profile.d/conda.sh
    conda activate testbed 2>/dev/null || true
fi

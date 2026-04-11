#!/usr/bin/env bash

source ~/.bashrc
SWEUTIL_DIR=/swe_util

# FIXME: Cannot read SWE_INSTANCE_ID from the environment variable
# SWE_INSTANCE_ID=django__django-11099
if [ -z "$SWE_INSTANCE_ID" ]; then
    echo "Error: SWE_INSTANCE_ID is not set." >&2
    exit 1
fi

# Read the swe-bench-test-lite.json file and extract the required item based on instance_id
item=$(jq --arg INSTANCE_ID "$SWE_INSTANCE_ID" '.[] | select(.instance_id == $INSTANCE_ID)' $SWEUTIL_DIR/eval_data/instances/swe-bench-instance.json)

if [[ -z "$item" ]]; then
  echo "No item found for the provided instance ID."
  exit 1
fi


# HF ``nebius/SWE-rebench`` rows may omit ``version``; match
# ``_get_swebench_workspace_dir_name`` in run_infer.py and instance_swe_entry_rebenchv2.sh.
WORKSPACE_NAME=$(echo "$item" | jq -r '
  if (.version != null) and ((.version | tostring | length) > 0) then
    ((.repo | tostring) + "__" + (.version | tostring)) | gsub("/"; "__")
  else
    (.instance_id | tostring) | gsub("/"; "__")
  end
')

echo "WORKSPACE_NAME: $WORKSPACE_NAME"

# Clear the workspace
if [ -d /workspace ]; then
    rm -rf /workspace/*
else
    mkdir /workspace
fi
# Copy repo to workspace
if [ -d /workspace/$WORKSPACE_NAME ]; then
    rm -rf /workspace/$WORKSPACE_NAME
fi
mkdir -p /workspace
cp -r /testbed /workspace/$WORKSPACE_NAME

# Activate instance-specific environment
if [ -d /opt/miniconda3 ]; then
    . /opt/miniconda3/etc/profile.d/conda.sh
    conda activate testbed
fi

export PATH=/opt/conda/envs/testbed/bin:$PATH

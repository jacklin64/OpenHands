#!/usr/bin/env bash
# SWE-bench-Pro images keep the checkout under /app (not /testbed).
# WORKSPACE_NAME must match ``_get_swebench_workspace_dir_name`` in run_infer.py:
#   1) repo_name → last path segment
#   2) else workdir → basename
#   3) else repo + "__" + version (slashes → "__")

source ~/.bashrc
SWEUTIL_DIR=/swe_util

if [ -z "$SWE_INSTANCE_ID" ]; then
    echo "Error: SWE_INSTANCE_ID is not set." >&2
    exit 1
fi

item=$(jq --arg INSTANCE_ID "$SWE_INSTANCE_ID" '.[] | select(.instance_id == $INSTANCE_ID)' "$SWEUTIL_DIR/eval_data/instances/swe-bench-instance.json")

if [[ -z "$item" ]]; then
  echo "No item found for the provided instance ID."
  exit 1
fi

WORKSPACE_NAME=$(echo "$item" | jq -r '
  if (.repo_name != null) and ((.repo_name | tostring | length) > 0) then
    (.repo_name | tostring | split("/") | .[-1])
  elif (.workdir != null) and ((.workdir | tostring | length) > 0) then
    (.workdir | tostring | split("/") | .[-1])
  elif (.repo != null) and (.version != null) and ((.version | tostring | length) > 0) and ((.version | tostring | ascii_downcase) != "nan") then
    ((.repo | tostring) + "__" + (.version | tostring)) | gsub("/"; "__")
  else
    (.instance_id | tostring) | gsub("/"; "__")
  end
')

echo "WORKSPACE_NAME: $WORKSPACE_NAME"

mkdir -p /workspace

SOURCE="/app"
if [ ! -d "$SOURCE" ]; then
  SOURCE="/testbed"
fi
if [ ! -d "$SOURCE" ]; then
  echo "Error: neither /app nor /testbed exists; cannot populate workspace." >&2
  exit 1
fi

DEST="/workspace/$WORKSPACE_NAME"
# SWE-bench-Pro images bake the repo at /app. Symlink into /workspace instead of copying.
if [ "$SOURCE" = "/app" ]; then
    rm -rf "$DEST"
    ln -sfn "$SOURCE" "$DEST"
else
    if [ -d /workspace ]; then
        rm -rf /workspace/*
    fi
    if [ -d "$DEST" ]; then
        rm -rf "$DEST"
    fi
    cp -r "$SOURCE" "$DEST"
fi

if [ -d /opt/miniconda3 ]; then
    . /opt/miniconda3/etc/profile.d/conda.sh
    conda activate testbed 2>/dev/null || true
fi
export PATH=/opt/conda/envs/testbed/bin:$PATH

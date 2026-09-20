#!/bin/bash

#####################################################################
# UOV-Coprocessor - 2026
# Lightweight UOV Co-processor with Oil Space Blinding
# Florian Krieger, Maciej Czuprynko, Sujoy Sinha Roy
# Graz University of Technology
# Contact: florian.krieger (at) tugraz.at
# URL: https://github.com/flokrieger/UOV-Coprocessor
#
# Licensed under the MIT License.
#####################################################################
#
# This is the main script to execute this artifact. Before running,
# please set up the required software and hardware as described
# in README.md
#
#####################################################################

set -eo pipefail

SKIP_BUILD=0
usage() {
  echo "Usage: $(basename "$0") [--skip-build]"
  echo "  --skip-build  Skip Vitis HLS and Vivado; reuse the bitstream already in results/"
}
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [ "$SKIP_BUILD" -eq 1 ] && [ ! -f results/uov_cw.bit ]; then
  echo "Error: --skip-build needs a pre-built bitstream at results/uov_cw.bit, but the file is missing." >&2
  exit 1
fi

UV="$(command -v uv || true)"
[ -n "$UV" ] || UV="$HOME/.local/bin/uv"
if [ ! -x "$UV" ]; then
  echo "Error: 'uv' was not found!"
  exit 1
fi

# Set up the python environment used by all steps below
"$UV" venv --python 3.12
"$UV" pip install -r requirements.txt
source .venv/bin/activate
printf '%s\n\n' "===== Done Installation ====="

# Compare against KAT files and generate test vectors
echo "===== Check UOV Python against KAT and generate test vectors ====="
cd uov_ref
python3 uov.py
printf '%s\n\n' "===== Done UOV Python ====="

if [ "$SKIP_BUILD" -eq 1 ]; then
  printf '%s\n\n' "===== Skipping Vitis HLS and Vivado ====="
else
  # Run Vitis HLS to generate the UOV IP
  printf '%s\n\n' "===== Run Vitis HLS ====="
  cd ../vitis
  vitis_hls -f run_vitis_hls.tcl 2>&1 | tee ../results/vitis_hls.log
  printf '%s\n\n' "===== Done Vitis HLS ====="

  # Run Vivado to simulate, synthesize and implement the design
  # for the ChipWhisperer CW305 FPGA board. This also exports the
  # bitstream, utilization, and timing reports to results/
  printf '%s\n\n' "===== Run Vivado ====="
  vivado -mode batch -source run_vivado_cw.tcl 2>&1 | tee ../results/vivado.log
  printf '%s\n\n' "===== Done Vivado ====="
fi

# Run the tests and trace collection on the FPGA
printf '%s\n\n' "===== Run Trace Collection on FPGA ====="
cd ../cw
python3 mainCW305.py
printf '%s\n\n' "===== Done Trace Collection on FPGA ====="

# Present results in PDF report
printf '%s\n\n' "===== Compile Artifact Report ====="
cd ../results
python3 makeReport.py
printf '%s\n\n' "===== Done Artifact Report ====="

printf "===== ARTIFACT SCRIPT DONE ====="

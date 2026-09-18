#!/bin/bash
set -eo pipefail

# Set up the python environment used by all steps below
curl -LsSf https://astral.sh/uv/install.sh | sh
~/.local/bin/uv venv --python 3.12
~/.local/bin/uv pip install -r requirements.txt
source .venv/bin/activate
printf '%s\n\n' "===== Done Installation ====="

# Compare against KAT files and generate test vectors
echo "===== Check UOV Python against KAT and generate test vectors ====="
cd uov_ref
python3 uov.py
printf '%s\n\n' "===== Done UOV Python ====="

# Run Vitis HLS to generate the UOV IP
printf '%s\n\n' "===== Run Vitis HLS ====="
cd ../vitis
vitis_hls -f run_vitis_hls.tcl 2>&1 | tee ../results/vitis_hls.log
printf '%s\n\n' "===== Done Vitis HLS ====="

# Run Vivado to simulate, synthesize and implement the design
# for the ChipWhisperer 305 FPGA board. This also exports the
# bitstream to results/ and the utilization and timing reports to
# results/
printf '%s\n\n' "===== Run Vivado ====="
vivado -mode batch -source run_vivado_cw.tcl 2>&1 | tee ../results/vivado.log
printf '%s\n\n' "===== Done Vivado ====="

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

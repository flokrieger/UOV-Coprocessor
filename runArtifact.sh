#!/bin/bash
set -eo pipefail

# Set up the python environment used by all steps below
curl -LsSf https://astral.sh/uv/install.sh | sh
~/.local/bin/uv venv --python 3.12
~/.local/bin/uv pip install -r requirements.txt
source .venv/bin/activate
echo "===== Done Installation =====\n"

# Compare against KAT files and generate test vectors
echo "===== Check UOV Python against KAT and generate test vectors ====="
cd uov_ref
python3 uov.py
echo "===== Done UOV Python =====\n"

# Run Vitis HLS to generate the UOV IP
echo "===== Run Vitis HLS =====\n"
cd ../vitis
vitis_hls -f run_vitis_hls.tcl 2>&1 | tee ../results/vitis_hls.log
echo "===== Done Vitis HLS =====\n"

# Run Vivado to simulate, synthesize and implement the design
# for the ChipWhisperer 305 FPGA board. This also exports the
# bitstream to results/ and the utilization and timing reports to
# results/
echo "===== Run Vivado =====\n"
vivado -mode batch -source run_vivado_cw.tcl 2>&1 | tee ../results/vivado.log
echo "===== Done Vivado =====\n"

# Run the tests and trace collection on the FPGA
echo "===== Run Trace Collection on FPGA =====\n"
cd ../cw
python3 mainCW305.py
echo "===== Done Trace Collection on FPGA =====\n"

# Present results in PDF report
echo "===== Compile Artifact Report =====\n"
cd ../results
python3 makeReport.py
echo "===== Done Artifact Report =====\n"

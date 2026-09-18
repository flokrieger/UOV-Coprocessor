#!/bin/bash
set -eo pipefail

# Compare against KAT files and generate test vectors
sudo docker buildx build -t uov:latest .
sudo docker run -v "$PWD/uov_ref/data:/sage/uov_ref/data" uov:latest


# Run Vitis HLS to generate the UOV IP
cd vitis
vitis_hls -f run_vitis_hls.tcl 2>&1 | tee ../results/vitis_hls.log

# Run Vivado to simulate, synthesize and implement the design
# for the ChipWhisperer 305 FPGA board. This also exports the
# bitstream to bit/ and the utilization and timing reports to
# results/
vivado -mode batch -source run_vivado_cw.tcl 2>&1 | tee ../results/vivado.log

# Run the tests and trace collection on the FPGA
cd ..
# curl -LsSf https://astral.sh/uv/install.sh | sh
# ~/.local/bin/uv venv --python 3.12
# ~/.local/bin/uv pip install -r requirements.txt
source .venv/bin/activate
cd cw
python3 mainCW305.py

# Present results in PDF report
cd ..
python3 results/makeReport.py

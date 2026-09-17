#!/bin/bash

# Compare against KAT files and generate test vectors
sudo docker buildx build -t uov:latest .
sudo docker run -v "$PWD/uov_ref/data:/sage/uov_ref/data" uov:latest


# Run Vitis HLS to generate the UOV IP
cd vitis
vitis_hls -f run_vitis_hls.tcl

# Run Vivado to simulate, synthesize and implement the design 
# for the ChipWhisperer 305 FPGA board. This also exports the 
# bitstream to bit/ and opens the post-implementation area 
# utilization report
vivado -source run_vivado_cw.tcl

# Run the tests and trace collection on the FPGA
cd ../cw
curl -LsSf https://astral.sh/uv/install.sh | sh
~/.local/bin/uv venv --python 3.12
~/.local/bin/uv pip install -r requirements.txt
source .venv/bin/activate
python3 mainCW305.py
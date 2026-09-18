/////////////////////////////////////////////////////////////////////
// Derived from the OpenNTT project:
// OpenNTT - 2024
// Florian Krieger, Florian Hirner, Ahmet Can Mert, Sujoy Sinha Roy
// Contact: florian.krieger@iaik.tugraz.at
// URL: https://github.com/flokrieger/OpenNTT
//
// Licensed under the MIT License.
/////////////////////////////////////////////////////////////////////


// shift register with a variable number of registers
// see https://docs.xilinx.com/r/en-US/ug901-vivado-synthesis/Shift-Registers

`default_nettype wire

module shiftreg # (
  parameter DELAY = 0,
  parameter LOGQ  = 0,
  parameter TYPE  = ""
) (
  input             clk,
  input  [LOGQ-1:0] data_in,
  output [LOGQ-1:0] data_out
);

  reg [LOGQ-1:0] shift_array [DELAY-1:0];

  always @(posedge clk) begin
    shift_array[0] <= data_in;
  end

  generate
    for (genvar i = 0; i < DELAY-1; i = i+1) begin: DELAY_BLOCK
      always @(posedge clk) begin
        shift_array[i+1] <= shift_array[i];
      end
    end
  endgenerate

  generate
    if (DELAY == 0)
      assign data_out = data_in;
    else
      assign data_out = shift_array[DELAY-1];
  endgenerate

endmodule

/////////////////////////////////////////////////////////////////////
// Part of the UOV-Coprocessor artifact:
// https://github.com/flokrieger/UOV-Coprocessor
/////////////////////////////////////////////////////////////////////
//
// Derived from the OpenNTT project:
// OpenNTT - 2024
// Florian Krieger, Florian Hirner, Ahmet Can Mert, Sujoy Sinha Roy
// Contact: florian.krieger@iaik.tugraz.at
// URL: https://github.com/flokrieger/OpenNTT
//
// Licensed under the MIT License.
//
/////////////////////////////////////////////////////////////////////
//
// parametric true dual-port RAM (2 independent read+write ports)
//
/////////////////////////////////////////////////////////////////////

`default_nettype wire

module ramt2p # (
  parameter MEM_WIDTH    = 0,
  parameter MEM_DEPTH    = 0,  // address width in bits; array depth = 2^MEM_DEPTH
  parameter READ_LATENCY = 0,  // at least 1 (use xpm if more than 2)
  parameter OUTPUT_REG   = 0,  // 0: no output register, 1: output register using DFFs
  parameter MEM_TYPE     = ""  // options: "xpm_auto", "xpm_block", "xpm_distributed", "xpm_mixed", "xpm_ultra",
                               //          "fpga_block", "fpga_ultra", "fpga_distributed", "fpga_registers", "" (sim), "custom" (asic)
) (
  input                  clk,

  // Port A
  input                  wen_a,
  input  [MEM_DEPTH-1:0] addr_a,
  input  [MEM_WIDTH-1:0] din_a,
  output [MEM_WIDTH-1:0] dout_a,

  // Port B
  input                  wen_b,
  input  [MEM_DEPTH-1:0] addr_b,
  input  [MEM_WIDTH-1:0] din_b,
  output [MEM_WIDTH-1:0] dout_b
);

  if (MEM_TYPE == "asic") begin
    my_custom_ram_t2p (clk, wen_a, addr_a, din_a, dout_a, wen_b, addr_b, din_b, dout_b); // CHANGE MODULE NAME/INTERFACE
  end
  else if ((MEM_TYPE == "xpm_auto")        ||
           (MEM_TYPE == "xpm_block")       ||
           (MEM_TYPE == "xpm_distributed") ||
           (MEM_TYPE == "xpm_mixed")       ||
           (MEM_TYPE == "xpm_ultra")) begin

    wire [MEM_WIDTH-1:0] dout_ram_a, dout_ram_b;
    reg  [MEM_WIDTH-1:0] dout_ram_reg_a, dout_ram_reg_b;

    localparam XPM_MEM_TYPE = (MEM_TYPE == "xpm_block")       ? "block"       :
                              (MEM_TYPE == "xpm_ultra")       ? "ultra"       :
                              (MEM_TYPE == "xpm_distributed") ? "distributed" :
                              (MEM_TYPE == "xpm_mixed")       ? "mixed"       : "auto";

    // https://docs.xilinx.com/r/en-US/ug974-vivado-ultrascale-libraries/XPM_MEMORY_TDPRAM
    // xpm_memory_tdpram: True Dual Port RAM
    // Xilinx Parameterized Macro, version 2023.1
    xpm_memory_tdpram # (
        .ADDR_WIDTH_A       ( MEM_DEPTH                 ), // DECIMAL
        .ADDR_WIDTH_B       ( MEM_DEPTH                 ), // DECIMAL
        .BYTE_WRITE_WIDTH_A ( MEM_WIDTH                 ), // DECIMAL
        .BYTE_WRITE_WIDTH_B ( MEM_WIDTH                 ), // DECIMAL
        .MEMORY_PRIMITIVE   ( XPM_MEM_TYPE              ), // String
        .MEMORY_SIZE        ( MEM_WIDTH*(1<<MEM_DEPTH)  ), // DECIMAL
        .READ_DATA_WIDTH_A  ( MEM_WIDTH                 ), // DECIMAL
        .READ_DATA_WIDTH_B  ( MEM_WIDTH                 ), // DECIMAL
        .READ_LATENCY_A     ( READ_LATENCY              ), // DECIMAL
        .READ_LATENCY_B     ( READ_LATENCY              ), // DECIMAL
        .WRITE_DATA_WIDTH_A ( MEM_WIDTH                 ), // DECIMAL
        .WRITE_DATA_WIDTH_B ( MEM_WIDTH                 )  // DECIMAL
    ) xpm_memory_tdpram_inst (
        .dbiterrb           (                           ),
        .dbiterra           (                           ),
        .douta              ( dout_ram_a                ), // READ_DATA_WIDTH_A-bit output
        .doutb              ( dout_ram_b                ), // READ_DATA_WIDTH_B-bit output
        .sbiterra           (                           ),
        .sbiterrb           (                           ),
        .addra              ( addr_a                    ), // ADDR_WIDTH_A-bit input
        .addrb              ( addr_b                    ), // ADDR_WIDTH_B-bit input
        .clka               ( clk                       ),
        .clkb               ( clk                       ),
        .dina               ( din_a                     ), // WRITE_DATA_WIDTH_A-bit input
        .dinb               ( din_b                     ), // WRITE_DATA_WIDTH_B-bit input
        .ena                ( 1'b1                      ),
        .enb                ( 1'b1                      ),
        .injectdbiterra     ( 1'b0                      ),
        .injectdbiterrb     ( 1'b0                      ),
        .injectsbiterra     ( 1'b0                      ),
        .injectsbiterrb     ( 1'b0                      ),
        .regcea             ( 1'b1                      ),
        .regceb             ( 1'b1                      ),
        .rsta               ( 1'b0                      ),
        .rstb               ( 1'b0                      ),
        .sleep              ( 1'b0                      ),
        .wea                ( wen_a                     ),
        .web                ( wen_b                     )
    );
    // End of xpm_memory_tdpram_inst instantiation

    // output registers
    if (OUTPUT_REG == 1) begin
      always @(posedge clk) begin
        dout_ram_reg_a <= dout_ram_a;
        dout_ram_reg_b <= dout_ram_b;
      end
    end
    else begin
      always @(*) begin
        dout_ram_reg_a = dout_ram_a;
        dout_ram_reg_b = dout_ram_b;
      end
    end

    assign dout_a = dout_ram_reg_a;
    assign dout_b = dout_ram_reg_b;
  end
  else begin // fpga_* / sim / other

    reg  [MEM_WIDTH-1:0] dout_ram_a, dout_ram_b;
    wire [MEM_WIDTH-1:0] dout_ram_w_a, dout_ram_w_b;
    reg  [MEM_WIDTH-1:0] dout_ram_reg_a, dout_ram_reg_b;

    localparam FPGA_MEM_TYPE = (MEM_TYPE == "fpga_block")       ? "block"       :
                               (MEM_TYPE == "fpga_ultra")       ? "ultra"       :
                               (MEM_TYPE == "fpga_distributed") ? "distributed" :
                               (MEM_TYPE == "fpga_registers")   ? "registers"   : "";

    (* ram_style=FPGA_MEM_TYPE *) reg [MEM_WIDTH-1:0] ram [(1<<MEM_DEPTH)-1:0];

    // port A: write then read (read-first)
    always @(posedge clk) begin
      if (wen_a) ram[addr_a] <= din_a;
      dout_ram_a <= ram[addr_a];
    end

    // port B: write then read (read-first)
    always @(posedge clk) begin
      if (wen_b) ram[addr_b] <= din_b;
      dout_ram_b <= ram[addr_b];
    end

    // shift registers for additional latency cycles
    shiftreg # (
        .LOGQ  ( MEM_WIDTH        ),
        .DELAY ( READ_LATENCY-1   )
    ) sr_a (
        clk, dout_ram_a, dout_ram_w_a
    );

    shiftreg # (
        .LOGQ  ( MEM_WIDTH        ),
        .DELAY ( READ_LATENCY-1   )
    ) sr_b (
        clk, dout_ram_b, dout_ram_w_b
    );

    // output registers
    if (OUTPUT_REG == 1) begin
      always @(posedge clk) begin
        dout_ram_reg_a <= dout_ram_w_a;
        dout_ram_reg_b <= dout_ram_w_b;
      end
    end
    else begin
      always @(*) begin
        dout_ram_reg_a = dout_ram_w_a;
        dout_ram_reg_b = dout_ram_w_b;
      end
    end

    assign dout_a = dout_ram_reg_a;
    assign dout_b = dout_ram_reg_b;
  end

endmodule

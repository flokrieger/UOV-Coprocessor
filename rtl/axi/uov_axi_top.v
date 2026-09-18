/////////////////////////////////////////////////////////////////////
// UOV-Coprocessor - 2026
// Lightweight UOV Co-processor with Oil Space Blinding
// Florian Krieger, Maciej Czuprynko, Sujoy Sinha Roy
// Graz University of Technology
// Contact: florian.krieger (at) tugraz.at
// URL: https://github.com/flokrieger/UOV-Coprocessor
//
// Licensed under the MIT License.
/////////////////////////////////////////////////////////////////////

`timescale 1ns / 1ps

// Vitis RTL-kernel top level for the UOV core.
module uov_axi_top #(
    parameter integer C_S_AXI_CONTROL_ADDR_WIDTH = 12,
    parameter integer C_S_AXI_CONTROL_DATA_WIDTH = 32
  ) (
    (* X_INTERFACE_PARAMETER = "ASSOCIATED_BUSIF s_axi_control, ASSOCIATED_RESET ap_rst_n" *)
    input  wire                                     ap_clk,
    input  wire                                     ap_rst_n,

    // AXI4-Lite control slave
    input  wire [C_S_AXI_CONTROL_ADDR_WIDTH-1:0]    s_axi_control_AWADDR,
    input  wire                                     s_axi_control_AWVALID,
    output wire                                     s_axi_control_AWREADY,
    input  wire [C_S_AXI_CONTROL_DATA_WIDTH-1:0]    s_axi_control_WDATA,
    input  wire [C_S_AXI_CONTROL_DATA_WIDTH/8-1:0]  s_axi_control_WSTRB,
    input  wire                                     s_axi_control_WVALID,
    output wire                                     s_axi_control_WREADY,
    output wire [1:0]                               s_axi_control_BRESP,
    output wire                                     s_axi_control_BVALID,
    input  wire                                     s_axi_control_BREADY,
    input  wire [C_S_AXI_CONTROL_ADDR_WIDTH-1:0]    s_axi_control_ARADDR,
    input  wire                                     s_axi_control_ARVALID,
    output wire                                     s_axi_control_ARREADY,
    output wire [C_S_AXI_CONTROL_DATA_WIDTH-1:0]    s_axi_control_RDATA,
    output wire [1:0]                               s_axi_control_RRESP,
    output wire                                     s_axi_control_RVALID,
    input  wire                                     s_axi_control_RREADY,

    output wire                                     interrupt
  );

  // Must match uov_pkg::BRAM_DWIDTH_BITS and uov_pkg::BRAM_AWIDTH_EXT_BITS.
  localparam integer WORD_BITS     = 128;
  localparam integer EXT_ADDR_BITS = 32;

  // ---------------------------------------------------------------------------
  // Register file <-> core
  // ---------------------------------------------------------------------------
  wire                     ap_start;
  wire                     uov_rst_sw;
  wire                     rng_en;
  wire                     do_blinding;
  wire                     do_verif;
  wire                     bram_wen;
  wire                     stream_tvalid;
  wire [15:0]              msg_len;
  wire [10:0]              uov_m;
  wire [10:0]              uov_v;
  wire [10:0]              uov_n;
  wire [10:0]              uov_n_padded;
  wire [31:0]              p1_bytes;
  wire [2:0]               nr_slices;
  wire [WORD_BITS-1:0]     seed_pk;
  wire [WORD_BITS-1:0]     seed_bl;
  wire [WORD_BITS-1:0]     bram_rd_data;
  wire [WORD_BITS-1:0]     bram_wr_data;
  wire [WORD_BITS-1:0]     stream_tdata;
  wire [EXT_ADDR_BITS-1:0] bram_rw_addr;

  wire                     core_done;
  wire                     core_ready;
  wire                     core_idle;
  wire                     axis_p3key_tready;


  wire uov_rst = !ap_rst_n || uov_rst_sw;
  wire ap_idle = uov_rst || core_idle;

  reg tvalid_d, tvalid_beat;
  always @(posedge ap_clk) begin
    tvalid_d <= stream_tvalid;

    if (uov_rst)                               tvalid_beat <= 1'b0;
    else if (tvalid_beat && axis_p3key_tready) tvalid_beat <= 1'b0;
    else if (!tvalid_d && stream_tvalid)       tvalid_beat <= 1'b1;
  end

  // ---------------------------------------------------------------------------
  // Register file
  // ---------------------------------------------------------------------------
  axil_control #(
      .ADDR_WIDTH   ( C_S_AXI_CONTROL_ADDR_WIDTH ),
      .WORD_BITS    ( WORD_BITS                  )
  ) axil_control_inst (
      .aclk         ( ap_clk                     ),
      .aresetn      ( ap_rst_n                   ),

      .awaddr       ( s_axi_control_AWADDR       ),
      .awvalid      ( s_axi_control_AWVALID      ),
      .awready      ( s_axi_control_AWREADY      ),
      .wdata        ( s_axi_control_WDATA        ),
      .wstrb        ( s_axi_control_WSTRB        ),
      .wvalid       ( s_axi_control_WVALID       ),
      .wready       ( s_axi_control_WREADY       ),
      .bresp        ( s_axi_control_BRESP        ),
      .bvalid       ( s_axi_control_BVALID       ),
      .bready       ( s_axi_control_BREADY       ),
      .araddr       ( s_axi_control_ARADDR       ),
      .arvalid      ( s_axi_control_ARVALID      ),
      .arready      ( s_axi_control_ARREADY      ),
      .rdata        ( s_axi_control_RDATA        ),
      .rresp        ( s_axi_control_RRESP        ),
      .rvalid       ( s_axi_control_RVALID       ),
      .rready       ( s_axi_control_RREADY       ),

      .ap_start     ( ap_start                   ),
      .ap_done      ( core_done                  ),
      .ap_ready     ( core_ready                 ),
      .ap_idle      ( ap_idle                    ),
      .interrupt    ( interrupt                  ),

      .uov_rst      ( uov_rst_sw                 ),
      .trng_en      ( rng_en                     ),
      .do_blinding  ( do_blinding                ),
      .do_verif     ( do_verif                   ),
      .bram_wen     ( bram_wen                   ),
      .stream_tvalid( stream_tvalid              ),
      .stream_tready( !tvalid_beat               ),

      .msg_len      ( msg_len                    ),
      .uov_m        ( uov_m                      ),
      .uov_v        ( uov_v                      ),
      .uov_n        ( uov_n                      ),
      .uov_n_padded ( uov_n_padded               ),
      .p1_bytes     ( p1_bytes                   ),
      .nr_slices    ( nr_slices                  ),
      .seed_pk      ( seed_pk                    ),
      .seed_bl      ( seed_bl                    ),

      .bram_rd_data ( bram_rd_data               ),
      .bram_wr_data ( bram_wr_data               ),
      .stream_tdata ( stream_tdata               ),
      .bram_rw_addr ( bram_rw_addr               )
  );

  // ---------------------------------------------------------------------------
  // UOV core
  // ---------------------------------------------------------------------------
  UovWrapper uov_wrapper_inst (
      .clk               ( ap_clk            ),
      .rst               ( uov_rst           ),
      .start             ( ap_start          ),
      .idle              ( core_idle         ),
      .ready             ( core_ready        ),
      .done              ( core_done         ),

      .msg_len_bytes     ( msg_len           ),
      .uov_m             ( uov_m             ),
      .uov_v             ( uov_v             ),
      .uov_n             ( uov_n             ),
      .uov_n_padded      ( uov_n_padded      ),
      .p1_bytes          ( p1_bytes          ),
      .nr_slices         ( nr_slices         ),
      .rng_en            ( rng_en            ),
      .seed_pk           ( seed_pk           ),
      .seed_bl           ( seed_bl           ),
      .do_verif          ( do_verif          ),
      .do_blinding       ( do_blinding       ),
      .trigger_uov       (                   ),

      .ext_rw_addr       ( bram_rw_addr      ),
      .ext_wr_en         ( bram_wen          ),
      .ext_rd_data       ( bram_rd_data      ),
      .ext_wr_data       ( bram_wr_data      ),

      .axis_p3key_tdata  ( stream_tdata      ),
      .axis_p3key_tvalid ( tvalid_beat       ),
      .axis_p3key_tready ( axis_p3key_tready )
  );

endmodule

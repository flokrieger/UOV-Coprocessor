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
//
// AXI4-Lite slave implementing the Vitis kernel control register map.
// The control register map (CTRL, GIER, IP_IER, IP_ISR) follows AMD/Xilinx 
// RTL kernel requirements here:
// https://docs.amd.com/r/2022.2-English/ug1393-vitis-application-acceleration/Requirements-of-an-RTL-Kernel
//
// Address Map:
//
//   0x00  CTRL      bit 0  ap_start                           RW, cleared on handshake
//                   bit 1  ap_done                            RO, cleared on read
//                   bit 2  ap_idle                            RO
//                   bit 3  ap_ready                           RO, cleared on read
//                   bit 7  auto_restart                       RW
//   0x04  GIER      bit 0  global interrupt enable            RW
//   0x08  IP_IER    bit 0  ap_done enable, bit 1 ap_ready     RW
//   0x0C  IP_ISR    bit 0  ap_done status, bit 1 ap_ready     RW, toggle on write
//
// ============================= Scalars =============================
//
//   0x10  UOV_CTRL              bit 0  uov_rst        RW
//                               bit 1  trng_en        RW
//                               bit 2  do_blinding    RW
//                               bit 3  do_verif       RW
//                               bit 4  bram_wen       RW
//                               bit 5  stream_tvalid  RW
//                               bit 6  stream_tready  R
//   0x14  MSG_LEN               bits 15:0             RW
//   0x18  UOV_M                 bits 10:0             RW
//   0x1C  UOV_V                 bits 10:0             RW
//   0x20  UOV_N                 bits 10:0             RW
//   0x24  UOV_N_PADDED          bits 10:0             RW
//   0x28  P1_BYTES              bits 31:0             RW
//   0x2c  NR_SLICES             bits  2:0             RW
//   0x30  seed_pk[ 31: 0]       bits 31:0             RW
//   0x34  seed_pk[ 63:32]       bits 31:0             RW
//   0x38  seed_pk[ 95:64]       bits 31:0             RW
//   0x3C  seed_pk[127:96]       bits 31:0             RW
//   0x40  seed_bl[ 31: 0]       bits 31:0             RW
//   0x44  seed_bl[ 63:32]       bits 31:0             RW
//   0x48  seed_bl[ 95:64]       bits 31:0             RW
//   0x4C  seed_bl[127:96]       bits 31:0             RW
//   0x50  bram_rd_data[ 31: 0]  bits 31:0             R
//   0x54  bram_rd_data[ 63:32]  bits 31:0             R
//   0x58  bram_rd_data[ 95:64]  bits 31:0             R
//   0x5C  bram_rd_data[127:96]  bits 31:0             R
//   0x60  bram_wr_data[ 31: 0]  bits 31:0             RW
//   0x64  bram_wr_data[ 63:32]  bits 31:0             RW
//   0x68  bram_wr_data[ 95:64]  bits 31:0             RW
//   0x6C  bram_wr_data[127:96]  bits 31:0             RW
//   0x70  stream_tdata[ 31: 0]  bits 31:0             RW
//   0x74  stream_tdata[ 63:32]  bits 31:0             RW
//   0x78  stream_tdata[ 95:64]  bits 31:0             RW
//   0x7C  stream_tdata[127:96]  bits 31:0             RW
//   0x80  bram_rw_addr[31:0]    bits 31:0             RW
/////////////////////////////////////////////////////////////////////

`timescale 1ns / 1ps

module axil_control #(
    parameter int ADDR_WIDTH = 12,
    parameter int WORD_BITS  = 128
  ) (
    input  wire                        aclk,
    input  wire                        aresetn,

    // AXI4-Lite slave
    input  wire [ADDR_WIDTH-1:0]       awaddr,
    input  wire                        awvalid,
    output wire                        awready,
    input  wire [31:0]                 wdata,
    input  wire [3:0]                  wstrb,
    input  wire                        wvalid,
    output wire                        wready,
    output wire [1:0]                  bresp,
    output wire                        bvalid,
    input  wire                        bready,
    input  wire [ADDR_WIDTH-1:0]       araddr,
    input  wire                        arvalid,
    output wire                        arready,
    output wire [31:0]                 rdata,
    output wire [1:0]                  rresp,
    output wire                        rvalid,
    input  wire                        rready,

    // Kernel control
    output wire                        ap_start,
    input  wire                        ap_done,
    input  wire                        ap_ready,
    input  wire                        ap_idle,
    output wire                        interrupt,

    // UOV control
    output wire                        uov_rst,
    output wire                        trng_en,
    output wire                        do_blinding,
    output wire                        do_verif,
    output wire                        bram_wen,
    output wire                        stream_tvalid,
    input  wire                        stream_tready,

    // UOV scalar arguments
    output wire [15:0]                 msg_len,
    output wire [10:0]                 uov_m,
    output wire [10:0]                 uov_v,
    output wire [10:0]                 uov_n,
    output wire [10:0]                 uov_n_padded,
    output wire [31:0]                 p1_bytes,
    output wire [2:0]                  nr_slices,
    output wire [WORD_BITS-1:0]        seed_pk,
    output wire [WORD_BITS-1:0]        seed_bl,

    // BRAM / stream data ports
    input  wire [WORD_BITS-1:0]        bram_rd_data,
    output wire [WORD_BITS-1:0]        bram_wr_data,
    output wire [WORD_BITS-1:0]        stream_tdata,
    output wire [31:0]                 bram_rw_addr
  );

  localparam int WORDS = WORD_BITS/32;

  localparam [ADDR_WIDTH-1:0] ADDR_CTRL         = 'h00;
  localparam [ADDR_WIDTH-1:0] ADDR_GIE          = 'h04;
  localparam [ADDR_WIDTH-1:0] ADDR_IER          = 'h08;
  localparam [ADDR_WIDTH-1:0] ADDR_ISR          = 'h0C;

  localparam [ADDR_WIDTH-1:0] ADDR_UOV_CTRL     = 'h10;
  localparam [ADDR_WIDTH-1:0] ADDR_MSG_LEN      = 'h14;
  localparam [ADDR_WIDTH-1:0] ADDR_UOV_M        = 'h18;
  localparam [ADDR_WIDTH-1:0] ADDR_UOV_V        = 'h1C;
  localparam [ADDR_WIDTH-1:0] ADDR_UOV_N        = 'h20;
  localparam [ADDR_WIDTH-1:0] ADDR_UOV_N_PADDED = 'h24;
  localparam [ADDR_WIDTH-1:0] ADDR_P1_BYTES     = 'h28;
  localparam [ADDR_WIDTH-1:0] ADDR_NR_SLICES    = 'h2C;
  localparam [ADDR_WIDTH-1:0] ADDR_SEED_PK      = 'h30;
  localparam [ADDR_WIDTH-1:0] ADDR_SEED_BL      = 'h40;
  localparam [ADDR_WIDTH-1:0] ADDR_BRAM_RD_DATA = 'h50;
  localparam [ADDR_WIDTH-1:0] ADDR_BRAM_WR_DATA = 'h60;
  localparam [ADDR_WIDTH-1:0] ADDR_STREAM_TDATA = 'h70;
  localparam [ADDR_WIDTH-1:0] ADDR_BRAM_RW_ADDR = 'h80;

  // ---------------------------------------------------------------------------
  // Write channel
  // ---------------------------------------------------------------------------
  typedef enum logic [1:0] { WR_RESET, WR_IDLE, WR_DATA, WR_RESP } wr_state_e;
  wr_state_e wstate, wnext;

  logic [ADDR_WIDTH-1:0] waddr;

  wire aw_hs = awvalid && awready;
  wire w_hs  = wvalid  && wready;

  assign awready = (wstate == WR_IDLE);
  assign wready  = (wstate == WR_DATA);
  assign bvalid  = (wstate == WR_RESP);
  assign bresp   = 2'b00;

  always_ff @(posedge aclk) begin
    if (!aresetn) wstate <= WR_RESET;
    else          wstate <= wnext;
  end

  always_comb begin
    case (wstate)
      WR_IDLE: wnext = awvalid ? WR_DATA : WR_IDLE;
      WR_DATA: wnext = wvalid  ? WR_RESP : WR_DATA;
      WR_RESP: wnext = bready  ? WR_IDLE : WR_RESP;
      default: wnext = WR_IDLE;
    endcase
  end

  always_ff @(posedge aclk) begin
    if (aw_hs) waddr <= awaddr;
  end

  // ---------------------------------------------------------------------------
  // Read channel
  // ---------------------------------------------------------------------------
  typedef enum logic [1:0] { RD_RESET, RD_IDLE, RD_DATA } rd_state_e;
  rd_state_e rstate, rnext;

  wire ar_hs = arvalid && arready;

  assign arready = (rstate == RD_IDLE);
  assign rvalid  = (rstate == RD_DATA);
  assign rresp   = 2'b00;

  always_ff @(posedge aclk) begin
    if (!aresetn) rstate <= RD_RESET;
    else          rstate <= rnext;
  end

  always_comb begin
    case (rstate)
      RD_IDLE: rnext = arvalid ? RD_DATA : RD_IDLE;
      RD_DATA: rnext = rready  ? RD_IDLE : RD_DATA;
      default: rnext = RD_IDLE;
    endcase
  end

  // ---------------------------------------------------------------------------
  // Vitis control registers
  // ---------------------------------------------------------------------------
  logic        int_ap_start;
  logic        int_ap_done;
  logic        int_ap_idle;
  logic        int_ap_ready;
  logic        int_auto_restart;
  logic        int_gie;
  logic [1:0]  int_ier;
  logic [1:0]  int_isr;

  assign ap_start  = int_ap_start;
  assign interrupt = int_gie && (|int_isr);

  wire ctrl_read = ar_hs && (araddr == ADDR_CTRL);

  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      int_ap_start <= 1'b0;
    end
    else if (w_hs && (waddr == ADDR_CTRL) && wstrb[0] && wdata[0]) begin
      int_ap_start <= 1'b1;
    end
    else if (ap_ready) begin
      int_ap_start <= int_auto_restart;
    end
  end

  always_ff @(posedge aclk) begin
    if (!aresetn)          int_ap_done <= 1'b0;
    else if (ap_done)      int_ap_done <= 1'b1;
    else if (ctrl_read)    int_ap_done <= 1'b0;
  end

  always_ff @(posedge aclk) begin
    if (!aresetn)          int_ap_ready <= 1'b0;
    else if (ap_ready)     int_ap_ready <= 1'b1;
    else if (ctrl_read)    int_ap_ready <= 1'b0;
  end

  always_ff @(posedge aclk) begin
    if (!aresetn) int_ap_idle <= 1'b1;
    else          int_ap_idle <= ap_idle;
  end

  always_ff @(posedge aclk) begin
    if (!aresetn)                                                int_auto_restart <= 1'b0;
    else if (w_hs && (waddr == ADDR_CTRL) && wstrb[0])            int_auto_restart <= wdata[7];
  end

  always_ff @(posedge aclk) begin
    if (!aresetn)                                                int_gie <= 1'b0;
    else if (w_hs && (waddr == ADDR_GIE) && wstrb[0])             int_gie <= wdata[0];
  end

  always_ff @(posedge aclk) begin
    if (!aresetn)                                                int_ier <= 2'b00;
    else if (w_hs && (waddr == ADDR_IER) && wstrb[0])             int_ier <= wdata[1:0];
  end

  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      int_isr <= 2'b00;
    end
    else begin
      if (int_ier[0] && ap_done)  int_isr[0] <= 1'b1;
      else if (w_hs && (waddr == ADDR_ISR) && wstrb[0]) int_isr[0] <= int_isr[0] ^ wdata[0];

      if (int_ier[1] && ap_ready) int_isr[1] <= 1'b1;
      else if (w_hs && (waddr == ADDR_ISR) && wstrb[0]) int_isr[1] <= int_isr[1] ^ wdata[1];
    end
  end

  // ---------------------------------------------------------------------------
  // UOV argument registers
  // ---------------------------------------------------------------------------
  logic                 int_uov_rst;
  logic                 int_trng_en;
  logic                 int_do_blinding;
  logic                 int_do_verif;
  logic                 int_bram_wen;
  logic                 int_stream_tvalid;
  logic [15:0]          int_msg_len;
  logic [10:0]          int_uov_m;
  logic [10:0]          int_uov_v;
  logic [10:0]          int_uov_n;
  logic [10:0]          int_uov_n_padded;
  logic [31:0]          int_p1_bytes;
  logic [2:0]           int_nr_slices;
  logic [WORD_BITS-1:0] int_seed_pk;
  logic [WORD_BITS-1:0] int_seed_bl;
  logic [WORD_BITS-1:0] int_bram_wr_data;
  logic [WORD_BITS-1:0] int_stream_tdata;
  logic [31:0]          int_bram_rw_addr;

  assign uov_rst       = int_uov_rst;
  assign trng_en       = int_trng_en;
  assign do_blinding   = int_do_blinding;
  assign do_verif      = int_do_verif;
  assign bram_wen      = int_bram_wen;
  assign stream_tvalid = int_stream_tvalid;
  assign msg_len       = int_msg_len;
  assign uov_m         = int_uov_m;
  assign uov_v         = int_uov_v;
  assign uov_n         = int_uov_n;
  assign uov_n_padded  = int_uov_n_padded;
  assign p1_bytes      = int_p1_bytes;
  assign nr_slices     = int_nr_slices;
  assign seed_pk       = int_seed_pk;
  assign seed_bl       = int_seed_bl;
  assign bram_wr_data  = int_bram_wr_data;
  assign stream_tdata  = int_stream_tdata;
  assign bram_rw_addr  = int_bram_rw_addr;

  wire [$clog2(WORDS)-1:0] wword = waddr[2 +: $clog2(WORDS)];
  wire [$clog2(WORDS)-1:0] rword = araddr[2 +: $clog2(WORDS)];

  localparam [ADDR_WIDTH-1:0] APERTURE = ADDR_WIDTH'(4*WORDS - 4);

  function automatic logic [31:0] wr_word(input logic [31:0] cur);
    wr_word = cur;
    for (int b = 0; b < 4; b++)
      if (wstrb[b]) wr_word[8*b +: 8] = wdata[8*b +: 8];
  endfunction

  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      int_uov_rst       <= 1'b1;
      int_trng_en       <= 1'b0;
      int_do_blinding   <= 1'b0;
      int_do_verif      <= 1'b0;
      int_bram_wen      <= 1'b0;
      int_stream_tvalid <= 1'b0;
      int_msg_len       <= 16'd0;
      int_uov_m         <= 11'd0;
      int_uov_v         <= 11'd0;
      int_uov_n         <= 11'd0;
      int_uov_n_padded  <= 11'd0;
      int_p1_bytes      <= 32'd0;
      int_nr_slices     <= 3'd0;
      int_seed_pk       <= '0;
      int_seed_bl       <= '0;
      int_bram_wr_data  <= '0;
      int_stream_tdata  <= '0;
      int_bram_rw_addr  <= 32'd0;
    end
    else if (w_hs) begin
      case (waddr) inside
        ADDR_UOV_CTRL: begin
          if (wstrb[0]) begin
            int_uov_rst       <= wdata[0];
            int_trng_en       <= wdata[1];
            int_do_blinding   <= wdata[2];
            int_do_verif      <= wdata[3];
            int_bram_wen      <= wdata[4];
            int_stream_tvalid <= wdata[5];
          end
        end
        ADDR_MSG_LEN: begin
          if (wstrb[0]) int_msg_len[7:0]  <= wdata[7:0];
          if (wstrb[1]) int_msg_len[15:8] <= wdata[15:8];
        end
        ADDR_UOV_M: begin
          if (wstrb[0]) int_uov_m[7:0]  <= wdata[7:0];
          if (wstrb[1]) int_uov_m[10:8] <= wdata[10:8];
        end
        ADDR_UOV_V: begin
          if (wstrb[0]) int_uov_v[7:0]  <= wdata[7:0];
          if (wstrb[1]) int_uov_v[10:8] <= wdata[10:8];
        end
        ADDR_UOV_N: begin
          if (wstrb[0]) int_uov_n[7:0]  <= wdata[7:0];
          if (wstrb[1]) int_uov_n[10:8] <= wdata[10:8];
        end
        ADDR_UOV_N_PADDED: begin
          if (wstrb[0]) int_uov_n_padded[7:0]  <= wdata[7:0];
          if (wstrb[1]) int_uov_n_padded[10:8] <= wdata[10:8];
        end
        ADDR_P1_BYTES:  int_p1_bytes     <= wr_word(int_p1_bytes);
        ADDR_NR_SLICES: if (wstrb[0]) int_nr_slices <= wdata[2:0];

        [ADDR_SEED_PK      : ADDR_SEED_PK      + APERTURE]:
          int_seed_pk     [32*wword +: 32] <= wr_word(int_seed_pk     [32*wword +: 32]);
        [ADDR_SEED_BL      : ADDR_SEED_BL      + APERTURE]:
          int_seed_bl     [32*wword +: 32] <= wr_word(int_seed_bl     [32*wword +: 32]);
        [ADDR_BRAM_WR_DATA : ADDR_BRAM_WR_DATA + APERTURE]:
          int_bram_wr_data[32*wword +: 32] <= wr_word(int_bram_wr_data[32*wword +: 32]);
        [ADDR_STREAM_TDATA : ADDR_STREAM_TDATA + APERTURE]:
          int_stream_tdata[32*wword +: 32] <= wr_word(int_stream_tdata[32*wword +: 32]);

        ADDR_BRAM_RW_ADDR: int_bram_rw_addr <= wr_word(int_bram_rw_addr);
        default: ;
      endcase
    end
  end

  // ---------------------------------------------------------------------------
  // Read data
  // ---------------------------------------------------------------------------
  logic [31:0] rdata_mux;

  always_comb begin
    rdata_mux = 32'd0;
    case (araddr) inside
      ADDR_CTRL: rdata_mux = {24'd0, int_auto_restart, 3'd0,
                              int_ap_ready, int_ap_idle, int_ap_done, int_ap_start};
      ADDR_GIE:  rdata_mux = {31'd0, int_gie};
      ADDR_IER:  rdata_mux = {30'd0, int_ier};
      ADDR_ISR:  rdata_mux = {30'd0, int_isr};

      ADDR_UOV_CTRL:     rdata_mux = {25'd0, stream_tready, int_stream_tvalid, int_bram_wen,
                                      int_do_verif, int_do_blinding, int_trng_en, int_uov_rst};
      ADDR_MSG_LEN:      rdata_mux = {16'd0, int_msg_len};
      ADDR_UOV_M:        rdata_mux = {21'd0, int_uov_m};
      ADDR_UOV_V:        rdata_mux = {21'd0, int_uov_v};
      ADDR_UOV_N:        rdata_mux = {21'd0, int_uov_n};
      ADDR_UOV_N_PADDED: rdata_mux = {21'd0, int_uov_n_padded};
      ADDR_P1_BYTES:     rdata_mux = int_p1_bytes;
      ADDR_NR_SLICES:    rdata_mux = {29'd0, int_nr_slices};

      [ADDR_SEED_PK      : ADDR_SEED_PK      + APERTURE]: rdata_mux = int_seed_pk     [32*rword +: 32];
      [ADDR_SEED_BL      : ADDR_SEED_BL      + APERTURE]: rdata_mux = int_seed_bl     [32*rword +: 32];
      [ADDR_BRAM_RD_DATA : ADDR_BRAM_RD_DATA + APERTURE]: rdata_mux = bram_rd_data    [32*rword +: 32];
      [ADDR_BRAM_WR_DATA : ADDR_BRAM_WR_DATA + APERTURE]: rdata_mux = int_bram_wr_data[32*rword +: 32];
      [ADDR_STREAM_TDATA : ADDR_STREAM_TDATA + APERTURE]: rdata_mux = int_stream_tdata[32*rword +: 32];

      ADDR_BRAM_RW_ADDR: rdata_mux = int_bram_rw_addr;
      default: rdata_mux = 32'd0;
    endcase
  end

  logic [31:0] rdata_r;
  always_ff @(posedge aclk) begin
    if (!aresetn)   rdata_r <= 32'd0;
    else if (ar_hs) rdata_r <= rdata_mux;
  end
  assign rdata = rdata_r;

endmodule

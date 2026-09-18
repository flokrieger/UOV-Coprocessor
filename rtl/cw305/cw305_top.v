/////////////////////////////////////////////////////////////////////
// Part of the UOV-Coprocessor artifact:
// https://github.com/flokrieger/UOV-Coprocessor
/////////////////////////////////////////////////////////////////////

/* 
ChipWhisperer Artix Target - Example of connections between example registers
and rest of system.

Copyright (c) 2016-2020, NewAE Technology Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted without restriction. Note that modules within
the project may have additional restrictions, please carefully inspect
additional licenses.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of NewAE Technology Inc.
*/

`timescale 1ns / 1ps
`default_nettype none 

module cw305_top #(
    parameter pBYTECNT_SIZE = 7,
    parameter pADDR_WIDTH = 21,
    parameter pPT_WIDTH = 128,
    parameter pCT_WIDTH = 128,
    parameter pKEY_WIDTH = 128,
   parameter BRAM_ADDR_WIDTH = 32,
   parameter BRAM_DATA_WIDTH = 128
)(
    // USB Interface
    input wire                          usb_clk,        // Clock
`ifdef SS2_WRAPPER
    output wire                         usb_clk_buf,    // if needed by parent module
    input  wire [7:0]                   usb_data,
    output wire [7:0]                   usb_dout,
`else
    inout wire [7:0]                    usb_data,       // Data for write/read
`endif
    input wire [pADDR_WIDTH-1:0]        usb_addr,       // Address
    input wire                          usb_rdn,        // !RD, low when addr valid for read
    input wire                          usb_wrn,        // !WR, low when data+addr valid for write
    input wire                          usb_cen,        // !CE, active low chip enable
    input wire                          usb_trigger,    // High when trigger requested

    // Buttons/LEDs on Board
    input wire                          j16_sel,        // DIP switch J16
    input wire                          k16_sel,        // DIP switch K16
    input wire                          k15_sel,        // DIP switch K15
    input wire                          l14_sel,        // DIP Switch L14
    input wire                          pushbutton,     // Pushbutton SW4, connected to R1, used here as reset
    output wire                         led1,           // red LED
    output wire                         led2,           // green LED
    output wire                         led3,           // blue LED

    // PLL
    input wire                          pll_clk1,       //PLL Clock Channel #1
    //input wire                        pll_clk2,       //PLL Clock Channel #2 (unused in this example)

    // 20-Pin Connector Stuff
    output wire                         tio_trigger,
    output wire                         tio_clkout,
    input  wire                         tio_clkin

    // Block Interface to Crypto Core
`ifdef USE_BLOCK_INTERFACE
   ,output wire                         crypto_clk,
    output wire                         crypto_rst,
    output wire [pPT_WIDTH-1:0]         crypto_textout,
    output wire [pKEY_WIDTH-1:0]        crypto_keyout,
    input  wire [pCT_WIDTH-1:0]         crypto_cipherin,
    output wire                         crypto_start,
    input wire                          crypto_ready,
    input wire                          crypto_done,
    input wire                          crypto_busy,
    input wire                          crypto_idle
`endif
    );



    wire [pKEY_WIDTH-1:0] crypt_key;
    wire [pPT_WIDTH-1:0] crypt_textout;
    wire [pCT_WIDTH-1:0] crypt_cipherin;
    wire crypt_init;
    wire crypt_ready;
    wire crypt_start;
    wire crypt_done;
    wire crypt_busy;

    wire isout;
    wire [pADDR_WIDTH-pBYTECNT_SIZE-1:0] reg_address;
    wire [pBYTECNT_SIZE-1:0] reg_bytecnt;
    wire reg_addrvalid;
    wire [7:0] write_data;
    wire [7:0] read_data;
    wire reg_read;
    wire reg_write;
    wire [4:0] clk_settings;
    wire crypt_clk;    

    wire resetn = pushbutton;
    wire reset = !resetn;

`ifndef SS2_WRAPPER
    wire usb_clk_buf;
    wire [7:0] usb_dout;
    assign usb_data = isout? usb_dout : 8'bZ;
`endif

    // USB CLK Heartbeat
    reg [24:0] usb_timer_heartbeat;
    always @(posedge usb_clk_buf) usb_timer_heartbeat <= usb_timer_heartbeat +  25'd1;
    assign led1 = usb_timer_heartbeat[24];

    // CRYPT CLK Heartbeat
    reg [22:0] crypt_clk_heartbeat;
    always @(posedge crypt_clk) crypt_clk_heartbeat <= crypt_clk_heartbeat +  23'd1;
    assign led2 = crypt_clk_heartbeat[22];


    cw305_usb_reg_fe #(
       .pBYTECNT_SIZE           (pBYTECNT_SIZE),
       .pADDR_WIDTH             (pADDR_WIDTH)
    ) U_usb_reg_fe (
       .rst                     (reset),
       .usb_clk                 (usb_clk_buf), 
       .usb_din                 (usb_data), 
       .usb_dout                (usb_dout), 
       .usb_rdn                 (usb_rdn), 
       .usb_wrn                 (usb_wrn),
       .usb_cen                 (usb_cen),
       .usb_alen                (1'b0),                 // unused
       .usb_addr                (usb_addr),
       .usb_isout               (isout), 
       .reg_address             (reg_address), 
       .reg_bytecnt             (reg_bytecnt), 
       .reg_datao               (write_data), 
       .reg_datai               (read_data),
       .reg_read                (reg_read), 
       .reg_write               (reg_write), 
       .reg_addrvalid           (reg_addrvalid)
    );


    wire [BRAM_ADDR_WIDTH-1:0] bram_rw_addr;
    wire                       bram_wr_en;
    wire [BRAM_DATA_WIDTH-1:0] bram_rd_data, bram_wr_data;
    wire                       sw_rst;
    wire [127:0]               seed_pk;
    wire [127:0]               seed_bl;
    wire  [15:0]               msg_len_bytes;
    wire  [10:0]               uov_m;
    wire  [10:0]               uov_v;
    wire  [10:0]               uov_n;
    wire  [10:0]               uov_n_padded;
    wire  [31:0]               p1_bytes;
    wire  [2:0]                nr_slices;
    wire                       rng_en;
    wire                       trigger_select;
    wire                       do_blinding;
    wire                       do_verif;
    wire [BRAM_DATA_WIDTH-1:0] axis_p3key_tdata;
    wire                       axis_p3key_tvalid;
    wire                       axis_p3key_tready;
    reg axis_p3key_tvalid_special, axis_p3key_tvalid_dp;
    cw305_reg_aes #(
       .pBYTECNT_SIZE           (pBYTECNT_SIZE),
       .pADDR_WIDTH             (pADDR_WIDTH),
       .pPT_WIDTH               (pPT_WIDTH),
       .pCT_WIDTH               (pCT_WIDTH),
       .pKEY_WIDTH              (pKEY_WIDTH),
       .BRAM_ADDR_WIDTH         (BRAM_ADDR_WIDTH),
       .BRAM_DATA_WIDTH         (BRAM_DATA_WIDTH)
    ) U_reg_aes (
       .reset_i                 (reset),
       .crypto_clk              (crypt_clk),
       .usb_clk                 (usb_clk_buf), 
       .reg_address             (reg_address[pADDR_WIDTH-pBYTECNT_SIZE-1:0]), 
       .reg_bytecnt             (reg_bytecnt), 
       .read_data               (read_data), 
       .write_data              (write_data),
       .reg_read                (reg_read), 
       .reg_write               (reg_write), 
       .reg_addrvalid           (reg_addrvalid),

       .exttrigger_in           (usb_trigger),

       .I_textout               (128'b0),               // unused
       .I_cipherout             (crypt_cipherin),
       .I_ready                 (crypt_ready),
       .I_done                  (crypt_done),
       .I_busy                  (crypt_busy),

       .O_clksettings           (clk_settings),
       .O_user_led              (led3),
       .O_key                   (crypt_key),
       .O_textin                (crypt_textout),
       .O_cipherin              (),                     // unused
       .O_start                 (crypt_start),
       .O_sw_rst                (sw_rst),
       .O_seed_pk               (seed_pk),
       .O_seed_bl               (seed_bl),
       .O_msg_len               (msg_len_bytes),
       .O_uov_m                 (uov_m),
       .O_uov_v                 (uov_v),
       .O_uov_n                 (uov_n),
       .O_uov_n_padded          (uov_n_padded),
       .O_p1_bytes              (p1_bytes),
       .O_nr_slices             (nr_slices),
       .O_trng_en               (rng_en),
       .O_trigger_select        (trigger_select),
       .O_do_blinding           (do_blinding),
       .O_do_verif              (do_verif),
       .O_axis_p3key_tdata      (axis_p3key_tdata),
       .O_axis_p3key_tvalid     (axis_p3key_tvalid),
       .I_axis_p3key_tready     (~axis_p3key_tvalid_special),

       .O_bram_rw_addr          (bram_rw_addr),
       .O_bram_wr_en            (bram_wr_en),
       .I_bram_rd_data          (bram_rd_data),
       .O_bram_wr_data          (bram_wr_data)
    );


`ifdef ICE40
    assign usb_clk_buf = usb_clk;
    assign crypt_clk = usb_clk;
    assign tio_clkout = usb_clk;
`else
    clocks U_clocks (
       .usb_clk                 (usb_clk),
       .usb_clk_buf             (usb_clk_buf),
       .I_j16_sel               (j16_sel),
       .I_k16_sel               (k16_sel),
       .I_clock_reg             (clk_settings),
       .I_cw_clkin              (tio_clkin),
       .I_pll_clk1              (pll_clk1),
       .O_cw_clkout             (tio_clkout),
       .O_cryptoclk             (crypt_clk)
    );
`endif



  // Block interface is used by the IP Catalog. If you are using block-based
  // design define USE_BLOCK_INTERFACE.
`ifdef USE_BLOCK_INTERFACE
    assign crypto_clk = crypt_clk;
    assign crypto_rst = crypt_init;
    assign crypto_keyout = crypt_key;
    assign crypto_textout = crypt_textout;
    assign crypt_cipherin = crypto_cipherin;
    assign crypto_start = crypt_start;
    assign crypt_ready = crypto_ready;
    assign crypt_done = crypto_done;
    assign crypt_busy = crypto_busy;
    assign tio_trigger = ~crypto_idle;
`endif

  // ============ START CRYPTO MODULE CONNECTIONS ===================
  
  assign crypt_cipherin = 128'd0;

  wire uov_start;
  wire uov_idle;
  wire uov_ready;
  wire uov_done;
  wire uov_rst;
  wire trigger_uov;

  assign crypt_ready = uov_ready;
  assign crypt_done = uov_done;
  assign crypt_busy = !uov_idle;
  assign tio_trigger = uov_idle;
  assign uov_rst = sw_rst;
  assign uov_start = crypt_start;

  always @(posedge crypt_clk) begin
    axis_p3key_tvalid_dp <= axis_p3key_tvalid;

    if(uov_rst)
      axis_p3key_tvalid_special <= 1'd0;
    else if(axis_p3key_tvalid_special && axis_p3key_tready)
      axis_p3key_tvalid_special <= 1'd0;
    else if(axis_p3key_tvalid_dp == 1'd0 && axis_p3key_tvalid == 1'd1)
      axis_p3key_tvalid_special <= 1'd1;
  end

  UovWrapper uov_wrapper_inst (
    .clk               ( crypt_clk                 ),
    .rst               ( uov_rst                   ),
    .start             ( uov_start                 ),
    .idle              ( uov_idle                  ),
    .ready             ( uov_ready                 ),
    .done              ( uov_done                  ),
    .msg_len_bytes     ( msg_len_bytes             ),
    .uov_m             ( uov_m                     ),
    .uov_v             ( uov_v                     ),
    .uov_n             ( uov_n                     ),
    .uov_n_padded      ( uov_n_padded              ),
    .p1_bytes          ( p1_bytes                  ),
    .nr_slices         ( nr_slices                 ),
    .rng_en            ( rng_en                    ),
    .seed_pk           ( seed_pk                   ),
    .seed_bl           ( seed_bl                   ),
    .do_verif          ( do_verif                  ),
    .ext_rw_addr       ( bram_rw_addr              ),
    .ext_wr_en         ( bram_wr_en                ),
    .ext_rd_data       ( bram_rd_data              ),
    .ext_wr_data       ( bram_wr_data              ),
    .trigger_uov       ( trigger_uov               ),
    .do_blinding       ( do_blinding               ),
    .axis_p3key_tdata  ( axis_p3key_tdata          ),
    .axis_p3key_tvalid ( axis_p3key_tvalid_special ),
    .axis_p3key_tready ( axis_p3key_tready         )
  );  

endmodule

`default_nettype wire


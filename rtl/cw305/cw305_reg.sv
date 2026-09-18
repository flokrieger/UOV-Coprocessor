/////////////////////////////////////////////////////////////////////
// Part of the UOV-Coprocessor artifact:
// https://github.com/flokrieger/UOV-Coprocessor
/////////////////////////////////////////////////////////////////////

/* 
ChipWhisperer Artix Target - Example of connections between example registers
and rest of system.

Copyright (c) 2020, NewAE Technology Inc.
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

`default_nettype none
`timescale 1ns / 1ps
`include "cw305_defines.v"

module cw305_reg_aes #(
   parameter pADDR_WIDTH = 21,
   parameter pBYTECNT_SIZE = 7,
   parameter pDONE_EDGE_SENSITIVE = 1,
   parameter pPT_WIDTH = 128,
   parameter pCT_WIDTH = 128,
   parameter pKEY_WIDTH = 128,
   parameter pCRYPT_TYPE = 2,
   parameter pCRYPT_REV = 5,
   parameter pIDENTIFY = 8'h2e,
   parameter BRAM_ADDR_WIDTH = 10,
   parameter BRAM_DATA_WIDTH = 64
)(

// Interface to cw305_usb_reg_fe:
   input  wire                                  usb_clk,
   input  wire                                  crypto_clk,
   input  wire                                  reset_i,
   input  wire [pADDR_WIDTH-pBYTECNT_SIZE-1:0]  reg_address,     // Address of register
   input  wire [pBYTECNT_SIZE-1:0]              reg_bytecnt,  // Current byte count
   output reg  [7:0]                            read_data,       //
   input  wire [7:0]                            write_data,      //
   input  wire                                  reg_read,        // Read flag. One clock cycle AFTER this flag is high
                                                                 // valid data must be present on the read_data bus
   input  wire                                  reg_write,       // Write flag. When high on rising edge valid data is
                                                                 // present on write_data
   input  wire                                  reg_addrvalid,   // Address valid flag

// from top:
   input  wire                                  exttrigger_in,

// control and status inputs:
   input  wire                                  I_ready,  /* Crypto core ready. Tie to '1' if not used. */
   input  wire                                  I_done,   /* Crypto done. Can be high for one crypto_clk cycle or longer. */
   input  wire                                  I_busy,   /* Crypto busy. */

// control and status outputs:
   output reg  [4:0]                            O_clksettings,
   output reg                                   O_user_led,
   output wire                                  O_start,   /* High for one crypto_clk cycle, indicates text ready. */
   output wire                                  O_sw_rst,   /* Active-high reset from software. */
   output wire [uov_pkg::SEED_PK_BITS-1:0]      O_seed_pk,
   output wire [uov_pkg::SEED_PK_BITS-1:0]      O_seed_bl,
   output wire [15:0]                           O_msg_len,
   output wire [10:0]                           O_uov_m,
   output wire [10:0]                           O_uov_v,
   output wire [10:0]                           O_uov_n,
   output wire [10:0]                           O_uov_n_padded,
   output wire [31:0]                           O_p1_bytes,
   output wire [2:0]                            O_nr_slices,
   output wire                                  O_trng_en,
   output wire                                  O_trigger_select,
   output wire                                  O_do_verif,
   output wire                                  O_do_blinding,
   output wire [BRAM_DATA_WIDTH-1:0]            O_axis_p3key_tdata,
   output wire                                  O_axis_p3key_tvalid,
   input  wire                                  I_axis_p3key_tready,

// register inputs:
   input  wire [pPT_WIDTH-1:0]                  I_textout,
   input  wire [pCT_WIDTH-1:0]                  I_cipherout,

   input  wire [BRAM_DATA_WIDTH-1:0]            I_bram_rd_data,

// register outputs:
   output wire [pKEY_WIDTH-1:0]                 O_key,
   output wire [pPT_WIDTH-1:0]                  O_textin,
   output wire [pCT_WIDTH-1:0]                  O_cipherin,

   output wire [BRAM_DATA_WIDTH-1:0]            O_bram_wr_data,
   output wire                                  O_bram_wr_en,
   output wire [BRAM_ADDR_WIDTH-1:0]            O_bram_rw_addr
);

   reg  [7:0]                   reg_read_data;
   reg  [pCT_WIDTH-1:0]         reg_crypt_cipherin;
   reg  [pKEY_WIDTH-1:0]        reg_crypt_key;
   reg  [pPT_WIDTH-1:0]         reg_crypt_textin;
   reg  [pPT_WIDTH-1:0]         reg_crypt_textout;
   reg  [pCT_WIDTH-1:0]         reg_crypt_cipherout;
   reg                          reg_crypt_go_pulse;
   wire                         reg_crypt_go_pulse_crypt;

   reg [BRAM_DATA_WIDTH-1:0]    reg_bram_rd_data;
   reg [BRAM_DATA_WIDTH-1:0]    reg_bram_wr_data;
   reg                          reg_bram_wr_en;
   reg [BRAM_ADDR_WIDTH-1:0]    reg_bram_rw_addr;
   
   reg                          reg_sw_rst;
   reg [uov_pkg::SEED_PK_BITS-1:0]                   reg_seed_pk;
   reg [uov_pkg::SEED_PK_BITS-1:0]                   reg_seed_bl;
   reg [15:0]                                        reg_msg_len;
   reg [15:0]                                        reg_uov_m;
   reg [15:0]                                        reg_uov_v;
   reg [15:0]                                        reg_uov_n;
   reg [15:0]                                        reg_uov_n_padded;
   reg [31:0]                                        reg_p1_bytes;
   reg [2:0]                                         reg_nr_slices;
   reg                                               reg_trng_en;
   reg                                               reg_trigger_select;
   reg                                               reg_do_verif;
   reg                                               reg_do_blinding;
   reg [BRAM_DATA_WIDTH-1:0]                          reg_axis_p3key_tdata;
   reg                                               reg_axis_p3key_tvalid;
   reg                                               axis_p3key_tready_usb;

   reg                          busy_usb;
   reg                          done_r;
   wire                         done_pulse;
   wire                         crypt_go_pulse;
   reg                          go_r;
   reg                          go;
   wire [31:0]                  buildtime;

   (* ASYNC_REG = "TRUE" *) reg  [pKEY_WIDTH-1:0] reg_crypt_key_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [pPT_WIDTH-1:0] reg_crypt_textin_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [pPT_WIDTH-1:0] reg_crypt_textout_usb;
   (* ASYNC_REG = "TRUE" *) reg  [pCT_WIDTH-1:0] reg_crypt_cipherout_usb;
   (* ASYNC_REG = "TRUE" *) reg  [1:0] go_pipe;
   (* ASYNC_REG = "TRUE" *) reg  [1:0] busy_pipe;

   (* ASYNC_REG = "TRUE" *) reg  [BRAM_DATA_WIDTH-1:0] reg_bram_rd_data_usb;
   (* ASYNC_REG = "TRUE" *) reg  [BRAM_DATA_WIDTH-1:0] reg_bram_wr_data_crypt;
   (* ASYNC_REG = "TRUE" *) reg                        reg_bram_wr_en_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [BRAM_ADDR_WIDTH-1:0] reg_bram_rw_addr_crypt;

   (* ASYNC_REG = "TRUE" *) reg                        reg_sw_rst_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [uov_pkg::SEED_PK_BITS-1:0]                reg_seed_pk_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [uov_pkg::SEED_PK_BITS-1:0]                reg_seed_bl_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [15:0]                                     reg_msg_len_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [15:0]                                     reg_uov_m_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [15:0]                                     reg_uov_v_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [15:0]                                     reg_uov_n_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [15:0]                                     reg_uov_n_padded_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [31:0]                                     reg_p1_bytes_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [2:0]                                      reg_nr_slices_crypt;
   (* ASYNC_REG = "TRUE" *) reg                                             reg_trng_en_crypt;
   (* ASYNC_REG = "TRUE" *) reg                                             reg_trigger_select_crypt;
   (* ASYNC_REG = "TRUE" *) reg                                             reg_do_verif_crypt;
   (* ASYNC_REG = "TRUE" *) reg                                             reg_do_blinding_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [BRAM_DATA_WIDTH-1:0]                       reg_axis_p3key_tdata_crypt;
   (* ASYNC_REG = "TRUE" *) reg                                             reg_axis_p3key_tvalid_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [1:0]                                       axis_p3key_tready_pipe;


   always @(posedge crypto_clk)
       done_r <= I_done & pDONE_EDGE_SENSITIVE;
   assign done_pulse = I_done & ~done_r;

   always @(posedge crypto_clk) begin
       if (done_pulse) begin
           reg_crypt_cipherout <= I_cipherout;
           reg_crypt_textout   <= I_textout;
       end

       reg_bram_rd_data <= I_bram_rd_data;
   end

`ifdef ICE40
   // iCE40 target has just one clock domain, so there's no CDC to worry
   // about; it also can't afford to spare the extra registers:
   always @(*) begin
       reg_crypt_cipherout_usb = reg_crypt_cipherout;
       reg_crypt_textout_usb   = reg_crypt_textout;
       reg_crypt_key_crypt     = reg_crypt_key;
       reg_crypt_textin_crypt  = reg_crypt_textin;
   end
`else
   always @(posedge usb_clk) begin
       reg_crypt_cipherout_usb <= reg_crypt_cipherout;
       reg_crypt_textout_usb   <= reg_crypt_textout;
       reg_bram_rd_data_usb    <= reg_bram_rd_data;
   end
   always @(posedge crypto_clk) begin
       reg_crypt_key_crypt <= reg_crypt_key;
       reg_crypt_textin_crypt <= reg_crypt_textin;
       reg_bram_wr_data_crypt <= reg_bram_wr_data;
       reg_bram_wr_en_crypt   <= reg_bram_wr_en;
       reg_bram_rw_addr_crypt <= reg_bram_rw_addr;
       reg_sw_rst_crypt       <= reg_sw_rst;
       reg_seed_pk_crypt      <= reg_seed_pk;
       reg_seed_bl_crypt      <= reg_seed_bl;
       reg_msg_len_crypt      <= reg_msg_len;
       reg_uov_m_crypt        <= reg_uov_m;
       reg_uov_v_crypt        <= reg_uov_v;
       reg_uov_n_crypt        <= reg_uov_n;
       reg_uov_n_padded_crypt <= reg_uov_n_padded;
       reg_p1_bytes_crypt     <= reg_p1_bytes;
       reg_nr_slices_crypt    <= reg_nr_slices;
       reg_trng_en_crypt      <= reg_trng_en;
       reg_trigger_select_crypt <= reg_trigger_select;
       reg_do_verif_crypt     <= reg_do_verif;
       reg_do_blinding_crypt  <= reg_do_blinding;
       reg_axis_p3key_tdata_crypt  <= reg_axis_p3key_tdata;
       reg_axis_p3key_tvalid_crypt <= reg_axis_p3key_tvalid;
   end
`endif

   assign O_textin = reg_crypt_textin_crypt;
   assign O_key = reg_crypt_key_crypt;
   assign O_start = crypt_go_pulse || reg_crypt_go_pulse_crypt;

   assign O_bram_wr_data = reg_bram_wr_data_crypt;
   assign O_bram_wr_en   = reg_bram_wr_en_crypt;
   assign O_bram_rw_addr = reg_bram_rw_addr_crypt;

   assign O_sw_rst       = reg_sw_rst_crypt;
   assign O_seed_pk      = reg_seed_pk_crypt;
   assign O_seed_bl      = reg_seed_bl_crypt;
   assign O_msg_len      = reg_msg_len_crypt;
   assign O_uov_m        = reg_uov_m_crypt[10:0];
   assign O_uov_v        = reg_uov_v_crypt[10:0];
   assign O_uov_n        = reg_uov_n_crypt[10:0];
   assign O_uov_n_padded = reg_uov_n_padded_crypt[10:0];
   assign O_p1_bytes     = reg_p1_bytes_crypt;
   assign O_nr_slices    = reg_nr_slices_crypt;
   assign O_trng_en      = reg_trng_en_crypt;
   assign O_trigger_select = reg_trigger_select_crypt;
   assign O_do_verif     = reg_do_verif_crypt;
   assign O_do_blinding  = reg_do_blinding_crypt;
   assign O_axis_p3key_tdata  = reg_axis_p3key_tdata_crypt;
   assign O_axis_p3key_tvalid = reg_axis_p3key_tvalid_crypt;

   //////////////////////////////////
   // read logic:
   //////////////////////////////////

   always @(*) begin
      if (reg_addrvalid && reg_read) begin
         case (reg_address)
            `REG_CLKSETTINGS:           reg_read_data = O_clksettings;
            `REG_USER_LED:              reg_read_data = O_user_led;
            `REG_CRYPT_TYPE:            reg_read_data = pCRYPT_TYPE;
            `REG_CRYPT_REV:             reg_read_data = pCRYPT_REV;
            `REG_IDENTIFY:              reg_read_data = pIDENTIFY;
            `REG_CRYPT_GO:              reg_read_data = busy_usb;
            `REG_CRYPT_KEY:             reg_read_data = reg_crypt_key[reg_bytecnt*8 +: 8];
            `REG_CRYPT_TEXTIN:          reg_read_data = reg_crypt_textin[reg_bytecnt*8 +: 8];
            `REG_CRYPT_CIPHERIN:        reg_read_data = reg_crypt_cipherin[reg_bytecnt*8 +: 8];
            `REG_CRYPT_TEXTOUT:         reg_read_data = reg_crypt_textout_usb[reg_bytecnt*8 +: 8];
            `REG_CRYPT_CIPHEROUT:       reg_read_data = reg_crypt_cipherout_usb[reg_bytecnt*8 +: 8];
            `REG_BUILDTIME:             reg_read_data = buildtime[reg_bytecnt*8 +: 8];
            `REG_BRAM_RD_DATA:          reg_read_data = reg_bram_rd_data_usb[reg_bytecnt*8 +: 8];
            `REG_RST:                   reg_read_data = {7'd0, reg_sw_rst};
            `REG_DATA_IN_TREADY:        reg_read_data = {7'd0, axis_p3key_tready_usb};
            default:                    reg_read_data = 0;
         endcase
      end
      else
         reg_read_data = 0;
   end

   // Register output read data to ease timing. If you need read data one clock
   // cycle earlier, simply remove this stage:
   always @(posedge usb_clk)
      read_data <= reg_read_data;

   //////////////////////////////////
   // write logic (USB clock domain):
   //////////////////////////////////
   always @(posedge usb_clk) begin
      if (reset_i) begin
         O_clksettings <= 0;
         O_user_led <= 0;
         reg_crypt_go_pulse <= 1'b0;
      end

      else begin
         if (reg_addrvalid && reg_write) begin
            case (reg_address)
               `REG_CLKSETTINGS:        O_clksettings <= write_data;
               `REG_USER_LED:           O_user_led <= write_data;
               `REG_CRYPT_TEXTIN:       reg_crypt_textin[reg_bytecnt*8 +: 8] <= write_data;
               `REG_CRYPT_CIPHERIN:     reg_crypt_cipherin[reg_bytecnt*8 +: 8] <= write_data;
               `REG_CRYPT_KEY:          reg_crypt_key[reg_bytecnt*8 +: 8] <= write_data;
               `REG_BRAM_WR_DATA:       reg_bram_wr_data[reg_bytecnt*8 +: 8] <= write_data;
               `REG_BRAM_WR_EN:         reg_bram_wr_en <= reg_bytecnt == 'd0 ? write_data[0] : reg_bram_wr_en;
               `REG_BRAM_RW_ADDR:       reg_bram_rw_addr[reg_bytecnt*8 +: 8] <= write_data;
               `REG_RST:                reg_sw_rst <= reg_bytecnt == 'd0 ? write_data[0] : reg_sw_rst;
               `REG_SEED_PK:            reg_seed_pk[reg_bytecnt*8 +: 8] <= write_data;
               `REG_SEED_BL:            reg_seed_bl[reg_bytecnt*8 +: 8] <= write_data;
               `REG_MSG_LEN:            reg_msg_len[reg_bytecnt*8 +: 8] <= write_data;
               `REG_UOV_M:              reg_uov_m[reg_bytecnt*8 +: 8] <= write_data;
               `REG_UOV_V:              reg_uov_v[reg_bytecnt*8 +: 8] <= write_data;
               `REG_UOV_N:              reg_uov_n[reg_bytecnt*8 +: 8] <= write_data;
               `REG_UOV_N_PADDED:       reg_uov_n_padded[reg_bytecnt*8 +: 8] <= write_data;
               `REG_P1_BYTES:           reg_p1_bytes[reg_bytecnt*8 +: 8] <= write_data;
               `REG_NR_SLICES:          reg_nr_slices <= (reg_bytecnt == 'd0) ? write_data[2:0] : reg_nr_slices;
               `REG_TRNG_EN:            reg_trng_en   <= (reg_bytecnt == 'd0) ? write_data[0]   : reg_trng_en;
               `REG_TRIGGER_SELECT:     reg_trigger_select <= (reg_bytecnt == 'd0) ? write_data[0] : reg_trigger_select;
               `REG_DO_VERIF:           {reg_do_blinding, reg_do_verif}  <= (reg_bytecnt == 'd0) ? write_data[1:0]   : {reg_do_blinding,reg_do_verif};
               `REG_DATA_IN_TDATA:      reg_axis_p3key_tdata[reg_bytecnt*8 +: 8] <= write_data;
               `REG_DATA_IN_TVALID:     reg_axis_p3key_tvalid <= (reg_bytecnt == 'd0) ? write_data[0] : reg_axis_p3key_tvalid;
            endcase
         end
         // REG_CRYPT_GO register is special: writing it creates a pulse. Reading it gives you the "busy" status.
         if ( (reg_addrvalid && reg_write && (reg_address == `REG_CRYPT_GO)) )
            reg_crypt_go_pulse <= 1'b1;
         else
            reg_crypt_go_pulse <= 1'b0;

      end
   end

   always @(posedge crypto_clk) begin
      {go_r, go, go_pipe} <= {go, go_pipe, exttrigger_in};
   end
   assign crypt_go_pulse = go & !go_r;

    /*
   cdc_pulse U_go_pulse (
      .reset_i       (reset_i),
      .src_clk       (usb_clk),
      .src_pulse     (reg_crypt_go_pulse),
      .dst_clk       (crypto_clk),
      .dst_pulse     (reg_crypt_go_pulse_crypt)
   );
   */
   
   xpm_cdc_pulse #(
      .DEST_SYNC_FF(4),   // DECIMAL; range: 2-10
      .INIT_SYNC_FF(1),   // DECIMAL; 0=disable simulation init values, 1=enable simulation init values
      .REG_OUTPUT(1),     // DECIMAL; 0=disable registered output, 1=enable registered output
      .RST_USED(0),       // DECIMAL; 0=no reset, 1=implement reset
      .SIM_ASSERT_CHK(1)  // DECIMAL; 0=disable simulation messages, 1=enable simulation messages
   ) U_go_pulse (
      .dest_pulse(reg_crypt_go_pulse_crypt), // 1-bit output: Outputs a pulse the size of one dest_clk period when a pulse
                               // transfer is correctly initiated on src_pulse input. This output is
                               // combinatorial unless REG_OUTPUT is set to 1.

      .dest_clk(crypto_clk),     // 1-bit input: Destination clock.
      .dest_rst(1'd0),     // 1-bit input: optional; required when RST_USED = 1
      .src_clk(usb_clk),       // 1-bit input: Source clock.
      .src_pulse(reg_crypt_go_pulse),   // 1-bit input: Rising edge of this signal initiates a pulse transfer to the
                               // destination clock domain. The minimum gap between each pulse transfer must be
                               // at the minimum 2*(larger(src_clk period, dest_clk period)). This is measured
                               // between the falling edge of a src_pulse to the rising edge of the next
                               // src_pulse. This minimum gap will guarantee that each rising edge of src_pulse
                               // will generate a pulse the size of one dest_clk period in the destination
                               // clock domain. When RST_USED = 1, pulse transfers will not be guaranteed while
                               // src_rst and/or dest_rst are asserted.

      .src_rst(1'd0)        // 1-bit input: optional; required when RST_USED = 1
   );

`ifdef ICE40
    always @(*) busy_usb = I_busy;
    always @(*) axis_p3key_tready_usb = I_axis_p3key_tready;
`else
   always @(posedge usb_clk)
      {busy_usb, busy_pipe} <= {busy_pipe, I_busy};
   always @(posedge usb_clk)
      {axis_p3key_tready_usb, axis_p3key_tready_pipe} <= {axis_p3key_tready_pipe, I_axis_p3key_tready};
`endif


   `ifdef ILA_REG
       ila_0 U_reg_ila (
	.clk            (usb_clk),                      // input wire clk
	.probe0         (reg_address[7:0]),             // input wire [7:0]  probe0  
	.probe1         (reg_bytecnt),                  // input wire [6:0]  probe1 
	.probe2         (read_data),                    // input wire [7:0]  probe2 
	.probe3         (write_data),                   // input wire [7:0]  probe3 
	.probe4         (reg_read),                     // input wire [0:0]  probe4 
	.probe5         (reg_write),                    // input wire [0:0]  probe5 
	.probe6         (reg_addrvalid),                // input wire [0:0]  probe6 
	.probe7         (reg_read_data),                // input wire [7:0]  probe7 
	.probe8         (exttrigger_in),                // input wire [0:0]  probe8 
	.probe9         (1'b0),                         // input wire [0:0]  probe9
	.probe10        (reg_crypt_go_pulse)            // input wire [0:0]  probe10
       );
   `endif

   `ifdef ILA_CRYPTO
       ila_1 U_reg_aes (
	.clk            (crypto_clk),                   // input wire clk
	.probe0         (O_start),                      // input wire [0:0]  probe0  
	.probe1         (I_done),                       // input wire [0:0]  probe1 
	.probe2         (I_cipherout[7:0]),             // input wire [7:0]  probe2 
	.probe3         (O_textin[7:0]),                // input wire [7:0]  probe3 
	.probe4         (done_pulse)                    // input wire [0:0]  probe4 
       );
   `endif

`ifdef ICE40
   // dynamically generated by build process:
   `include "timestamp.v"
`else
   `ifndef __ICARUS__
      USR_ACCESSE2 U_buildtime (
         .CFGCLK(),
         .DATA(buildtime),
         .DATAVALID()
      );
   `else
      assign buildtime = 0;
   `endif
`endif


endmodule

`default_nettype wire

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
// Testbench for the UOV co-processor. Runs signing with and without oil
// space blinding as well as verification of valid and invalid signatures for
// all security levels. Compares the results against the reference data in
// uov_ref/data/
//
/////////////////////////////////////////////////////////////////////

module uov_wrapper_tb();
  import uov_pkg::*;

  // Path to reference data files
  localparam string DATA_DIR = "../../../../../../uov_ref/data/";
  int errors = 0;

  logic clk = 0;
  logic rst = 1;
  logic start = 0;
  always #5 clk = ~clk;

  logic ready;
  logic done;
  logic [AES_BITS-1:0]             seed_pk_val     = '0;
  logic [AES_BITS-1:0]             seed_bl_val     = '0;
  logic [BRAM_AWIDTH_EXT_BITS-1:0] ext_rw_addr_val = '0;
  logic                            ext_wr_en_val   = '0;
  logic [BRAM_DWIDTH_BITS-1:0]     ext_wr_data_val = '0;
  logic [BRAM_DWIDTH_BITS-1:0]     ext_rd_data_val;

  // DUT instance and wiring:
  logic do_verif, do_blinding;
  logic [15:0] msg_len_bytes = 16'd0;
  logic [2:0] sec_lvl;
  logic [10:0] uov_m;
  logic [10:0] uov_v;
  logic [10:0] uov_n;
  logic [10:0] uov_n_padded;
  logic [31:0] p1_bytes;
  logic [2:0]  nr_slices;
  logic [BRAM_DWIDTH_BITS-1:0] axis_p3key_tdata;
  logic axis_p3key_tvalid;
  logic axis_p3key_tready;
  UovWrapper dut (
    .clk               ( clk              ),
    .rst               ( rst              ),
    .start             ( start            ),
    .ready             ( ready            ),
    .done              ( done             ),

    .seed_pk           ( seed_pk_val      ),
    .seed_bl           ( seed_bl_val      ),
    .msg_len_bytes     ( msg_len_bytes    ),
    .uov_m             ( uov_m            ),
    .uov_v             ( uov_v            ),
    .uov_n             ( uov_n            ),
    .uov_n_padded      ( uov_n_padded     ),
    .p1_bytes          ( p1_bytes         ),
    .nr_slices         ( nr_slices        ),
    .rng_en            ( 1'd1             ),
    .do_verif          ( do_verif         ),

    .axis_p3key_tdata  (axis_p3key_tdata  ),
    .axis_p3key_tvalid (axis_p3key_tvalid ),
    .axis_p3key_tready (axis_p3key_tready ),

    .ext_rw_addr       ( ext_rw_addr_val  ),
    .ext_wr_en         ( ext_wr_en_val    ),
    .ext_rd_data       ( ext_rd_data_val  ),
    .ext_wr_data       ( ext_wr_data_val  ),
    .trigger_uov       (                  ),
    .do_blinding       ( do_blinding      )
  );

  // Map the 3-bit security level to its reference-file suffix (e.g. "uov-Ip").
  function automatic string lvl_suffix(input logic [2:0] sec_lvl);
    case (sec_lvl)
      UOV_LVL_Ip:  return "uov-Ip";
      UOV_LVL_III: return "uov-III";
      UOV_LVL_V:   return "uov-V";
      UOV_LVL_TOY: return "uov-toy";
      default:     return "uov-V";
    endcase
  endfunction

  // Per-level UOV dimensions (runtime, selected by the 3-bit sec_lvl)
  function automatic int lvl_m(input logic [2:0] sec_lvl);
    case (sec_lvl)
      UOV_LVL_Ip:  return UOV_LVL_Ip_M;
      UOV_LVL_III: return UOV_LVL_III_M;
      UOV_LVL_V:   return UOV_LVL_V_M;
      UOV_LVL_TOY: return UOV_LVL_TOY_M;
      default:     return UOV_LVL_V_M;
    endcase
  endfunction

  function automatic int lvl_v(input logic [2:0] sec_lvl);
    case (sec_lvl)
      UOV_LVL_Ip:  return UOV_LVL_Ip_V;
      UOV_LVL_III: return UOV_LVL_III_V;
      UOV_LVL_V:   return UOV_LVL_V_V;
      UOV_LVL_TOY: return UOV_LVL_TOY_V;
      default:     return UOV_LVL_V_V;
    endcase
  endfunction

  function automatic int lvl_n(input logic [2:0] sec_lvl);
    case (sec_lvl)
      UOV_LVL_Ip:  return UOV_LVL_Ip_N;
      UOV_LVL_III: return UOV_LVL_III_N;
      UOV_LVL_V:   return UOV_LVL_V_N;
      UOV_LVL_TOY: return UOV_LVL_TOY_N;
      default:     return UOV_LVL_V_N;
    endcase
  endfunction

  function automatic int lvl_n_padded(input logic [2:0] sec_lvl);
    case (sec_lvl)
      UOV_LVL_Ip:  return UOV_LVL_Ip_N_PADDED;
      UOV_LVL_III: return UOV_LVL_III_N_PADDED;
      UOV_LVL_V:   return UOV_LVL_V_N_PADDED;
      UOV_LVL_TOY: return UOV_LVL_TOY_N_PADDED;
      default:     return UOV_LVL_V_N_PADDED;
    endcase
  endfunction

  assign uov_m        = lvl_m(sec_lvl);
  assign uov_v        = lvl_v(sec_lvl);
  assign uov_n        = lvl_n(sec_lvl);
  assign uov_n_padded = lvl_n_padded(sec_lvl);
  assign p1_bytes     = lvl_m(sec_lvl) * lvl_v(sec_lvl) * (lvl_v(sec_lvl) + 1) / 2;
  assign nr_slices    = (lvl_m(sec_lvl) + W_FE - 1) / W_FE;


  // ===================== Signing Helpers ==========================

  // Reads the seed for the public key from file:
  task automatic load_seed_pk(input logic [2:0] sec_lvl);
    int fd, status;
    logic [7:0] b;
    string path;
    path = {DATA_DIR, "seed_pk_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    for (int i = 0; i < UOV_SEED_PK_BYTES; i++) begin
      status = $fscanf(fd, " %h", b);
      seed_pk_val[8*i +: 8] = b;
    end
    $fclose(fd);
    $display("uov_wrapper_tb: seed_pk loaded from %s: %032h", path, seed_pk_val);
  endtask

  // Reads the seed for blinding from file:
  task automatic load_seed_bl(input logic [2:0] sec_lvl);
    int fd, status;
    logic [7:0] b;
    string path;
    path = {DATA_DIR, "seed_bl_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    for (int i = 0; i < UOV_SEED_PK_BYTES; i++) begin
      status = $fscanf(fd, " %h", b);
      seed_bl_val[8*i +: 8] = b;
    end
    $fclose(fd);
    $display("uov_wrapper_tb: seed_bl loaded from %s: %032h", path, seed_bl_val);
  endtask

  // Reads the BRAM_O content (i.e. Ob) from the file into the BRAM
  task automatic load_bram_O(input logic [2:0] sec_lvl);
    field_t O_ref [0:UOV_LVL_V_N-1][0:UOV_LVL_V_M-1];
    int fd, status;
    int sage_col, sage_row;
    logic [7:0] fval;
    word_t packed_word;
    int w, i, flat, col_idx, row_idx;
    int uov_m, uov_n, uov_n_padded;
    string path;

    uov_m        = lvl_m(sec_lvl);
    uov_n        = lvl_n(sec_lvl);
    uov_n_padded = lvl_n_padded(sec_lvl);

    for (int r = 0; r < UOV_LVL_V_N; r++)
      for (int c = 0; c < UOV_LVL_V_M; c++)
        O_ref[r][c] = '0;

    path = {DATA_DIR, "O_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    while ($fscanf(fd, " %d %d %h", sage_col, sage_row, fval) == 3)
      if (sage_row < uov_n && sage_col < uov_m)
        O_ref[sage_row][sage_col] = fval;
    $fclose(fd);

    for (w = 0; w < BRAM_O_DEPTH; w++) begin
      packed_word = '0;
      for (i = 0; i < W_FE; i++) begin
        flat    = w * W_FE + i;
        col_idx = flat / uov_n_padded;
        row_idx = flat % uov_n_padded;
        if (row_idx < uov_n && col_idx < uov_m)
          packed_word[FE_BITS*i +: FE_BITS] = O_ref[row_idx][col_idx];
      end
      ext_rw_addr_val = {3'(BRAM_O_SEL), 18'd0, addr_t'(w)};
      ext_wr_data_val = packed_word;
      ext_wr_en_val   = 1'b1;
      @(posedge clk);
    end
    ext_wr_en_val = 1'b0;
    $display("uov_wrapper_tb: bram_O loaded from %s (%0d words)", path, BRAM_O_DEPTH);
  endtask

  // Reads the BRAM_ty content (i.e. t) from the file into the BRAM
  task automatic load_bram_ty(input logic [2:0] sec_lvl);
    field_t t_ref [0:UOV_LVL_V_M-1];
    int fd, status;
    logic [7:0] fval;
    word_t packed_word;
    int w, i, flat;
    int uov_m;
    string path;

    uov_m = lvl_m(sec_lvl);

    for (int k = 0; k < UOV_LVL_V_M; k++)
      t_ref[k] = '0;

    path = {DATA_DIR, "t_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    for (int k = 0; k < uov_m; k++) begin
      status = $fscanf(fd, " %h", fval);
      t_ref[k] = fval;
    end
    $fclose(fd);

    for (w = 0; w < BRAM_ty_DEPTH; w++) begin
      packed_word = '0;
      for (i = 0; i < W_FE; i++) begin
        flat = w * W_FE + i;
        if (flat < uov_m)
          packed_word[FE_BITS*i +: FE_BITS] = t_ref[flat];
      end
      ext_rw_addr_val = {3'(BRAM_ty_SEL), 18'd0, addr_t'(w)};
      ext_wr_data_val = packed_word;
      ext_wr_en_val   = 1'b1;
      @(posedge clk);
    end
    ext_wr_en_val = 1'b0;
    $display("uov_wrapper_tb: bram_ty loaded from %s (%0d words)", path, BRAM_ty_DEPTH);
  endtask

  // Loads the Keccak hash input (i.e. msg || salt || seed_sk) from the file into the BRAM_vs
  task automatic load_hash_input(input logic [2:0] sec_lvl, output int msg_len);
    logic [7:0] in_bytes [0:BRAM_vs_DEPTH*W_FE-1];
    int fd, nbytes;
    logic [7:0] fval;
    word_t packed_word;
    int w, i, flat;
    string path;

    for (int k = 0; k < BRAM_vs_DEPTH*W_FE; k++)
      in_bytes[k] = '0;

    path = {DATA_DIR, "hash_in_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    nbytes = 0;
    while ($fscanf(fd, " %h", fval) == 1) begin
      if (nbytes < BRAM_vs_DEPTH*W_FE)
        in_bytes[nbytes] = fval;
      nbytes++;
    end
    $fclose(fd);

    if (nbytes > (BRAM_vs_DEPTH/2)*W_FE)
      $display("uov_wrapper_tb: WARNING hash input %0d bytes exceeds bram_vs upper-half capacity %0d",
               nbytes, (BRAM_vs_DEPTH/2)*W_FE);

    msg_len = nbytes - UOV_SALT_BYTES - UOV_SEED_SK_BYTES;

    for (w = 0; w < BRAM_vs_DEPTH/2; w++) begin
      packed_word = '0;
      for (i = 0; i < W_FE; i++) begin
        flat = w * W_FE + i;
        if (flat < nbytes)
          packed_word[FE_BITS*i +: FE_BITS] = in_bytes[flat];
      end
      ext_rw_addr_val = {3'(BRAM_vs_SEL), 18'd0, addr_t'(w + BRAM_vs_DEPTH/2)};
      ext_wr_data_val = packed_word;
      ext_wr_en_val   = 1'b1;
      @(posedge clk);
    end
    ext_wr_en_val = 1'b0;
    $display("uov_wrapper_tb: hash input loaded from %s (%0d bytes, msg_len=%0d)", path, nbytes, msg_len);
  endtask

  // Reads the BRAM_O content (i.e. Ob) from the BRAM and checks the correctness against the reference file
  task automatic check_bram_O(input logic [2:0] sec_lvl, input logic enable_blinding);
    string ref_name;
    field_t Ob_ref    [0:UOV_LVL_V_N-1][0:UOV_LVL_V_M-1];
    word_t  bram_O_rd [0:BRAM_O_DEPTH-1];
    int fd;
    int sage_col, sage_row;
    logic [7:0] fval;
    field_t got, exp;
    int mismatches, row, col, flat, word_addr, lane, w;
    int uov_m, uov_n, uov_n_padded;
    string path;

    uov_m        = lvl_m(sec_lvl);
    uov_n        = lvl_n(sec_lvl);
    uov_n_padded = lvl_n_padded(sec_lvl);

    for (int r = 0; r < UOV_LVL_V_N; r++)
      for (int c = 0; c < UOV_LVL_V_M; c++)
        Ob_ref[r][c] = '0;

    path = {DATA_DIR, enable_blinding ? "Ob_ref_" : "O_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    while ($fscanf(fd, " %d %d %h", sage_col, sage_row, fval) == 3)
      if (sage_row < uov_n && sage_col < uov_m)
        Ob_ref[sage_row][sage_col] = fval;
    $fclose(fd);

    rst = 1;
    @(posedge clk);

    for (w = 0; w < BRAM_O_DEPTH; w++) begin
      ext_rw_addr_val = {3'(BRAM_O_SEL), 18'd0, addr_t'(w)};
      ext_wr_en_val   = 1'b0;
      repeat(BRAM_RD_LAT) @(posedge clk);
      #1;
      bram_O_rd[w] = ext_rd_data_val;
    end

    mismatches = 0;
    for (row = 0; row < uov_n; row++) begin
      for (col = 0; col < uov_m; col++) begin
        flat      = row + col * uov_n_padded;
        word_addr = flat / W_FE;
        lane      = flat % W_FE;
        got = bram_O_rd[word_addr][FE_BITS*lane +: FE_BITS];
        exp = Ob_ref[row][col];
        if (got !== exp) begin
          if (mismatches < 10)
            $display("check_bram_O[%s] mismatch [%0d][%0d]: got %02h exp %02h", lvl_suffix(sec_lvl), row, col, got, exp);
          mismatches++;
        end
      end
    end

    if (enable_blinding) ref_name = "Ob_ref";
    else                 ref_name = "O_ref";
    if (mismatches == 0) $display("uov_wrapper_tb[%s]: O matches %s [OK]", lvl_suffix(sec_lvl), ref_name);
    else begin $display("uov_wrapper_tb[%s]: O has %0d mismatches against %s [FAIL]", lvl_suffix(sec_lvl), mismatches, ref_name); errors++; end
  endtask

  
  // Reads the BRAM_ty content (i.e. y) from the BRAM and checks the correctness against the reference file
  task automatic check_bram_ty(input logic [2:0] sec_lvl);
    field_t y_ref    [0:UOV_LVL_V_M-1];
    word_t  bram_ty_rd[0:BRAM_ty_DEPTH-1];
    int fd;
    int idx;
    logic [7:0] fval;
    field_t got, exp;
    int mismatches, k, w;
    int uov_m;
    string path;

    uov_m = lvl_m(sec_lvl);

    for (int j = 0; j < UOV_LVL_V_M; j++)
      y_ref[j] = '0;

    path = {DATA_DIR, "y_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    while ($fscanf(fd, " %d %h", idx, fval) == 2)
      if (idx < uov_m)
        y_ref[idx] = fval;
    $fclose(fd);

    rst = 1;
    @(posedge clk);

    for (w = 0; w < BRAM_ty_DEPTH; w++) begin
      ext_rw_addr_val = {3'(BRAM_ty_SEL), 18'd0, addr_t'(w)};
      ext_wr_en_val   = 1'b0;
      repeat(BRAM_RD_LAT) @(posedge clk);
      #1;
      bram_ty_rd[w] = ext_rd_data_val;
    end

    mismatches = 0;
    for (k = 0; k < uov_m; k++) begin
      got = bram_ty_rd[k / W_FE][FE_BITS*(k % W_FE) +: FE_BITS];
      exp = y_ref[k];
      if (got !== exp) begin
        if (mismatches < 10)
          $display("check_bram_ty[%s] mismatch [%0d]: got %02h exp %02h", lvl_suffix(sec_lvl), k, got, exp);
        mismatches++;
      end
    end

    if (mismatches == 0) $display("uov_wrapper_tb[%s]: y matches y_ref [OK]", lvl_suffix(sec_lvl));
    else begin $display("uov_wrapper_tb[%s]: y has %0d mismatches [FAIL]", lvl_suffix(sec_lvl), mismatches); errors++; end
  endtask

  // Reads the BRAM_vs content (i.e. s) from the BRAM and checks the correctness against the reference file
  task automatic check_bram_vs(input logic [2:0] sec_lvl);
    field_t s_ref    [0:UOV_LVL_V_N-1];
    word_t  bram_vs_rd[0:BRAM_vs_DEPTH-1];
    int fd;
    int idx;
    logic [7:0] fval;
    field_t got, exp;
    int mismatches, k, w;
    int uov_n;
    string path;

    uov_n = lvl_n(sec_lvl);

    for (int j = 0; j < UOV_LVL_V_N; j++)
      s_ref[j] = '0;

    path = {DATA_DIR, "s_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    while ($fscanf(fd, " %d %h", idx, fval) == 2)
      if (idx < uov_n)
        s_ref[idx] = fval;
    $fclose(fd);

    rst = 1;
    @(posedge clk);

    for (w = 0; w < BRAM_vs_DEPTH; w++) begin
      ext_rw_addr_val = {3'(BRAM_vs_SEL), 18'd0, addr_t'(w)};
      ext_wr_en_val   = 1'b0;
      repeat(BRAM_RD_LAT) @(posedge clk);
      #1;
      bram_vs_rd[w] = ext_rd_data_val;
    end

    mismatches = 0;
    for (k = 0; k < uov_n; k++) begin
      got = bram_vs_rd[k / W_FE][FE_BITS*(k % W_FE) +: FE_BITS];
      exp = s_ref[k];
      if (got !== exp) begin
        if (mismatches < 10)
          $display("check_bram_vs[%s] mismatch [%0d]: got %02h exp %02h", lvl_suffix(sec_lvl), k, got, exp);
        mismatches++;
      end
    end

    if (mismatches == 0) $display("uov_wrapper_tb[%s]: s matches s_ref [OK]", lvl_suffix(sec_lvl));
    else begin $display("uov_wrapper_tb[%s]: s has %0d mismatches [FAIL]", lvl_suffix(sec_lvl), mismatches); errors++; end
  endtask

  // Reads the BRAM_ty content (i.e. t) from the BRAM and checks the correctness against the reference file
  task automatic check_hash_output_ty(input logic [2:0] sec_lvl);
    field_t t_ref    [0:UOV_LVL_V_M-1];
    word_t  bram_ty_rd[0:BRAM_ty_DEPTH-1];
    int fd, status;
    logic [7:0] fval;
    field_t got, exp;
    int mismatches, k, w;
    int uov_m;
    string path;

    uov_m = lvl_m(sec_lvl);

    for (int j = 0; j < UOV_LVL_V_M; j++)
      t_ref[j] = '0;

    path = {DATA_DIR, "t_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    for (k = 0; k < uov_m; k++) begin
      status = $fscanf(fd, " %h", fval);
      t_ref[k] = fval;
    end
    $fclose(fd);

    rst = 1;
    @(posedge clk);

    for (w = 0; w < BRAM_ty_DEPTH; w++) begin
      ext_rw_addr_val = {3'(BRAM_ty_SEL), 18'd0, addr_t'(w)};
      ext_wr_en_val   = 1'b0;
      repeat(BRAM_RD_LAT) @(posedge clk);
      #1;
      bram_ty_rd[w] = ext_rd_data_val;
    end

    mismatches = 0;
    for (k = 0; k < uov_m; k++) begin
      got = bram_ty_rd[BRAM_ty_DEPTH/2 + k / W_FE][FE_BITS*(k % W_FE) +: FE_BITS];
      exp = t_ref[k];
      if (got !== exp) begin
        if (mismatches < 10)
          $display("check_hash_output_ty[%s] mismatch [%0d]: got %02h exp %02h", lvl_suffix(sec_lvl), k, got, exp);
        mismatches++;
      end
    end

    if (mismatches == 0) $display("uov_wrapper_tb[%s]: t matches t_ref [OK]", lvl_suffix(sec_lvl));
    else begin $display("uov_wrapper_tb[%s]: t has %0d mismatches [FAIL]", lvl_suffix(sec_lvl), mismatches); errors++; end
  endtask

  // Executes UOV signing for the specified security level
  task automatic run_uov_sign(input logic [2:0] sec_lvl, input logic enable_blinding);
    int unsigned cycle_count;
    string mode;
    do_verif = 1'b0;
    do_blinding = enable_blinding;

    // Prepare input:
    load_seed_bl(sec_lvl);
    load_seed_pk(sec_lvl);
    load_bram_O(sec_lvl);
    load_hash_input(sec_lvl, msg_len_bytes);

    #20;
    rst = 0;
    @(posedge clk);

    #101;

    start = 1;
    @(posedge clk);
    #1;

    start = 0;

    cycle_count = 0;
    forever begin
      @(posedge clk);
      cycle_count++;
      if (done == 1'd1) break;
    end
    if (enable_blinding) mode = "blinded";
    else                 mode = "unblinded";
    $display("uov_wrapper_tb[%s]: %s uov sign execution took %0d clock cycles", lvl_suffix(sec_lvl), mode, cycle_count);

    #31;
    rst = 1'd1;
    
    @(posedge clk);
    #31;

    // Check result
    check_bram_O(sec_lvl, enable_blinding);
    check_hash_output_ty(sec_lvl);
    if(enable_blinding) check_bram_ty(sec_lvl);
    check_bram_vs(sec_lvl);
  endtask

  // ===================== Verification Helpers ==========================

  // Loas the signature s into BRAM_vs
  task automatic load_bram_vs_s(input logic [2:0] sec_lvl, input int invalid);
    field_t s_ref [0:UOV_LVL_V_N-1];
    int fd, idx, status;
    logic [7:0] fval;
    word_t packed_word;
    int w, i, flat, uov_n;
    string path;

    uov_n = lvl_n(sec_lvl);
    for (int k = 0; k < UOV_LVL_V_N; k++) s_ref[k] = '0;

    if (invalid != 0)
      path = {DATA_DIR, "signature_invalid", $sformatf("%0d", invalid), "_", lvl_suffix(sec_lvl), ".txt"};
    else
      path = {DATA_DIR, "s_ref_", lvl_suffix(sec_lvl), ".txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end
    while ($fscanf(fd, " %d %h", idx, fval) == 2)
      if (idx < uov_n) s_ref[idx] = fval;
    $fclose(fd);

    for (w = 0; w < BRAM_vs_DEPTH; w++) begin
      packed_word = '0;
      for (i = 0; i < W_FE; i++) begin
        flat = w * W_FE + i;
        if (flat < uov_n)
          packed_word[FE_BITS*i +: FE_BITS] = s_ref[flat];
      end
      ext_rw_addr_val = {3'(BRAM_vs_SEL), 18'd0, addr_t'(w)};
      ext_wr_data_val = packed_word;
      ext_wr_en_val   = 1'b1;
      @(posedge clk);
    end
    ext_wr_en_val = 1'b0;
    $display("uov_wrapper_tb: bram_vs (s) loaded from %s", path);
  endtask

  // Streams the P3 key to the UOV coprocessor
  task automatic feed_p3_stream(input logic [2:0] sec_lvl);
    int fd, status, slice_base, r, c, count;
    logic [7:0] fval;
    word_t packed_word;
    string path;

    path = {DATA_DIR, "p3_ref_", lvl_suffix(sec_lvl), "_normalOrder.txt"};
    fd = $fopen(path, "r");
    if (fd == 0) begin $display("ERROR: cannot open %s", path); errors++; $finish; end

    count = 0;
    while ($fscanf(fd, " %d %d %d", slice_base, r, c) == 3) begin
      packed_word = '0;
      for (int i = 0; i < W_FE; i++) begin
        status = $fscanf(fd, " %h", fval);
        packed_word[FE_BITS*i +: FE_BITS] = fval;
      end
      // present word and wait for the consuming TREADY pulse
      axis_p3key_tdata  = packed_word;
      axis_p3key_tvalid = 1'b1;
      @(posedge clk); #1;
      while (axis_p3key_tready !== 1'b1) begin @(posedge clk); #1; end
      count++;
    end
    axis_p3key_tvalid = 1'b0;
    $fclose(fd);
    $display("uov_wrapper_tb[%s]: P3 stream fed (%0d words)", lvl_suffix(sec_lvl), count);
  endtask

  // Check the verification result in bram_ty
  task automatic check_verif_ty(input logic [2:0] sec_lvl, input int invalid);
    word_t  bram_ty_rd[0:BRAM_ty_DEPTH-1];
    field_t got;
    int nonzero, k, w, uov_m;
    string lvl;

    uov_m = lvl_m(sec_lvl);
    lvl   = lvl_suffix(sec_lvl);

    rst = 1;
    @(posedge clk);
    for (w = 0; w < BRAM_ty_DEPTH; w++) begin
      ext_rw_addr_val = {3'(BRAM_ty_SEL), 18'd0, addr_t'(w)};
      ext_wr_en_val   = 1'b0;
      repeat(BRAM_RD_LAT) @(posedge clk);
      #1;
      bram_ty_rd[w] = ext_rd_data_val;
    end

    nonzero = 0;
    for (k = 0; k < uov_m; k++) begin
      got = bram_ty_rd[k / W_FE][FE_BITS*(k % W_FE) +: FE_BITS];
      if (got !== '0) nonzero++;
    end

    if (invalid == 0) begin
      if (nonzero == 0) $display("uov_wrapper_tb[%s]: valid signature verified, result zero [OK]", lvl);
      else begin $display("uov_wrapper_tb[%s]: valid signature has %0d nonzero positions [FAIL]", lvl, nonzero); errors++; end
    end else begin
      if (nonzero == 0) begin $display("uov_wrapper_tb[%s]: invalid signature (%0d) accepted [FAIL]", lvl, invalid); errors++; end
      else              $display("uov_wrapper_tb[%s]: invalid signature (%0d) rejected, %0d nonzero [OK]", lvl, invalid, nonzero);
    end
  endtask

  // Executes UOV verification for the specified security level
  task automatic run_uov_verif(input logic [2:0] sec_lvl, input int invalid);
    int unsigned cycle_count;
    do_verif       = 1'b1;
    axis_p3key_tvalid = 1'b0;

    // Prepare input data
    load_seed_bl(sec_lvl);
    load_seed_pk(sec_lvl);
    load_bram_vs_s(sec_lvl, invalid);
    load_hash_input(sec_lvl, msg_len_bytes);

    #20;
    rst = 0;
    @(posedge clk);
    #101;

    start = 1;
    @(posedge clk);
    #1;
    start = 0;

    // Stream P3 concurrently
    fork
      feed_p3_stream(sec_lvl);
    join_none

    cycle_count = 0;
    forever begin
      @(posedge clk);
      cycle_count++;
      if (done == 1'd1) break;
    end
    $display("uov_wrapper_tb[%s]: uov verif (invalid=%0d) took %0d clock cycles",
             lvl_suffix(sec_lvl), invalid, cycle_count);

    #31;
    rst = 1'd1;
    @(posedge clk);
    #31;

    // check if the signature is valid or not:
    check_verif_ty(sec_lvl, invalid);
    do_verif = 1'b0;
  endtask

  // ===================== Main ==========================

  // Execute the tests for different security levels:
  initial begin
    #101;
    
    sec_lvl = UOV_LVL_TOY; run_uov_sign(sec_lvl, 1'd0); #101;// disabled blinding
    sec_lvl = UOV_LVL_TOY; run_uov_sign(sec_lvl, 1'd1); #101;// enabled blinding
    sec_lvl = UOV_LVL_TOY; run_uov_verif(sec_lvl, 0); #101;  // valid signature
    sec_lvl = UOV_LVL_TOY; run_uov_verif(sec_lvl, 1); #101;  // invalid signature
    sec_lvl = UOV_LVL_TOY; run_uov_verif(sec_lvl, 2); #101;  // invalid signature

    sec_lvl = UOV_LVL_Ip;  run_uov_sign(sec_lvl, 1'd0); #101;// disabled blinding
    sec_lvl = UOV_LVL_Ip;  run_uov_sign(sec_lvl, 1'd1); #101;// enabled blinding
    sec_lvl = UOV_LVL_Ip;  run_uov_verif(sec_lvl, 0); #101;

    sec_lvl = UOV_LVL_III; run_uov_sign(sec_lvl, 1'd0); #101;// disabled blinding
    sec_lvl = UOV_LVL_III; run_uov_sign(sec_lvl, 1'd1); #101;// enabled blinding
    sec_lvl = UOV_LVL_III; run_uov_verif(sec_lvl, 0); #101;

    sec_lvl = UOV_LVL_V;   run_uov_sign(sec_lvl, 1'd0); #101;// disabled blinding
    sec_lvl = UOV_LVL_V;   run_uov_sign(sec_lvl, 1'd1); #101;// enabled blinding
    sec_lvl = UOV_LVL_V;   run_uov_verif(sec_lvl, 0); #101;

    #100;

    $display("==============================================");
    if (errors != 0) $fatal(1, "uov_wrapper_tb: %0d check(s) FAILED", errors);
    $display("uov_wrapper_tb: all checks passed");
    $display("==============================================");
    $finish;
  end

endmodule
import chipwhisperer as cw
from random import randint
from math import ceil
from pathlib import Path
import numpy as np
import galois
import time

# Reference file path
_DATA_DIR = Path(__file__).parent.parent / "uov_ref" / "data"

# UOV configuration. Must match with HLS/RTL code
_GF256 = galois.GF(2**8, irreducible_poly=0x11b) # AES field GF(256)

UOV_LVL_Ip  = 1
UOV_LVL_III = 3
UOV_LVL_V   = 5
UOV_LVL_TOY = 7

LEVELS = {
    UOV_LVL_Ip:  dict(suffix="uov-Ip",  m=44, v=68,  n=112, n_padded=112),
    UOV_LVL_III: dict(suffix="uov-III", m=72, v=112, n=184, n_padded=192),
    UOV_LVL_V:   dict(suffix="uov-V",   m=96, v=148, n=244, n_padded=256),
    UOV_LVL_TOY: dict(suffix="uov-toy", m=32, v=48,  n=80,  n_padded=80),
}

UOV_LVL_V_M        = LEVELS[UOV_LVL_V]["m"]
UOV_LVL_V_N_PADDED = LEVELS[UOV_LVL_V]["n_padded"]

UOV_SEED_PK_BYTES = 16
UOV_SALT_BYTES    = 16
UOV_SEED_SK_BYTES = 32

AES_BITS = 128
FE_BITS  = 8
W_BITS   = AES_BITS
W_FE     = W_BITS // FE_BITS

# BRAM configuration. Must match with HLS/RTL code
BRAM_ADDR_BYTES = 4
BRAM_DATA_BYTES = 16

BRAM_O_DEPTH   = UOV_LVL_V_N_PADDED * UOV_LVL_V_M // W_FE
BRAM_LR_DEPTH  = 576
BRAM_T_DEPTH   = UOV_LVL_V_N_PADDED * UOV_LVL_V_M // W_FE
MEM_vs_DEPTH   = 512
MEM_ty_DEPTH   = MEM_vs_DEPTH
HASH_IN_OFFSET = MEM_ty_DEPTH // 2

BRAM_O_ID  = 0
BRAM_LR_ID = 1
BRAM_T_ID  = 2
MEM_ty_ID  = 3
MEM_vs_ID  = 4

def initCW(bitstream_file, use_scope=True):
  scope = None

  if use_scope:
    scope = cw.scope()
    scope.default_setup()
    if scope._is_husky:
      scope.adc.samples = 4*32000 # Husky max 131070 samples, 4 samples per FPGA clock cycle
    else:
      scope.adc.samples = 40000 # CW-Lite max 24400
    scope.adc.offset = 0
    scope.adc.basic_mode = "falling_edge"  # tio_trigger rests high, falls at op start
    scope.trigger.triggers = "tio4"
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"
    scope.io.hs2 = "disabled"
    scope.gain.db = 15
    scope.io.hs2 = "disabled"

  # PROGRAMMING THE FPGA
  platform = 'cw305'
  fpga_id  = '100t'

  target = cw.target(scope, cw.targets.CW305, force=True, fpga_id=fpga_id, platform=platform,
                    bsfile=bitstream_file,
                    defines_files=["../rtl/cw305/cw305_defines.v"])

  #############################################

  target.vccint_set(1.0)
  target.pll.pll_enable_set(True)
  target.pll.pll_outenable_set(False, 0)
  target.pll.pll_outenable_set(True, 1)
  target.pll.pll_outenable_set(False, 2)


  # run at 10 MHz:
  target.pll.pll_outfreq_set(10E6, 1)

  if use_scope:
    target.clkusbautooff = True
    target.clksleeptime = 1

  #############################################

  if use_scope:
    if scope._is_husky:
      scope.clock.clkgen_freq = 10e6
      scope.clock.clkgen_src = 'extclk'
      scope.clock.adc_mul = 4
    else:
      scope.clock.adc_src = "extclk_x4"

    for i in range(5):
      scope.clock.reset_adc()
      time.sleep(1)
      if scope.clock.adc_locked:
        break
    assert (scope.clock.adc_locked), "ADC failed to lock"

  return target, scope


def applyReset(target):
  time.sleep(0.01)
  one = 1  
  target.fpga_write(target.REG_RST, one.to_bytes(1, 'little'))
  time.sleep(0.01)

def releaseReset(target):
  time.sleep(0.01)
  zero = 0  
  target.fpga_write(target.REG_RST, zero.to_bytes(1, 'little'))
  time.sleep(0.01)

def writeBRAM(target, data, bram_id, addr_offset=0):
  '''
  writes integers to bram

  data:        integer array to be written to BRAM
  addr_offset: word address of data[0] within the BRAM (default 0)
  '''
  one = 1
  zero = 0
  for i,e in enumerate(data):
    addr = (bram_id << 29) + addr_offset + i
    target.fpga_write(target.REG_BRAM_RW_ADDR, addr.to_bytes(BRAM_ADDR_BYTES, 'little'))
    target.fpga_write(target.REG_BRAM_WR_DATA, e.to_bytes(BRAM_DATA_BYTES, 'little'))
    target.fpga_write(target.REG_BRAM_WR_EN, one.to_bytes(1, 'little'))
    target.fpga_write(target.REG_BRAM_WR_EN, zero.to_bytes(1, 'little'))

def readBRAM(target, length, bram_id, addr_offset=0):
  '''
  read integers from bram

  length:      number of elements to be read
  addr_offset: word address of the first element within the BRAM (default 0)
  '''
  ret = [0]*length

  for i in range(length):
    addr = (bram_id << 29) + addr_offset + i
    target.fpga_write(target.REG_BRAM_RW_ADDR, addr.to_bytes(BRAM_ADDR_BYTES, 'little'))
    r = target.fpga_read(target.REG_BRAM_RD_DATA, BRAM_DATA_BYTES)
    ret[i] = int.from_bytes(r, 'little')
  
  return ret

def testBRAM(target, bram_id):
  print(f"Testing BRAM {bram_id}...")
  length = {
      BRAM_O_ID:  BRAM_O_DEPTH,
      BRAM_LR_ID: BRAM_LR_DEPTH,
      BRAM_T_ID:  BRAM_T_DEPTH,
      MEM_ty_ID:  MEM_ty_DEPTH,
      MEM_vs_ID:  MEM_vs_DEPTH,
  }[bram_id]
  data = [(randint(0, 2**64-1) << 64) + _ for _ in range(length)]
  applyReset(target)
  writeBRAM(target, data, bram_id)
  ret = readBRAM(target, length, bram_id)
  releaseReset(target)

  error = 0
  for i,e in enumerate(data):
    if e != ret[i]:
      print("Error", i, hex(e), hex(ret[i]))
      error = 1

  if error == 1:
    print("BRAM Error!")
    exit(-1)
  print("  OK")


def runUOV(target, block=True):
  target.go()
  time.sleep(0.001)
  i = 1
  while block and not target.is_done():
    i += 1
    time.sleep(0.001)
    if i > 1000:
      print("Target did not finish operation")
      exit(-1)
  return i


def sendSeedPK(target, seed_pk : bytes):
  target.fpga_write(target.REG_SEED_PK, seed_pk)

def sendSeedBL(target, seed_bl : bytes):
  target.fpga_write(target.REG_SEED_BL, seed_bl)

def sendRngEnable(target, rng_en):
  '''Enable (1) or disable (0) the on-chip blinding RNG.'''
  target.fpga_write(target.REG_TRNG_EN, int(bool(rng_en)).to_bytes(1, 'little'))

def sendMsgLen(target, msg_len : bytes):
  assert len(msg_len) == 2
  target.fpga_write(target.REG_MSG_LEN, msg_len)

def sendDoVerif(target, do_verif, do_blinding=True):
  '''Select between verification and signing. 
     do_blinding==False disables all blinding steps'''
  i = int(bool(do_blinding)) << 1
  i |= int(bool(do_verif)) 
  target.fpga_write(target.REG_DO_VERIF, i.to_bytes(1, 'little'))

def sendParameters(target, sec_lvl):
  lvl       = LEVELS[sec_lvl]
  m, v      = lvl["m"], lvl["v"]
  p1_bytes  = m * v * (v + 1) // 2
  nr_slices = (m + W_FE - 1) // W_FE

  target.fpga_write(target.REG_UOV_M,        m.to_bytes(2, 'little'))
  target.fpga_write(target.REG_UOV_V,        v.to_bytes(2, 'little'))
  target.fpga_write(target.REG_UOV_N,        lvl["n"].to_bytes(2, 'little'))
  target.fpga_write(target.REG_UOV_N_PADDED, lvl["n_padded"].to_bytes(2, 'little'))
  target.fpga_write(target.REG_P1_BYTES,     p1_bytes.to_bytes(4, 'little'))
  target.fpga_write(target.REG_NR_SLICES,    nr_slices.to_bytes(1, 'little'))


def lvl_suffix(sec_lvl):
  return LEVELS[sec_lvl]["suffix"]

def bramO_words(sec_lvl):
  return LEVELS[sec_lvl]["m"] * LEVELS[sec_lvl]["n_padded"] // W_FE

def ref_path(base, sec_lvl):
  '''Per-level reference path'''
  return str(_DATA_DIR / f"{base}_{lvl_suffix(sec_lvl)}.txt")

def load_vector(path, n):
  arr = [0] * n
  with open(path, 'r') as f:
    tokens = f.read().split()
  it = iter(tokens)
  for idx_s, val_s in zip(it, it):
    idx, val = int(idx_s), int(val_s, 16)
    if idx < n:
      arr[idx] = val
  return arr

def load_matrix(path, cols):
  with open(path, 'r') as f:
    tokens = f.read().split()
  arr = [0] * len(tokens)
  it = iter(tokens)
  for col_s, row_s, val_s in zip(it, it, it):
    sage_col, sage_row, val = int(col_s), int(row_s), int(val_s, 16)
    arr[sage_row * cols + sage_col] = val
  return arr

def load_seed_pk(sec_lvl):
  path = ref_path("seed_pk", sec_lvl)
  with open(path, 'r') as f:
    vals = [int(x, 16) for x in f.read().split()]
  assert len(vals) >= UOV_SEED_PK_BYTES, f"load_seed_pk: unexpected EOF in {path}"
  return bytes(vals[:UOV_SEED_PK_BYTES])

def load_seed_bl(sec_lvl):
  path = ref_path("seed_bl", sec_lvl)
  with open(path, 'r') as f:
    vals = [int(x, 16) for x in f.read().split()]
  assert len(vals) >= UOV_SEED_PK_BYTES, f"load_seed_bl: unexpected EOF in {path}"
  return bytes(vals[:UOV_SEED_PK_BYTES])

def getRandomOcontent(sec_lvl):
  '''
    Builds a random BRAM_O image with the UOV oil-space structure over GF(256)
    '''
  m, v, n, n_padded = (LEVELS[sec_lvl]["m"], LEVELS[sec_lvl]["v"],
                       LEVELS[sec_lvl]["n"], LEVELS[sec_lvl]["n_padded"])

  O1 = _GF256(np.array([[randint(0, 255) for _ in range(m)] for _ in range(v)], dtype=np.uint8))
  while True:
    R = _GF256(np.array([[randint(0, 255) for _ in range(m)] for _ in range(m)], dtype=np.uint8))
    if np.linalg.matrix_rank(R) == m:
      break
  O = np.array(np.vstack([O1 @ R, R]), dtype=np.uint8).tolist()

  n_words = bramO_words(sec_lvl)
  bram_O = [0] * n_words
  for w in range(n_words):
    b = [0] * W_FE
    for i in range(W_FE):
      flat = w * W_FE + i
      col  = flat // n_padded
      row  = flat %  n_padded
      if col < m and row < n:
        b[i] = O[row][col]
    bram_O[w] = int.from_bytes(bytes(b), 'little')
  return bram_O

def randomizeOcontent(sec_lvl, bram_O, use_lu = False):
  '''
    Re-randomize a BRAM_O image by multiplying the oil-space matrix O
    with a random invertible matrix over GF(256). use_lu=True uses
    the LU approach for matrix sampling. use_lu=False uses an uniformly 
    random matrix
    '''
  m, n, n_padded = LEVELS[sec_lvl]["m"], LEVELS[sec_lvl]["n"], LEVELS[sec_lvl]["n_padded"]
  n_words = bramO_words(sec_lvl)

  # unpack from BRAM_O layout
  O = np.zeros((n, m), dtype=np.uint8)
  for w in range(n_words):
    word = bram_O[w]
    for i in range(W_FE):
      flat = w * W_FE + i
      col  = flat // n_padded
      row  = flat %  n_padded
      if col < m and row < n:
        O[row][col] = (word >> (FE_BITS * i)) & 0xFF

  # sample a random invertible matrix
  if use_lu:
    L = np.zeros((m, m), dtype=np.uint8)
    U = np.zeros((m, m), dtype=np.uint8)
    for i in range(m):
      L[i][i] = 1                            # unit diagonal
      U[i][i] = randint(1, 255)              # non-zero diagonal
      for j in range(i):
        L[i][j] = randint(0, 255)          # lower triangle
      for j in range(i + 1, m):
        U[i][j] = randint(0, 255)          # upper triangle
    R = np.array(_GF256(L) @ _GF256(U), dtype=np.uint8)
  else:
    while True:
      R = np.array([[randint(0, 255) for _ in range(m)] for _ in range(m)], dtype=np.uint8)
      if np.linalg.matrix_rank(_GF256(R)) == m:
        break

  O_rand = np.array(_GF256(O) @ _GF256(R), dtype=np.uint8)

  # pack into BRAM_O layout
  out = [0] * n_words
  for w in range(n_words):
    b = [0] * W_FE
    for i in range(W_FE):
      flat = w * W_FE + i
      col  = flat // n_padded
      row  = flat %  n_padded
      if col < m and row < n:
        b[i] = int(O_rand[row][col])
    out[w] = int.from_bytes(bytes(b), 'little')
  return out

def prepareBramO(sec_lvl):
  m, n, n_padded = LEVELS[sec_lvl]["m"], LEVELS[sec_lvl]["n"], LEVELS[sec_lvl]["n_padded"]
  O_ref = load_matrix(ref_path("O_ref", sec_lvl), m)
  bram_O = [0] * BRAM_O_DEPTH
  for w in range(BRAM_O_DEPTH):
    b = [0] * W_FE
    for i in range(W_FE):
      flat = w * W_FE + i
      col  = flat // n_padded
      row  = flat %  n_padded
      b[i] = O_ref[row * m + col] if (row < n and col < m) else 0
    bram_O[w] = int.from_bytes(bytes(b), 'little')
  return bram_O

def load_hash_input(sec_lvl):
  '''
    Read the Keccak hash input (msg || salt || seed_sk) from input file
    '''
  with open(ref_path("hash_in_ref", sec_lvl), 'r') as f:
    in_bytes = [int(x, 16) for x in f.read().split()]
  nbytes  = len(in_bytes)
  msg_len = nbytes - UOV_SALT_BYTES - UOV_SEED_SK_BYTES

  cap = HASH_IN_OFFSET * W_FE
  if nbytes > cap:
    print(f"WARNING: hash input {nbytes} bytes exceeds mem_ty upper-half capacity {cap}")

  n_words = ceil(nbytes / W_FE)
  words = [0] * n_words
  for w in range(n_words):
    b = [0] * W_FE
    for i in range(W_FE):
      flat = w * W_FE + i
      b[i] = in_bytes[flat] if flat < nbytes else 0
    words[w] = int.from_bytes(bytes(b), 'little')
  return words, msg_len

def verifyOb(fpga_data, sec_lvl):
  m, n, n_padded = LEVELS[sec_lvl]["m"], LEVELS[sec_lvl]["n"], LEVELS[sec_lvl]["n_padded"]
  Ob_ref = load_matrix(ref_path("Ob_ref", sec_lvl), m)
  mismatches = 0
  for row in range(n):
    for col in range(m):
      flat = row + col * n_padded
      got = (fpga_data[flat // W_FE] >> (FE_BITS * (flat % W_FE))) & 0xFF
      ref = Ob_ref[row * m + col]
      if got != ref:
        if mismatches < 10:
          print(f"verifyOb[{lvl_suffix(sec_lvl)}] mismatch [{row}][{col}]: got {got:02x} ref {ref:02x}")
        mismatches += 1
  if mismatches:
    print(f"verifyOb[{lvl_suffix(sec_lvl)}]: {mismatches} mismatches")
  else:
    print(f"verifyOb[{lvl_suffix(sec_lvl)}]: matches Ob_ref ✓")
  return mismatches == 0

def verifyY(fpga_data, sec_lvl):
  m = LEVELS[sec_lvl]["m"]
  y_ref = load_vector(ref_path("y_ref", sec_lvl), m)
  mismatches = 0
  for k in range(m):
    got = (fpga_data[k // W_FE] >> (FE_BITS * (k % W_FE))) & 0xFF
    ref = y_ref[k]
    if got != ref:
      if mismatches < 10:
        print(f"verifyY[{lvl_suffix(sec_lvl)}] mismatch [{k}]: got {got:02x} ref {ref:02x}")
      mismatches += 1
  if mismatches:
    print(f"verifyY[{lvl_suffix(sec_lvl)}]: {mismatches} mismatches")
  else:
    print(f"verifyY[{lvl_suffix(sec_lvl)}]: matches y_ref ✓")
  return mismatches == 0

def verifyS(fpga_data, sec_lvl):
  n = LEVELS[sec_lvl]["n"]
  s_ref = load_vector(ref_path("s_ref", sec_lvl), n)
  mismatches = 0
  for k in range(n):
    got = (fpga_data[k // W_FE] >> (FE_BITS * (k % W_FE))) & 0xFF
    ref = s_ref[k]
    if got != ref:
      if mismatches < 10:
        print(f"verifyS[{lvl_suffix(sec_lvl)}] mismatch [{k}]: got {got:02x} ref {ref:02x}")
      mismatches += 1
  if mismatches:
    print(f"verifyS[{lvl_suffix(sec_lvl)}]: {mismatches} mismatches")
  else:
    print(f"verifyS[{lvl_suffix(sec_lvl)}]: matches s_ref ✓")
  return mismatches == 0

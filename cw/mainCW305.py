import chipwhisperer as cw
from random import randint, seed, randbytes
import matplotlib.pyplot as plt
from scalib.metrics import Ttest
import numpy as np
import os
from datetime import datetime
from tqdm import tqdm
from myCW305interface import *


bitstream_file = "../bit/uov_cw_reference.bit"
target, scope  = initCW(bitstream_file, use_scope=True)

#############################################
# Test the BRAM interface:
#############################################
testBRAM(target, BRAM_O_ID)
testBRAM(target, MEM_ty_ID)
testBRAM(target, MEM_vs_ID)


#############################################
## Functional Signing Tests:
#############################################
print("=== Performing Functional Signing Tests ===")

applyReset(target)

ok = True

for sec_lvl in [UOV_LVL_TOY,UOV_LVL_Ip,UOV_LVL_III,UOV_LVL_V]:
  
  print("  SIGN TEST " + lvl_suffix(sec_lvl))
  # read BRAM_O content from input file and send to BRAM
  bram_O_data = prepareBramO(sec_lvl)
  writeBRAM(target, bram_O_data,  BRAM_O_ID)

  # read message from input file and send to BRAM
  hash_in_words, msg_len = load_hash_input(sec_lvl)
  writeBRAM(target, hash_in_words, MEM_vs_ID, addr_offset=HASH_IN_OFFSET)

  # Send auxiliary information
  sendMsgLen(target, msg_len.to_bytes(2, 'little'))
  sendSeedPK(target, load_seed_pk(sec_lvl)) # seed for public key
  sendSeedBL(target, load_seed_bl(sec_lvl)) # seed for blinding RNG
  sendDoVerif(target, False)                # perform signing
  sendParameters(target, sec_lvl)           # send the security-level dependent parameters
  sendRngEnable(target, True)               # enable or disable RNG for blinding

  releaseReset(target)

  print("  Inputs loaded")

  # trigger computation
  print("  Run UOV signing for message length = "+str(msg_len)+" bytes")
  runUOV(target)
  print("  Run UOV DONE")

  # read back results
  applyReset(target)
  bram_Ob_out = readBRAM(target, BRAM_O_DEPTH,  BRAM_O_ID)
  mem_y_out   = readBRAM(target, MEM_ty_DEPTH,  MEM_ty_ID)
  mem_s_out   = readBRAM(target, MEM_vs_DEPTH,  MEM_vs_ID)

  print("  Verifying outputs...")
  ok &= verifyOb(bram_Ob_out, sec_lvl)
  ok &= verifyY(mem_y_out, sec_lvl)
  ok &= verifyS(mem_s_out, sec_lvl)
  if not ok:
    print("  -> SIGN FAILED")

if ok:
    print("All outputs match reference ✓")
else:
    print("Output verification FAILED")
    exit(-1)



#############################################
## Collecting traces:
#############################################

CHUNK_TRACES  = 500   # traces buffered before each fit_u
FIXED_MESSAGE = False # True: fixed message and salt, False: random message and salt

def runTraceCollection(checkpoints, rng_en, sec_lvl):
  checkpoint_set = set(checkpoints)
  num_traces_max = checkpoints[-1]

  trace_sum         = None # average power trace
  trace_count       = 0    # number of traces in total
  trace_fixed_count = 0    # number of traces in fixed class
  ts = datetime.now().strftime("%m%d-%H%M%S") # timestamp of this run

  tt = Ttest(d=1)
  buf_traces = []
  buf_labels = []

  def fit_chunk():
      ''' Updates tt with the buffered traces in buf_traces '''
      if not buf_traces:
          return
      tt.fit_u(np.asarray(buf_traces, dtype=np.int16), np.asarray(buf_labels, dtype=np.uint16))
      buf_traces.clear()
      buf_labels.clear()

  def dump_results(num_traces):
      ''' Store checkpoint to hard drive '''

      fit_chunk()
      avg_trace = trace_sum / trace_count
      tv = tt.get_ttest()
      t_values = tv[0]

      n_pairs = trace_count // 2

      name = ("tvla_rngOn_" if rng_en else "tvla_rngOff_") + str(n_pairs) + "_" + ts
      np.savez("./data/" + name + ".npz",
               t_values=np.asarray(t_values),
               avg_trace=np.asarray(avg_trace))

      fig, ax1 = plt.subplots()
      fig.suptitle(name)
      ax1.plot(avg_trace)
      ax1.set_ylabel("avg trace")
      ax2 = ax1.twinx()
      ax2.plot(t_values, 'r-')
      ax2.plot([5.3]*len(t_values), 'r-')
      ax2.plot([-5.3]*len(t_values), 'r-')
      ax2.set_ylabel("t-values")
      plt.savefig("./data/" + name + ".png")
      plt.close()
      print(f"  -> snapshot at {num_traces} fixed + {trace_count - num_traces} random traces saved ({name})")

  # seed the randomness generation
  run_seed = int.from_bytes(os.urandom(8), 'little')
  seed(run_seed)
  print(f"RNG seed: {run_seed}")

  applyReset(target)

  # read the fixed secret oil space from file:
  bram_O_data = prepareBramO(sec_lvl)
  n_words_O   = bramO_words(sec_lvl)

  # prepare input message and salt:
  hash_in_words, msg_len = load_hash_input(sec_lvl)
  ctr_word_idx = (msg_len + UOV_SALT_BYTES + UOV_SEED_SK_BYTES) // W_FE
  ctr_word_val = hash_in_words[ctr_word_idx] if ctr_word_idx < len(hash_in_words) else 0
  nr_msg_salt_bytes = msg_len + UOV_SALT_BYTES
  hash_in_seedsk_ctr = b''.join(int(w).to_bytes(W_FE, 'little') for w in hash_in_words)[nr_msg_salt_bytes:]

  # write static configuration to FPGA:
  writeBRAM(target, hash_in_words, MEM_vs_ID, addr_offset=HASH_IN_OFFSET)
  sendMsgLen(target, msg_len.to_bytes(2, 'little'))
  sendSeedPK(target, load_seed_pk(sec_lvl))
  sendParameters(target, sec_lvl)
  sendDoVerif(target, False)
  sendRngEnable(target, rng_en)

  print(f"Collecting up to {num_traces_max} fixed+random pairs, {rng_en=}; snapshots at {checkpoints} ...")
  for i in tqdm(range(2*num_traces_max), total=2*num_traces_max, desc="Capturing"):
      fixed = randint(0,1) == 0
      random_blinding_seed = randbytes(16)
      sendSeedBL(target, random_blinding_seed)

      # fixed vs random O matrix: Update and send to FPGA:
      bram_O_input_fixed = randomizeOcontent(sec_lvl, bram_O_data, use_lu=True) if rng_en else bram_O_data
      bram_O_input_rand  = getRandomOcontent(sec_lvl)
      bram_O_input       = bram_O_input_fixed if fixed else bram_O_input_rand
      writeBRAM(target, bram_O_input[:n_words_O], BRAM_O_ID)

      if FIXED_MESSAGE:
        # fixed message and salt
        writeBRAM(target, [ctr_word_val], MEM_vs_ID, addr_offset=HASH_IN_OFFSET + ctr_word_idx)
      else:
        # random message and salt
        rb = randbytes(nr_msg_salt_bytes) + hash_in_seedsk_ctr
        random_msg_salt = [int.from_bytes(rb[k:k+W_FE], 'little') for k in range(0, len(rb), W_FE)]
        writeBRAM(target, random_msg_salt, MEM_vs_ID, addr_offset=HASH_IN_OFFSET)

      releaseReset(target)

      time.sleep(0.05)

      ret = cw.capture_trace(scope, target, bytearray(), as_int=True)
      if not ret:
        print("Failed capture")
        applyReset(target)
        exit(-1)
      
      applyReset(target)

      buf_traces.append(ret.wave)
      buf_labels.append(0 if fixed else 1)
      if trace_sum is None:
        trace_sum = np.zeros(len(ret.wave), dtype=np.float64)
      trace_sum += ret.wave
      trace_count += 1
      trace_fixed_count += (1 if fixed else 0)

      if len(buf_traces) >= CHUNK_TRACES:
        fit_chunk()

      if trace_count % 2 == 0 and trace_count // 2 in checkpoint_set:
        dump_results(trace_fixed_count)

  print("Traces collected!")


runTraceCollection([10**3,10**4,10**5], rng_en=True,  sec_lvl=UOV_LVL_TOY)
runTraceCollection([500,10**3,10**4],   rng_en=False, sec_lvl=UOV_LVL_TOY)

scope.dis()
target.dis()
print("Successfully finished trace collection!")
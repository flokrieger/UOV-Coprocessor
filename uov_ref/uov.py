from sage.all import GF, matrix, block_matrix, identity_matrix, random_matrix, PolynomialRing
from random import randint, randbytes
from math import log2,ceil 
from hashlib import shake_256
from Crypto.Cipher import AES
from Crypto.Util import Counter

OUTPUT_PATH   = "./data/"  # Path for storing the reference data for the hardware
KAT_PATH      = "./kat/"   # Path for storing the reference data for the hardware
NUM_KAT_TESTS = 5          # Number of KAT tests for each security level.
                           # We only include 5 KAT tests per security level due to size constraints
                           # If you want to use more KAT tests, please refer to
                           # https://drive.google.com/file/d/1UJ4C6yAHXrNGpk6Xpzg8IkeNWVR4IbX1/view
                           # There, the UOV team hosts the full set of KAT tests (~2GB)
class NIST_KAT_DRBG:
    def __init__(self, seed):
        self.seed_length = 48
        assert len(seed) == self.seed_length
        self.key = b'\x00' * 32
        self.ctr = b'\x00' * 16
        update = self.get_bytes(self.seed_length)
        update = bytes(a^b for a,b in zip(update,seed))
        self.key = update[:32]
        self.ctr = update[32:]

    def __increment_ctr(self):
        x = int.from_bytes(self.ctr, 'big') + 1
        self.ctr = x.to_bytes(16, byteorder='big')

    def get_bytes(self, num_bytes):
        tmp = b''
        cipher = AES.new(self.key, AES.MODE_ECB)
        while len(tmp) < num_bytes:
            self.__increment_ctr()
            tmp  += cipher.encrypt(self.ctr)
        return tmp[:num_bytes]

    def random_bytes(self, num_bytes):
        output_bytes = self.get_bytes(num_bytes)
        update = self.get_bytes(48)
        self.key = update[:32]
        self.ctr = update[32:]
        return output_bytes

drbg    = NIST_KAT_DRBG(bytes([i for i in range(48)]))


# Round 2 Parameters for UOV, including the toy parameter set:
DEFAULT_PARAMETERS = {
    "uov-Ip": {
        "name": "uov-Ip",
        "n": 112,
        "m": 44,
        "q": 256,
        "sk_seed_len": 256,
        "pk_seed_len": 128,
        "salt_len" : 128
    },
    "uov-Is": {
        "name": "uov-Is",
        "n": 160,
        "m": 64,
        "q": 16,
        "sk_seed_len": 256,
        "pk_seed_len": 128,
        "salt_len" : 128
    },
    "uov-III": {
        "name": "uov-III",
        "n": 184,
        "m": 72,
        "q": 256,
        "sk_seed_len": 256,
        "pk_seed_len": 128,
        "salt_len" : 128
    },
    "uov-V": {
        "name": "uov-V",
        "n": 244,
        "m": 96,
        "q": 256,
        "sk_seed_len": 256,
        "pk_seed_len": 128,
        "salt_len" : 128
    },
    "uov-toy": {
        "name": "uov-toy",
        "n": 80,
        "m": 32,
        "q": 256,
        "sk_seed_len": 256,
        "pk_seed_len": 128,
        "salt_len" : 128
    },
}

def aes_ctr_prng(key: bytes, initial_counter_block: bytes, out_len: int) -> bytes:
    if len(initial_counter_block) != 16:
        raise ValueError("counter block must be 16 bytes")
    ctr_int = int.from_bytes(initial_counter_block, "big")  # define endianness!
    ctr = Counter.new(128, initial_value=ctr_int)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(b"\x00" * out_len)


def writeElements(name, elements):
  with open(OUTPUT_PATH + name + ".txt", "w") as f:
    for e in elements:
      f.write(hex(e)[2:] + " ")

def writeVector(name, vec):
  with open(OUTPUT_PATH + name + ".txt", "w") as f:
    for r in range(vec.nrows()):
      f.write(str(r) + " " + hex(vec[r,0].to_integer())[2:] + "\n")

def writeMatrix(name, mat):
  with open(OUTPUT_PATH + name + ".txt", "w") as f:
    for r in range(mat.ncols()):
      for c in range(mat.nrows()):
        f.write(str(r) + " " + str(c) + " " + hex(mat[c,r].to_integer())[2:] + "\n")


class UOV:
  def __init__(self, parameter_set, doBlinding=False):
    self.doBlinding = doBlinding
    self.set_name = str(parameter_set)
    self.name = parameter_set["name"]
    self.n = parameter_set["n"]
    self.m = parameter_set["m"]
    self.v = self.n - self.m
    self.q = parameter_set["q"]
    self.logq = int(ceil(log2(self.q)))
    self.sk_seed_len = parameter_set["sk_seed_len"]
    self.pk_seed_len = parameter_set["pk_seed_len"]
    self.salt_len = parameter_set["salt_len"]

    F2 = GF(2)
    R = PolynomialRing(F2, 'x')
    x = R.gen()
    if self.q == 256:
      mod = x**8 + x**4 + x**3 + x + 1
      self.F = GF(2**8, name='x', modulus=mod)
    else:
      mod = x**4 + x + 1
      self.F = GF(2**4, name='x', modulus=mod)

  def _expandSK(self, seed_sk):
    bytestring = shake_256(seed_sk).digest(self.pk_seed_len//8 + int(ceil(self.v*self.m*self.logq/8)))
    seed_pk = bytestring[0:self.pk_seed_len//8]
    O = self.bytesToMatrixColMaj(bytestring[self.pk_seed_len//8:],self.v,self.m, 1)[0]

    return seed_pk, O

  def matrixToBytesColMaj(self, matrices):
    n_mat = len(matrices)
    rows = matrices[0].nrows()
    cols = matrices[0].ncols()

    out = bytearray()
    for c in range(cols):
      for r in range(rows):
        for i in range(n_mat):
            out.append(int(matrices[i][r, c].to_integer()))

    if self.logq == 8:
      return bytes(out)
    else:
      return self.nibblesToBytes(bytes(out))

  def matrixToBytes(self, matrices, triangular):
    n_mat = len(matrices)
    rows = matrices[0].nrows()
    cols = matrices[0].ncols()

    out = bytearray()
    for r in range(rows):
        c_start = r if triangular else 0
        for c in range(c_start, cols):
            for i in range(n_mat):
                out.append(int(matrices[i][r, c].to_integer()))
    
    if self.logq == 8:
      return bytes(out)
    else:
      return self.nibblesToBytes(bytes(out))

  def bytesToMatrixColMaj(self, bytestring, rows, cols, n_mat):
    idx = 0
    mats = [matrix(self.F, rows, cols) for _ in range(n_mat)]

    if self.logq == 8:
      elements = bytestring
    else:
      elements = self.bytesToNibbles(bytestring)

    for c in range(cols):
        for r in range(rows):
            for i in range(n_mat):
                mats[i][r, c] = self.F.from_integer(elements[idx])
                idx += 1

    return mats

  def bytesToMatrix(self, bytestring, rows, cols, triangular, n_mat):
    idx = 0
    mats = [matrix(self.F, rows, cols) for _ in range(n_mat)]

    if self.logq == 8:
      elements = bytestring
    else:
      elements = self.bytesToNibbles(bytestring)

    for r in range(rows):
        c_start = r if triangular else 0
        for c in range(c_start,cols):
            for i in range(n_mat):
                mats[i][r, c] = self.F.from_integer(elements[idx])
                idx += 1

        if triangular:
            # explicitly zero below diagonal in this column
            for r in range(c + 1, rows):
                for i in range(n_mat):
                    mats[i][r, c] = self.F(0)

    return mats

  def bytesToNibbles(self, bytestring):
    nibbles = bytes([])
    for i in range(len(bytestring)):
      nibbles += bytes([bytestring[i] % self.q])
      nibbles += bytes([bytestring[i] // self.q])

    return nibbles

  def nibblesToBytes(self, nibbles):
    bytestring = bytes()
    for i in range(0,len(nibbles),2):
      bytestring += bytes([(nibbles[i+1] << self.logq) | nibbles[i]])
    return bytestring

  def _expandP(self, seed_pk):
    p1_nonzero_el = self.v*(self.v+1)//2
    bytestring = aes_ctr_prng(seed_pk, bytes([0]*(128//8)), (p1_nonzero_el + self.v*self.m)*self.logq//8*self.m)
    P1 = self.bytesToMatrix(bytestring[: p1_nonzero_el*self.m*self.logq//8],self.v,self.v, True, self.m)
    P2 = self.bytesToMatrix(bytestring[p1_nonzero_el*self.m*self.logq//8 :],self.v,self.m, False, self.m)

    return P1, P2
  
  def _upper(self, matrix):
    assert matrix.nrows() == matrix.ncols()
    for j in range(0, matrix.nrows()):
      for k in range(j+1, matrix.nrows()):
        matrix[j, k] += matrix[k, j]
        matrix[k, j] = 0
    return matrix
  
  def compactKeyGen(self, seed_sk=None):
    ''' Compact key generation as specified in UOV. Returns csk, cpk'''
    if seed_sk is None:
      seed_sk = salt_func(self.sk_seed_len//8)

    seed_pk, O = self._expandSK(seed_sk)
    P1, P2 = self._expandP(seed_pk)

    P3 = [self._upper(-O.transpose() * P1[i] * O - O.transpose() * P2[i]) for i in range(self.m)]

    cpk = (seed_pk, P3)
    csk = seed_sk

    return csk, cpk
  
  def _getRandomInvertibleMatrix(self, size):
    ''' Samples a uniformly random invertible matrix of size x size '''
    while True:
        M = random_matrix(self.F, size, size)
        if M.is_invertible():
            return M

  def _getRandomLUMatrix(self, blinding_aes_seed, ctr=0):
    ''' Implements the LU-based random invertible matrix 
    sampling using AES as a PRNG seeded by blinding_aes_seed. This 
    matches the hardware implementation'''

    slice_off = (ctr % 8) * 16
    p1_bytes  = (self.v * (self.v + 1) // 2) * self.m
    ks_len    = p1_bytes + self.m * self.m * self.m + 8 * 16 + 16
    ks        = aes_ctr_prng(blinding_aes_seed, bytes([0] * 16), ks_len) # randomness stream from AES

    L = matrix(self.F, self.m, self.m)
    U = matrix(self.F, self.m, self.m)

    # L: lower triangular matrix with unit diagonal
    for i in range(self.m):
      L[i, i] = self.F(1)
      for j in range(i):
        entry = self.v * j - j * (j + 1) // 2 + i
        L[i, j] = self.F.from_integer(ks[entry * self.m + slice_off] % self.q)

    # U: upper triangular matrix with non-zero diagonal
    for j in range(self.m):
      for i in range(j):
        U[i, j] = self.F.from_integer(ks[p1_bytes + (j * self.m + i) * self.m + slice_off] % self.q)

      off = p1_bytes + (j * self.m + j) * self.m + slice_off
      b = [ks[off + k] % self.q for k in range(4)]
      non_zero = b[0] if b[0] else b[1] if b[1] else b[2] if b[2] else b[3] if b[3] else (0xc5 % self.q) # select non-zero field element
      U[j, j] = self.F.from_integer(non_zero)

    return L * U

  def expandSK(self, csk):
    ''' Expand the secret key. This is mostly as in UOV but additionally performs blinding if enabled. '''
    seed_pk, O = self._expandSK(csk)
    P1, P2 = self._expandP(seed_pk)

    if self.doBlinding:
      O_bar = block_matrix([[O], [identity_matrix(self.F, self.m)]])
      R = self._getRandomInvertibleMatrix(self.m)
      O_bar_blinded = O_bar * R
      S = [(block_matrix([[P1[i]+P1[i].transpose(), P2[i]]]) * O_bar_blinded)  for i in range(self.m)]
      esk = (csk, O_bar_blinded, P1, S)
    else:
      S = [(P1[i]+P1[i].transpose())*O + P2[i] for i in range(self.m)]
      O_I = block_matrix([[O],[identity_matrix(self.F, self.m)]])
      esk = (csk, O_I, P1, S)

    return esk
  
  def expandPK(self, cpk):
    P1, P2 = self._expandP(cpk[0])
    P3 = cpk[1]
    P = [block_matrix([[P1[i], P2[i]], [matrix(self.F, self.m, self.v), P3[i]]]) for i in range(self.m)]
    return P, P1, P2, P3
  
  def hashVector(self, msg, length):
    ''' Hash the message msg with length bytes into a target vector t '''
    t_prime = shake_256(msg).digest(int(length*int(log2(self.q))//8))
    if self.q == 16:
      t = [self.F.from_integer((t_prime[i//2] >> 4*(i&1)) % 2**4) for i in range(length)]
    else:
      t = [self.F.from_integer(t_prime[i]) for i in range(length)]
    return matrix(self.F, length, 1, t)
  

  def _echelonForm(self,B):
        ''' Implementation of Echelon Form computation as done in hardware '''
        assert B.nrows() == self.m
        assert B.ncols() == self.m + 1

        L = B
        singular = False
        W_FE = 128 // self.logq
        nr_slices = self.m // W_FE + 1  # +1 covers the augmented RHS column
        for pivot_row_idx in range(self.m):
          taken_idx = None
          slice_start_idx = pivot_row_idx // W_FE

          # conditionally add all elements to get non-zero pivot
          slice_idx = slice_start_idx
          L_slice = L[:,slice_idx*W_FE:(slice_idx+1)*W_FE]
          taken_idx = None
          for row_idx in range(pivot_row_idx+1, self.m):
            if L_slice[pivot_row_idx,pivot_row_idx%W_FE] == 0 and L_slice[row_idx,pivot_row_idx%W_FE] != 0:
              L_slice[pivot_row_idx,:] += L_slice[row_idx,:]
              taken_idx = row_idx

          if L_slice[pivot_row_idx, pivot_row_idx%W_FE] == 0:
            singular = True
            piv_inverse = 0
          else:
            piv_inverse = L_slice[pivot_row_idx, pivot_row_idx%W_FE]**-1

          L_slice[pivot_row_idx,:] = L_slice[pivot_row_idx,:] * piv_inverse
          L.set_block(0, slice_idx*W_FE, L_slice)

          # remaining slices:
          for slice_idx in range(slice_start_idx+1, nr_slices):
            L_slice = L[:,slice_idx*W_FE:(slice_idx+1)*W_FE]
            if taken_idx is not None:
              L_slice[pivot_row_idx,:] += L_slice[taken_idx,:]

            L_slice[pivot_row_idx,:] = L_slice[pivot_row_idx,:] * piv_inverse
            L.set_block(0, slice_idx*W_FE, L_slice)

          # multiply and add pivot row to other rows:
          for row_idx in range(pivot_row_idx+1, self.m):
            val = L[row_idx, pivot_row_idx]
            for slice_idx in range(slice_start_idx, nr_slices):
              L_slice = L[:,slice_idx*W_FE:(slice_idx+1)*W_FE]
              L_slice[row_idx,:] += val * L_slice[pivot_row_idx,:]
              L.set_block(0, slice_idx*W_FE, L_slice)

        return L if not singular else None

  def _backSubstitution(self,B,y):
    ''' Implementation of back substitution computation as done in hardware '''
    assert B.nrows() == self.m
    assert B.ncols() == self.m

    for slice_idx in range(self.m-1,-1,-1):
      yl = y[slice_idx]
      for row_idx in range(0,slice_idx,1):
        y[row_idx] += yl*B[row_idx,slice_idx]

    return matrix(self.F, self.m, 1, list(y))
      
  def _gaussianElimination(self, A, y):
        ''' Implementation of Gaussian Elimination as done in hardware '''

        augmented_matrix = A.augment(matrix(self.m,1,y))
        ef_matrix = self._echelonForm(augmented_matrix)
        if augmented_matrix is None:
          return None

        A = ef_matrix[:,0:self.m]
        y = ef_matrix.column(self.m)

        last_row_zero = True
        for i in range(self.m):
            if A[self.m-1,i] != 0:
                last_row_zero = False
                break

        if last_row_zero:
            return None

        return self._backSubstitution(A,y)
    
  def sign(self, esk, msg, cpk, debug_output=False):
    ''' UOV's signing operation using esk with message msg. If debug_output is enabled,
        the data is written to files used for hardware testing '''

    salt = salt_func(self.salt_len//8)
    seed_sk = esk[0]

    # Hash message into vector t:
    hash_in_bytes = msg + salt + seed_sk
    if debug_output:
      writeElements("hash_in_ref_" + self.name, hash_in_bytes)

    t = self.hashVector(msg + salt, self.m)
    if debug_output:
      writeElements("t_ref_" + self.name, [_[0].to_integer() for _ in t])

    # Take a random seed for blinding:
    blinding_aes_seed = randbytes(self.pk_seed_len // 8)
    if debug_output:
      writeElements("seed_bl_" + self.name, blinding_aes_seed)

    # UOV's main signing loop
    for ctr in range(256):
      # Sample vinegar vector v:
      v = self.hashVector(msg + salt + esk[0] + ctr.to_bytes(1, 'little'), self.v)
      if debug_output:
        writeElements("v_ref_" + self.name, [_[0].to_integer() for _ in v])

      # Perform blinding operation:
      O_bar = esk[1]
      R = self._getRandomLUMatrix(blinding_aes_seed, ctr)
      O_bar_blinded = O_bar * R

      # Compute linear equation system matrix L
      L = matrix(self.F, self.m,self.m)
      P1, P2 = self._expandP(cpk[0])
      for i in range(self.m):
        T = v.transpose() * block_matrix(1,2,[P1[i]+P1[i].transpose(),P2[i]])
        L[i,:] = T * O_bar_blinded

      if debug_output:
        writeMatrix("O_ref_" + self.name, O_bar)
        writeMatrix("R_ref_" + self.name, R)
        writeMatrix("Ob_ref_" + self.name, O_bar_blinded)

      # Compute RHS of linear equation system
      y = [(v.transpose() * P1[i] * v)[0,0] for i in range(self.m)]
      y = matrix(self.F, self.m, 1, y)
      t_minus_y = t-y      

      # Solve the equation system
      x = self._gaussianElimination(L, t_minus_y)

      if x is not None:
         if debug_output:
          writeVector("y_ref_" + self.name, x)

         # Compute the signature s:
         s = block_matrix([[v],[matrix(self.F, self.m, 1)]]) + O_bar_blinded * x
         if debug_output:
          writeVector("s_ref_" + self.name, s)
         return s, salt
      
      elif debug_output:
        print("ERROR! No solution exists on the first try. Take another seed by re-executing this script")
        assert False

    print("This must not be reached!")
    assert False

  def verify(self, epk, msg, s, salt):
    ''' Verification of UOV using the epk, message msg, signature s, and salt '''
    t = self.hashVector(msg + salt, self.m)
    P = epk[0]
    t_p = matrix(self.F, self.m, 1)
    ok = 1
    for i in range(self.m):
       t_p[i,0] = (s.transpose() * P[i] * s)[0,0]
       if t[i,0] != t_p[i,0]:
          print("Error:", i, t[i,0], t_p[i,0])
          ok = 0
    return ok


def readKATfile(path):
  ''' This reads the KAT file in path and returnes the prepared test vectors tv '''
  with open(path, "r") as f:
    print(f.readline())
    lines = f.readlines()
    tv = []
    for i in range(len(lines)):
      if not lines[i].startswith("count = "):
        continue
      
      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "seed"
      seed_prng = int(splits[1], 16).to_bytes(48, 'big')

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "mlen"
      mlen = int(splits[1])

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "msg"
      msg = int(splits[1], 16).to_bytes(mlen, 'big')

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "pk"
      pk = splits[1][:-1]

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "sk"
      sk = splits[1][:-1]

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "smlen"
      smlen = int(splits[1])

      i += 1
      splits = lines[i].split(" = ")
      assert splits[0] == "sm"
      sm = splits[1][:-1]

      tv += [(seed_prng, mlen, msg, pk, sk, smlen, sm)]
    return tv

def katTest(file, uov_name, compact, doBlinding=False):
  ''' This reads the KAT file file with the UOV configuration given by uov_name. Compact selects between
      compact and expanded key variants. The KAT data is compared against this implementation,
       either with enabled or disabled blinding '''
  
  print("Test", uov_name, "pkc-skc" if compact else "classic")

  uov = UOV(DEFAULT_PARAMETERS[uov_name], doBlinding) # Create UOV instance with specified parameters
  tv = readKATfile(file) # Read the KAT file

  for i,t in enumerate(tv[:NUM_KAT_TESTS]):
    global salt_func
    salt_func = NIST_KAT_DRBG(t[0]).random_bytes
    
    msg = t[2] 
    csk, cpk = uov.compactKeyGen()
    esk = uov.expandSK(csk)
    epk = uov.expandPK(cpk)
    s, salt = uov.sign(esk, msg, cpk)
    assert uov.verify(epk, msg, s, salt)

    if compact:
      if csk.hex().upper() != t[4]:
        print("error csk", i, csk.hex().upper())
        print("           ", t[4])
        exit(1)
      assert cpk[0].hex().upper() + uov.matrixToBytes(cpk[1], True).hex().upper() == t[3]
    else:
      if not uov.doBlinding: # TODO
        esk_string = esk[0].hex().upper()
        esk_string += uov.matrixToBytesColMaj([esk[1][:uov.v,:uov.m]]).hex().upper()
        esk_string += uov.matrixToBytes(esk[2], True).hex().upper()
        esk_string += uov.matrixToBytes(esk[3], False).hex().upper()
        assert esk_string == t[4]


      epk_string = uov.matrixToBytes(epk[1], True).hex().upper()
      epk_string += uov.matrixToBytes(epk[2], False).hex().upper()
      epk_string += uov.matrixToBytes(epk[3], True).hex().upper()
      assert epk_string == t[3]

    if (msg + uov.matrixToBytes([s],False) + salt).hex().upper() != t[6]:
       print("error sig", i, (msg + uov.matrixToBytes([s],False) + salt).hex().upper())
       print("          ", t[6])
       exit(2)

def writeUOVTests(sec_lvl, msg_len):
  ''' Executes UOV to generate hardware test vectors for sec_lvl and msg_len '''

  uov = UOV(DEFAULT_PARAMETERS[sec_lvl], True)
  csk, cpk = uov.compactKeyGen()
  esk = uov.expandSK(csk)
  epk = uov.expandPK(cpk)
  _, _, _, P3 = epk

  seed_pk = cpk[0]
  writeElements("seed_pk_" + sec_lvl, seed_pk)
  
  with open(OUTPUT_PATH+"p3_ref_"+ sec_lvl +"_normalOrder.txt", "w") as f:
    for r in range(uov.m):
      for c in range(r,uov.m):
        for m in range(0,uov.m,16):
          p3_slice = P3[m:m+16]
          f.write(str(m) + " " + str(r) + " " + str(c) + " ")
          for _ in range(16):
            if _ + m < uov.m:
              f.write(hex(p3_slice[_][r,c].to_integer())[2:] + " ")
            else:
              f.write("0" + " ")
          f.write("\n")

  msg = randbytes(msg_len)
  s, salt = uov.sign(esk, msg, cpk, True)
  assert uov.verify(epk, msg, s, salt) == 1

  # invalid0: single corrupted element -> must fail verification
  s[randint(0,uov.n-1),0] += uov.F(1)
  writeVector("signature_invalid1_" + sec_lvl, s)

  # invalid1: fully random vector -> must fail verification
  s = random_matrix(uov.F, uov.n, 1)
  writeVector("signature_invalid2_" + sec_lvl, s)


if __name__=="__main__":
  global salt_func
  salt_func = NIST_KAT_DRBG(randbytes(48)).random_bytes

  # Generate reference data for testing the hardware:
  print("Generate reference data for testing the hardware...")
  msg_len = 15 # message length in bytes
  writeUOVTests("uov-Ip",  msg_len)
  writeUOVTests("uov-III", msg_len)
  writeUOVTests("uov-V",   msg_len)
  writeUOVTests("uov-toy", msg_len)

  # Check this implementation against the KAT tests:
  print("Check the implementation against KAT files...")
  katTest(KAT_PATH + "/Ip-pkc-skc/PQCsignKAT_32.rsp", "uov-Ip", True)
  katTest(KAT_PATH + "/Ip/PQCsignKAT_237896.rsp",     "uov-Ip", False)

  katTest(KAT_PATH + "/Is-pkc-skc/PQCsignKAT_32.rsp", "uov-Is", True)
  katTest(KAT_PATH + "/Is/PQCsignKAT_348704.rsp",     "uov-Is", False)
  
  katTest(KAT_PATH + "/III-pkc-skc/PQCsignKAT_32.rsp", "uov-III", True)
  katTest(KAT_PATH + "/III/PQCsignKAT_1044320.rsp",    "uov-III", False)

  katTest(KAT_PATH + "/V-pkc-skc/PQCsignKAT_32.rsp", "uov-V", True)

  print("SUCCESS: Tests generated and compared to KAT data")
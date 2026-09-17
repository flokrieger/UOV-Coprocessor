# my implementation of the UOV signature scheme.

from sage.all import GF, matrix, block_matrix, identity_matrix, random_matrix, vector, diagonal_matrix, PolynomialRing
from sage.misc.randstate import set_random_seed
from sage.matrix.constructor import random_matrix
from random import randint, seed, randbytes
from math import log2,ceil 
from hashlib import shake_256
from Crypto.Cipher import AES
from Crypto.Util import Counter

PATH = "./data/"

class NIST_KAT_DRBG:
    """ AES-256 CTR to extract "fake" DRBG outputs that are compatible with
        the randombytes() call in the NIST KAT testing suite."""

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


#   test bench

# The parameters for the MAYO variants. They are:
# q (the size of the finite field F_q), m (the number of multivariate quadratic polynomials in the public key),
# n (the number of variables in the multivariate quadratic polynomials in the public key),
# o (the dimension of the oil space), k (the whipping parameter)
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


class UOV:
  def __init__(self, parameter_set, randomizeO=False, randomizeP=False):
    self.randomizeO = randomizeO
    self.randomizeP = randomizeP
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
    O = self.bytesToMatrixRowMaj(bytestring[self.pk_seed_len//8:],self.v,self.m, False, 1)[0]

    return seed_pk, O

  def matrixToBytesRowMaj(self, matrices, triangular):
    n_mat = len(matrices)
    rows = matrices[0].nrows()
    cols = matrices[0].ncols()

    out = bytearray()
    for c in range(cols):
      for r in range(c+1 if triangular else rows):
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

  def bytesToMatrixRowMaj(self, bytestring, rows, cols, triangular, n_mat):
    idx = 0
    mats = [matrix(self.F, rows, cols) for _ in range(n_mat)]

    if self.logq == 8:
      elements = bytestring
    else:
      elements = self.bytesToNibbles(bytestring)

    for c in range(cols):
        
        for r in range(c+1 if triangular else rows):
            for i in range(n_mat):
                mats[i][r, c] = self.F.from_integer(elements[idx])
                idx += 1

        if triangular:
            # explicitly zero below diagonal in this column
            for r in range(c + 1, rows):
                for i in range(n_mat):
                    mats[i][r, c] = self.F(0)

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

  def _expandP(self,seed_pk):
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
  
  def _upperInverse(self, mat):
    assert mat.nrows() == mat.ncols()
    denseMat = matrix(self.F, mat.nrows(), mat.nrows())
    for j in range(0, mat.nrows()):
      denseMat[j,j] = mat[j,j]
      for k in range(j+1, mat.nrows()):
        rand = self.F.random_element()
        denseMat[j, k] = mat[j,k] + rand
        denseMat[k, j] = rand

    assert (self._upper(denseMat) - mat).is_zero()
    return denseMat

  
  def compactKeyGen(self, seed_sk=None):
    if seed_sk is None:
      seed_sk = salt_func(self.sk_seed_len//8)
      # print(seed_sk.hex())

    seed_pk, O = self._expandSK(seed_sk)
    P1, P2 = self._expandP(seed_pk)

    P3 = [self._upper(-O.transpose() * P1[i] * O - O.transpose() * P2[i]) for i in range(self.m)]

    cpk = (seed_pk, P3)
    csk = seed_sk

    return csk, cpk
  
  def _random_invertible_matrix(self, size):
    while True:
        M = random_matrix(self.F, size, size)
        if M.is_invertible():
            return M
  def _random_singular_matrix(self, size):
    M = random_matrix(self.F, size, size) * diagonal_matrix(self.F, [self.F(0)] + [self.F.random_element() for _ in range(self.m-1)])
    assert not M.is_invertible()
    return M

  def expandSK(self, csk):
    seed_pk, O = self._expandSK(csk)
    P1, P2 = self._expandP(seed_pk)

    if self.randomizeO:
      O_t = block_matrix([[O], [identity_matrix(self.F, self.m)]])
      H = diagonal_matrix(self.F, [self.F.random_element() or self.F(1) for _ in range(self.m)]) # hiding matrix. Or is it blinding??
      H = self._random_invertible_matrix(self.m)
      H2 = self._random_invertible_matrix(self.m)
      # H = self._random_singular_matrix(self.m) # this will fail
      O_t = O_t*H
      S = [(block_matrix([[P1[i]+P1[i].transpose(), P2[i]]]) * O_t * H2)  for i in range(self.m)]
      esk = (csk, O_t*H2, P1, S)
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
  
  def hashVec(self, msg, length):
    t_prime = shake_256(msg).digest(int(length*int(log2(self.q))//8))
    if self.q == 16:
      t = [self.F.from_integer((t_prime[i//2] >> 4*(i&1)) % 2**4) for i in range(length)]
    else:
      t = [self.F.from_integer(t_prime[i]) for i in range(length)]
    return matrix(self.F, length, 1, t)
  

  def _ef(self,B):
        return self._my_ef(B)
        B = copy(B)
        assert B.nrows() == self.m
        assert B.ncols() == self.m + 1

        RS = B.row_space()

        pivot_row = 0
        pivot_col = 0
        while pivot_row < self.m and pivot_col < self.m + 1:
            next_pivot_row = pivot_row
            while next_pivot_row < self.m and B[next_pivot_row,pivot_col] == 0:
                next_pivot_row += 1
            if next_pivot_row == self.m:
                pivot_col += 1
            else:
                if next_pivot_row > pivot_row:
                    B.swap_rows(next_pivot_row, pivot_row)

                if B.row_space() != RS:
                    print("OOPS1")
                    return

                B.set_row(pivot_row, B.row(pivot_row)*B[pivot_row,pivot_col]^(-1))

                if B.row_space() != RS:
                    print("OOPS2")
                    return

                for row in range(pivot_row + 1, self.m):
                    for col in range(pivot_col+1, self.m + 1):
                        B[row,col] -= B[pivot_row,col]*B[row,pivot_col]
                    B[row,pivot_col] = 0
                    if B.row_space() != RS:
                        print("OOPS3", row)
                        return

                pivot_row += 1
                pivot_col += 1
        return B
  
  def _my_ef(self,B):
        assert B.nrows() == self.m
        assert B.ncols() == self.m + 1

        L = B
        singular = False
        W_FE = 128 // self.logq  # 16 for GF(256), 32 for GF(16)
        nr_slices = self.m // W_FE + 1  # +1 covers the augmented RHS column
        for pivot_row_idx in range(self.m):
          taken_idx = None
          slice_start_idx = pivot_row_idx // W_FE

          # conditionally add all elements to get non-zero pivot
          # first slice differs:
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
          # possible early out here. Do this later, ignore this for now

          L_slice[pivot_row_idx,:] = L_slice[pivot_row_idx,:] * piv_inverse
          L.set_block(0, slice_idx*W_FE, L_slice)  # write back: slice is a copy in Sage

          # remaining slices:
          for slice_idx in range(slice_start_idx+1, nr_slices):
            L_slice = L[:,slice_idx*W_FE:(slice_idx+1)*W_FE]
            if taken_idx is not None:
              L_slice[pivot_row_idx,:] += L_slice[taken_idx,:]

            L_slice[pivot_row_idx,:] = L_slice[pivot_row_idx,:] * piv_inverse
            L.set_block(0, slice_idx*W_FE, L_slice)  # write back: slice is a copy in Sage

          # multiply and add pivot row to other rows:
          for row_idx in range(pivot_row_idx+1, self.m):
            val = L[row_idx, pivot_row_idx]
            for slice_idx in range(slice_start_idx, nr_slices):
              L_slice = L[:,slice_idx*W_FE:(slice_idx+1)*W_FE]
              L_slice[row_idx,:] += val * L_slice[pivot_row_idx,:]
              L.set_block(0, slice_idx*W_FE, L_slice)  # write back

        return L if not singular else None

  def _my_bs(self,B,y):
    assert B.nrows() == self.m
    assert B.ncols() == self.m


    for slice_idx in range(self.m-1,-1,-1):
      yl = y[slice_idx]
      for row_idx in range(0,slice_idx,1):
        y[row_idx] += yl*B[row_idx,slice_idx]

    return matrix(self.F, self.m, 1, list(y))
      
  def _sample_solution(self, A, y, r):
        """
        takes as input a matrix A in F_q^{m x n} of rank m with n >= m,
        a vector y in F_q^m, and a vector r in F_q^n
        and outputs a solution x such that Ax = y
        """

        use_sage_linear_albegra = False

        if use_sage_linear_albegra:
            if A.rank() != self.m:
                return None
            x = A.solve_right(y - A*r)

            assert A*x == y - A*r
            return x + r

        # Above is the easy 'SAGE' way. To test if the spec is correct, we implement it below without using A.solve_right
        x = r
        y -= A*r

        Augmented_matrix = A.augment(matrix(self.m,1,y))
        Augmented_matrix = self._ef(Augmented_matrix)
        if Augmented_matrix is None:
          return None

        A = Augmented_matrix[:,0:self.m]
        y = Augmented_matrix.column(self.m)

        last_row_zero = True
        for i in range(self.m):
            if A[self.m-1,i] != 0:
                last_row_zero = False
                break

        if last_row_zero:
            return None

        return self._my_bs(A,y)
        for r in range(self.m-1,-1,-1):
            c = 0
            while A[r,c] == 0:
                c += 1
            x[c, 0] += y[r]
            y -= vector(y[r]*A[:,c])

        return x
  
  def _upper_lower_triag_random_matrix(self, blinding_aes_seed, ctr=0):
    # Mirrors the HLS L/U sampling (memorySubsystem OL/OLU): L and U are produced on the fly
    # from one AES-CTR keystream, addressed exactly like getPElement (slice = ctr -> byte entry*m + slice_off).
    # The blinding seed (AES key) is sampled once per sign() and passed in fixed; only the resample
    # counter ctr selects the keystream slice (slice_idx = ctr & 7 in HLS), so each retry yields
    # different L/U -- matching the fixed-key hardware.
    #   L : unit lower-triangular. L[i][j] (i>j) <- P1-region byte; L[i][i] = 1.
    #   U : upper-triangular.      U[i][j] (i<j) <- P2-region byte;
    #       U[i][i] = first nonzero of 4 consecutive keystream bytes (else the 4th)  -> nonzero diagonal.
    # R = L*U is the (invertible) blinding matrix returned for Ob = O*R.
    m, v = self.m, self.v

    slice_off = (ctr % 8) * 16                                 # HLS slice_idx = ap_uint<3>(ctr) -> byte_off += slice*16
    p1_bytes  = (v * (v + 1) // 2) * m                         # P1 keystream region size (matches getPElement)
    ks_len    = p1_bytes + m * m * m + 8 * 16 + 16             # covers the largest U offset + slice + diagonal lookahead
    ks        = aes_ctr_prng(blinding_aes_seed, bytes([0] * 16), ks_len)

    L = matrix(self.F, m, m)
    U = matrix(self.F, m, m)

    # L: strict-lower from the P1 region (p1_p2_sel=0), entry = v*c - c(c+1)/2 + r  with r=row=i, c=col=j
    for i in range(m):
      L[i, i] = self.F(1)
      for j in range(i):                                       # i > j
        entry = v * j - j * (j + 1) // 2 + i
        L[i, j] = self.F.from_integer(ks[entry * m + slice_off] % self.q)

    # U: from the P2 region (p1_p2_sel=1), entry = c*m + r  with r=row=i, c=col=j
    for j in range(m):
      for i in range(j):                                       # i < j (strict upper)
        U[i, j] = self.F.from_integer(ks[p1_bytes + (j * m + i) * m + slice_off] % self.q)
      off = p1_bytes + (j * m + j) * m + slice_off             # diagonal entry, with nonzero patch
      b = [ks[off + k] % self.q for k in range(4)]             # reduce mod q first (so nonzero test is in-field)
      nz = b[0] if b[0] else b[1] if b[1] else b[2] if b[2] else b[3]
      U[j, j] = self.F.from_integer(nz)

    return L * U
  
  def sign(self, esk, msg, cpk=None, debug_output=False):
    salt = salt_func(self.salt_len//8)
    # print("salt", salt.hex())
    seed_sk = esk[0]
    hash_in_bytes = msg + salt + seed_sk
    if debug_output:
      with open(PATH+"hash_in_ref_" + self.name + ".txt", "w") as f: # per level: salt and seed_sk values differ per sign
        for _ in hash_in_bytes:
          f.write(hex(_)[2:] + " ")

    t = self.hashVec(msg + salt, self.m)
    if debug_output:
      with open(PATH+"t_ref_" + self.name + ".txt", "w") as f:
        for _ in t:
          f.write(hex(_[0].to_integer())[2:] + " ")

    # Blinding seed (AES key) sampled once and held constant across all ctr retries; only the
    # keystream slice varies with ctr (mirrors the fixed-key hardware).
    blinding_aes_seed = randbytes(self.pk_seed_len // 8) if cpk is not None else None
    if debug_output and cpk is not None:
      with open(PATH+"seed_bl_" + self.name + ".txt", "w") as f:
        for _ in blinding_aes_seed:
          f.write(hex(_)[2:] + " ")

    for ctr in range(256):
      v = self.hashVec(msg + salt + esk[0] + ctr.to_bytes(1, 'little'), self.v)
      if debug_output:
        with open(PATH+"v_ref_" + self.name + ".txt", "w") as f:
          for _ in v:
            f.write(hex(_[0].to_integer())[2:] + " ")

      # T = self._random_invertible_matrix(self.v)
      # vb = T * v
      L = matrix(self.F, self.m,self.m)
      if cpk is None:
        Ob = None
        for i in range(self.m):
          Si = esk[3][i]
          R = self._random_invertible_matrix(self.v) if self.randomizeP else identity_matrix(self.F, self.v)
          R_inv = R.inverse() 
          L[i,:] = (v.transpose() * R_inv) * (R * Si)
      else:
        P, P1, P2, P3 = self.expandPK(cpk)
        O = esk[1]
        R = self._upper_lower_triag_random_matrix(blinding_aes_seed, ctr)
        # R = self._random_invertible_matrix(self.m) 
        # R = diagonal_matrix(self.F, [self.F.random_element() or self.F(1) for _ in range(self.m)])
        # R = identity_matrix(self.F, self.m) * (self.F.random_element() or self.F(1))
        Ob = O * R
        for i in range(self.m):
          T = v.transpose() * block_matrix(1,2,[P1[i]+P1[i].transpose(),P2[i]])
          L[i,:] = T * Ob
        
        if debug_output:
          with open(PATH+"O_ref_" + self.name + ".txt", "w") as f:
            for r in range(self.m):
              for c in range(self.n):
                f.write(str(r) + " " + str(c) + " " + hex(O[c,r].to_integer())[2:] + "\n")

          with open(PATH+"R_ref_" + self.name + ".txt", "w") as f:
            for r in range(self.m):
              for c in range(self.m):
                f.write(str(r) + " " + str(c) + " " + hex(R[c,r].to_integer())[2:] + "\n")
          
          with open(PATH+"Ob_ref_" + self.name + ".txt", "w") as f:
            for r in range(self.m):
              for c in range(self.n):
                f.write(str(r) + " " + str(c) + " " + hex(Ob[c,r].to_integer())[2:] + "\n")

          with open(PATH+"L_ref_" + self.name + ".txt", "w") as f:
            for r in range(self.m):
              for c in range(self.m):
                f.write(str(r) + " " + str(c) + " " + hex(L[c,r].to_integer())[2:] + "\n")
          
      
      P1 = esk[2]
      # D = [diagonal_matrix(self.F, [self.F.random_element() or self.F(1) for _ in range(self.v)]) for _ in range(self.m)]
      # D_inv = [d.inverse() for d in D]
      # P1_dense = [self._upperInverse(P1[_]) for _ in range(self.m)]

      # y = [(vb.transpose()* T.inverse().transpose() * R * R_inv * P1[i] * T.inverse() * vb)[0,0] for i in range(self.m)] # Works
      # y = [(v.transpose() * D[i] * D_inv[i] * P1_dense[i] * v)[0,0] for i in range(self.m)] # Works
      y = [(v.transpose() * P1[i] * v)[0,0] for i in range(self.m)] # Works
      # ones_upper = matrix(self.F, self.v, self.v, 
      #        [[self.F(1) if row <= col else self.F(0) 
      #          for col in range(self.v)] 
      #         for row in range(self.v)])
      # y = [(v.transpose() *ones_upper* v)[0,0] for i in range(self.m)] # Works
      y = matrix(self.F, self.m, 1, y)
      t_minus_y = t-y      

      x = self._sample_solution(L, t_minus_y, matrix(self.F, self.m, 1))

      if debug_output:
        with open(PATH+"y_ref_" + self.name + ".txt", "w") as f:
          for r in range(self.m):
            f.write(str(r) + " " + hex(x[r,0].to_integer())[2:] + "\n")

      if x is not None:
         O_I = esk[1] if Ob is None else Ob
         s = block_matrix([[v],[matrix(self.F, self.m, 1)]]) + O_I * x
         if debug_output:
          s_tmp = s # use this if GE is not performed: block_matrix([[v],[matrix(self.F, self.m, 1)]]) + O_I * (t-y)
          with open(PATH+"s_ref_" + self.name + ".txt", "w") as f:
            for r in range(self.n):
              f.write(str(r) + " " + hex(s_tmp[r,0].to_integer())[2:] + "\n")
         return s, salt
      elif debug_output:
        print("ERROR! No solution exists on the first try. Take another seed by re-executing this script")
        assert False
    
    assert False

  def verify(self, epk, msg, s, salt):
    t = self.hashVec(msg + salt, self.m)
    P = epk[0]
    t_p = matrix(self.F, self.m, 1)
    ok = 1
    for i in range(self.m):
       t_p[i,0] = (s.transpose() * P[i] * s)[0,0]
       if t[i,0] != t_p[i,0]:
          print("Error:", i, t[i,0], t_p[i,0])
          ok = 0
    return ok


def testUOV(param):
  uov   = UOV(DEFAULT_PARAMETERS[param], False)
  uov_h = UOV(DEFAULT_PARAMETERS[param], True)

  seed(1234)
  csk, cpk = uov.compactKeyGen()
  seed(1234)
  csk_h, cpk_h = uov_h.compactKeyGen()
  assert csk == csk_h and cpk == cpk_h
  
  set_random_seed(456)
  seed(789)
  esk = uov.expandSK(csk)
  epk = uov.expandPK(cpk)
  set_random_seed(456)
  seed(789)
  esk_h = uov_h.expandSK(csk_h)
  epk_h = uov_h.expandPK(cpk_h)
  assert epk == epk_h

  seed(1234)
  msg = randbytes(8)

  seed(1234)
  s, salt = uov.sign(esk, msg)
  seed(1234)
  s_h, salt_h = uov_h.sign(esk_h, msg)
  assert salt == salt_h
  assert s == s_h

  ret = uov.verify(epk, msg, s, salt)
  ret_h = uov_h.verify(epk_h, msg, s_h, salt_h)
  assert ret == ret_h
  print("Result: ", ret)

def find_string_in_file(filename, search_string):
    """
    Opens a file and returns the line number (1-based) where search_string is found.
    Returns None if not found.
    """
    try:
        with open(filename, 'r') as file:
            for line_num, line in enumerate(file, 1):
                if search_string in line:
                    return line_num
        assert False # not in file
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        assert False


def readKATfile(path):
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

def katTest(file, uov_name, compact):
  print("Test", uov_name, "pkc-skc" if compact else "classic")

  uov = UOV(DEFAULT_PARAMETERS[uov_name], True, True)
  tv = readKATfile(file) 
  for i,t in enumerate(tv[:4]):
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
      if not uov.randomizeO:
        esk_string = esk[0].hex().upper()
        esk_string += uov.matrixToBytesRowMaj([esk[1][:uov.v,:uov.m]], False).hex().upper()
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

def writeGETests(sec_lvl):
  uov = UOV(DEFAULT_PARAMETERS[sec_lvl])
  csk, cpk = uov.compactKeyGen()
  
  # random_invertible
  L_in = random_matrix(uov.F, uov.m, uov.m+1)
  while L_in.rank() != uov.m:
    L_in = random_matrix(uov.F, uov.m, uov.m+1)
  with open(PATH+"L_ef_input_0_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_input_0_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  L_ef = uov._ef(L_in)
  with open(PATH+"L_ef_output_0_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_ef[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_output_0_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  y_out = uov._my_bs(L_ef[:,:-1], L_ef[:,-1])
  with open(PATH+"y_bs_output_0_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      f.write(str(r) + " " + hex(y_out[r,0].to_integer())[2:] + "\n")

  # random_invertible
  L_in = random_matrix(uov.F, uov.m, uov.m+1)
  while L_in.rank() != uov.m:
    L_in = random_matrix(uov.F, uov.m, uov.m+1)
  with open(PATH+"L_ef_input_1_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_input_1_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  L_ef = uov._ef(L_in)
  with open(PATH+"L_ef_output_1_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_ef[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_output_1_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  y_out = uov._my_bs(L_ef[:,:-1], L_ef[:,-1])
  with open(PATH+"y_bs_output_1_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      f.write(str(r) + " " + hex(y_out[r,0].to_integer())[2:] + "\n")

  # pivot is zero:
  L_in = random_matrix(uov.F, uov.m, uov.m+1)
  L_in[0,0] = 0
  while L_in.rank() != uov.m:
    L_in = random_matrix(uov.F, uov.m, uov.m+1)
    L_in[0,0] = 0
  with open(PATH+"L_ef_input_2_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_input_2_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  L_ef = uov._ef(L_in)
  with open(PATH+"L_ef_output_2_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_ef[c,r].to_integer())[2:] + "\n")
  with open(PATH+"y_ef_output_2_" + sec_lvl + ".txt", "w") as f:
    r = uov.m
    for c in range(uov.m):
      f.write(str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  y_out = uov._my_bs(L_ef[:,:-1], L_ef[:,-1])
  with open(PATH+"y_bs_output_2_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      f.write(str(r) + " " + hex(y_out[r,0].to_integer())[2:] + "\n")

  #singluar:
  L_in = random_matrix(uov.F, uov.m, uov.m+1)
  while L_in.rank() == uov.m:
    L_in = random_matrix(uov.F, uov.m, uov.m+1)
  with open(PATH+"L_ef_input_3_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  L_ef = uov._ef(L_in)
  assert L_ef is None

  #singluar:
  L_in = random_matrix(uov.F, uov.m, uov.m+1)
  while L_in.rank() == uov.m:
    L_in = random_matrix(uov.F, uov.m, uov.m+1)
  with open(PATH+"L_ef_input_4_" + sec_lvl + ".txt", "w") as f:
    for r in range(uov.m):
      for c in range(uov.m):
        f.write(str(r) + " " + str(c) + " " + hex(L_in[c,r].to_integer())[2:] + "\n")
  L_ef = uov._ef(L_in)
  assert L_ef is None

def writePElementTests(sec_lvl):
  uov = UOV(DEFAULT_PARAMETERS[sec_lvl])
  csk, cpk = uov.compactKeyGen()
  seed_pk = cpk[0]
  P, P1, P2, P3 = uov.expandPK(cpk)

  with open(PATH+"pk_bytestring_ref_"+ sec_lvl +".txt", "w") as f:
    for _ in seed_pk:
      f.write(hex(_)[2:] + " ")
    f.write("\n")
    p1_nonzero_el = uov.v*(uov.v+1)//2
    bytestring = aes_ctr_prng(seed_pk, bytes([0]*(128//8)), (p1_nonzero_el + uov.v*uov.m)*uov.logq//8*uov.m)
    for _ in bytestring:
      f.write(hex(_)[2:] + " ")
  
  with open(PATH+"pk_p1_ref_"+ sec_lvl +".txt", "w") as f:
    for _ in seed_pk:
      f.write(hex(_)[2:] + " ")
    f.write("\n")
    for m in range(0,uov.m,16):
      p1_slice = P1[m:m+16]
      for r in range(uov.v):
        for c in range(r+1):
          f.write(str(m) + " " + str(r) + " " + str(c) + " ")
          for _ in range(16):
            if _ + m < uov.m:
              f.write(hex(p1_slice[_][c,r].to_integer())[2:] + " ")
            else:
              f.write("0" + " ")
          f.write("\n")  

  with open(PATH+"pk_p2_ref_"+ sec_lvl +".txt", "w") as f:
    for _ in seed_pk:
      f.write(hex(_)[2:] + " ")
    f.write("\n")
    for m in range(0,uov.m,16):
      p2_slice = P2[m:m+16]
      for r in range(uov.m):
        for c in range(uov.v):
          f.write(str(m) + " " + str(r) + " " + str(c) + " ")
          for _ in range(16):
            if _ + m < uov.m:
              f.write(hex(p2_slice[_][c,r].to_integer())[2:] + " ")
            else:
              f.write("0" + " ")
          f.write("\n")  

def writeUOVTests(sec_lvl,msg_len):
  uov = UOV(DEFAULT_PARAMETERS[sec_lvl])
  csk, cpk = uov.compactKeyGen()
  esk = uov.expandSK(csk)
  epk = uov.expandPK(cpk)
  P, P1, P2, P3 = epk

  # for _ in range(1,uov.q):
  #   print(hex((uov.F.from_integer(_)**-1).to_integer()))

  seed_pk = cpk[0]
  with open(PATH+"seed_pk_"+ sec_lvl +".txt", "w") as f:
    for _ in seed_pk:
      f.write(hex(_)[2:] + " ")
  
  with open(PATH+"p3_ref_"+ sec_lvl +"_reordered.txt", "w") as f:
    for m in range(0,uov.m,16):
      p3_slice = P3[m:m+16]
      for r in range(uov.m):
        for c in range(r+1):
          f.write(str(m) + " " + str(r) + " " + str(c) + " ")
          for _ in range(16):
            if _ + m < uov.m:
              f.write(hex(p3_slice[_][c,r].to_integer())[2:] + " ")
            else:
              f.write("0" + " ")
          f.write("\n")

  with open(PATH+"p3_ref_"+ sec_lvl +"_normalOrder.txt", "w") as f:
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

  # invalid0: a single corrupted element -> must fail verification
  s[randint(0,uov.n-1),0] += uov.F(1)
  with open(PATH+"signature_invalid1_"+ sec_lvl +".txt", "w") as f:
    for r in range(uov.n):
      f.write(str(r) + " " + hex(s[r,0].to_integer())[2:] + "\n")

  # invalid1: a fully random vector -> must fail verification
  s = random_matrix(uov.F, uov.n, 1)
  with open(PATH+"signature_invalid2_"+ sec_lvl +".txt", "w") as f:
    for r in range(uov.n):
      f.write(str(r) + " " + hex(s[r,0].to_integer())[2:] + "\n")


if __name__=="__main__":
  global salt_func
  salt_func = NIST_KAT_DRBG(randbytes(48)).random_bytes

  writePElementTests("uov-Ip")
  writePElementTests("uov-III")
  writePElementTests("uov-V")

  # writeGETests("uov-Ip")
  # writeGETests("uov-III")
  # writeGETests("uov-V")

  msg_len = 15 # message length in bytes, only works for some values 
  writeUOVTests("uov-Ip", msg_len)
  writeUOVTests("uov-III",msg_len)
  writeUOVTests("uov-V",  msg_len)
  writeUOVTests("uov-toy",  msg_len)

  # exit(0)

  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip-pkc-skc/PQCsignKAT_32.rsp", "uov-Ip", True)
  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip/PQCsignKAT_237896.rsp", "uov-Ip", False)

  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Is-pkc-skc/PQCsignKAT_32.rsp", "uov-Is", True)
  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Is/PQCsignKAT_348704.rsp", "uov-Is", False)
  
  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/III-pkc-skc/PQCsignKAT_32.rsp", "uov-III", True)
  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/III/PQCsignKAT_1044320.rsp", "uov-III", False)

  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/V-pkc-skc/PQCsignKAT_32.rsp", "uov-V", True)
  katTest("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/V/PQCsignKAT_2436704.rsp", "uov-V", False)

  exit(0)

  seed_sk = 0x7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D.to_bytes(uov.sk_seed_len//8, 'big')
  mlen = 33
  msg = 0xD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8.to_bytes(mlen, 'big')
  
  #### CSK / CPK
  csk, cpk = uov.compactKeyGen(seed_sk)
  print("csk=", hex(int.from_bytes(csk, 'big')))
  print("cpk=", hex(int.from_bytes(cpk[0], 'big')), "...")
  
  string = csk.hex().upper()
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip-pkc-skc/PQCsignKAT_32.rsp", string))

  string = cpk[0].hex().upper()
  string += uov.matrixToBytes(cpk[1], True).hex().upper()
  print(len(string), string[:16], string[-16:])
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip-pkc-skc/PQCsignKAT_32.rsp", string))
  
  #### ESK / EPK

  esk = uov.expandSK(csk)
  epk, P1, P2, P3 = uov.expandPK(cpk)

  string = esk[0].hex().upper()
  string += uov.matrixToBytesRowMaj([esk[1][:uov.v,:uov.m]], False).hex().upper()
  string += uov.matrixToBytes(esk[2], True).hex().upper()
  string += uov.matrixToBytes(esk[3], False).hex().upper()
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip/PQCsignKAT_237896.rsp", string))

  string = uov.matrixToBytes(P1, True).hex().upper()
  string += uov.matrixToBytes(P2, False).hex().upper()
  string += uov.matrixToBytes(P3, True).hex().upper()
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip/PQCsignKAT_237896.rsp", string))


  #### SIGN
  s, salt = uov.sign(esk, msg)
  
  string = msg.hex().upper()
  string += uov.matrixToBytes([s],False).hex().upper()
  string += salt.hex().upper()
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip/PQCsignKAT_237896.rsp", string))
  print(find_string_in_file("/home/fkrieger/Documents/Projects/Rigoletto/uov_reference/KAT/Ip-pkc-skc/PQCsignKAT_32.rsp", string))



  # testUOV("uov-Ip")
  # testUOV("uov-Is")
  # testUOV("uov-III")
  # testUOV("uov-V")


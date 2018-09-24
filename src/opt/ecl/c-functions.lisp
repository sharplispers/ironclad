;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
#+ecl
(in-package :crypto)

#+(and ecl ironclad-assembly)
(progn
  (ffi:clines "
#define ROTL32(v, c) \\
  (((v) << (c)) | ((v) >> (32 - (c))))

#define CHACHA_QUARTER_ROUND(a, b, c, d) \\
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \\
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \\
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \\
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

#define SALSA_QUARTER_ROUND(a, b, c, d) \\
  x[a] ^= ROTL32(x[d] + x[c], 7); \\
  x[b] ^= ROTL32(x[a] + x[d], 9); \\
  x[c] ^= ROTL32(x[b] + x[a], 13); \\
  x[d] ^= ROTL32(x[c] + x[b], 18);
")
  (declaim (inline x-chacha-core))
  (defun x-chacha-core (n-rounds buffer state)
    (ffi:c-inline (n-rounds buffer state)
                  (:unsigned-int t t)
                  :void
                  "{
unsigned int n_rounds = #0;
uint8_t *buffer = (#1)->array.self.b8;
uint32_t *state = (#2)->array.self.b32;
unsigned int i;
uint32_t x[16];

for(i = 0; i < 16; i++)
  x[i] = state[i];

for(i = 0; i < n_rounds; i++)
{
  CHACHA_QUARTER_ROUND(0, 4, 8, 12);
  CHACHA_QUARTER_ROUND(1, 5, 9, 13);
  CHACHA_QUARTER_ROUND(2, 6, 10, 14);
  CHACHA_QUARTER_ROUND(3, 7, 11, 15);

  CHACHA_QUARTER_ROUND(0, 5, 10, 15);
  CHACHA_QUARTER_ROUND(1, 6, 11, 12);
  CHACHA_QUARTER_ROUND(2, 7, 8, 13);
  CHACHA_QUARTER_ROUND(3, 4, 9, 14);
}

for(i = 0; i < 16; i++)
  x[i] += state[i];

for(i = 0; i < 16; i++)
{
  buffer[4 * i] = x[i] & 0xff;
  buffer[4 * i + 1] = (x[i] >> 8) & 0xff;
  buffer[4 * i + 2] = (x[i] >> 16) & 0xff;
  buffer[4 * i + 3] = (x[i] >> 24) & 0xff;
}
}"))

  (declaim (inline x-salsa-core))
  (defun x-salsa-core (n-rounds buffer state)
    (ffi:c-inline (n-rounds buffer state)
                  (:unsigned-int t t)
                  :void
                  "{
unsigned int n_rounds = #0;
uint8_t *buffer = (#1)->array.self.b8;
uint32_t *state = (#2)->array.self.b32;
unsigned int i;
uint32_t x[16];

for(i = 0; i < 16; i++)
  x[i] = state[i];

for(i = 0; i < n_rounds; i++)
{
  SALSA_QUARTER_ROUND(4, 8, 12, 0);
  SALSA_QUARTER_ROUND(9, 13, 1, 5);
  SALSA_QUARTER_ROUND(14, 2, 6, 10);
  SALSA_QUARTER_ROUND(3, 7, 11, 15);

  SALSA_QUARTER_ROUND(1, 2, 3, 0);
  SALSA_QUARTER_ROUND(6, 7, 4, 5);
  SALSA_QUARTER_ROUND(11, 8, 9, 10);
  SALSA_QUARTER_ROUND(12, 13, 14, 15);
}

for(i = 0; i < 16; i++)
  x[i] += state[i];

for(i = 0; i < 16; i++)
{
  buffer[4 * i] = x[i] & 0xff;
  buffer[4 * i + 1] = (x[i] >> 8) & 0xff;
  buffer[4 * i + 2] = (x[i] >> 16) & 0xff;
  buffer[4 * i + 3] = (x[i] >> 24) & 0xff;
}
}")))

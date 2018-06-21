;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(cl:defpackage :ironclad
  (:use :cl)
  (:nicknames :crypto)
  (:import-from #:nibbles
                #:ub16ref/le #:ub16ref/be
                #:ub32ref/le #:ub32ref/be
                #:ub64ref/le #:ub64ref/be)
  (:export
   ;; referencing multiple-octet values in an octet vector (SETF-able)
   #:ub16ref/be #:ub16ref/le #:ub32ref/be #:ub32ref/le #:ub64ref/le #:ub64ref/be

   ;; hash functions
   #:digest-sequence #:digest-stream #:digest-file
   #:make-digest #:copy-digest #:update-digest #:produce-digest

   ;; MACs
   #:make-mac #:update-mac #:produce-mac

   ;;; Deprecated MAC functions
   ;; HMACs
   #:make-hmac #:update-hmac #:hmac-digest
   ;; CMACs
   #:make-cmac #:update-cmac #:cmac-digest
   ;; Skein-MAC
   #:make-skein-mac #:update-skein-mac #:skein-mac-digest
   ;; Poly1305
   #:make-poly1305 #:update-poly1305 #:poly1305-digest
   ;; Blake2-MAC
   #:make-blake2-mac #:update-blake2-mac #:blake2-mac-digest
   ;; Blake2s-MAC
   #:make-blake2s-mac #:update-blake2s-mac #:blake2s-mac-digest

   ;; introspection
   #:cipher-supported-p #:list-all-ciphers
   #:digest-supported-p #:list-all-digests
   #:mac-supported-p #:list-all-macs
   #:mode-supported-p #:list-all-modes
   #:block-length #:digest-length #:key-lengths
   #:keystream-position

   ;; high-level block cipher operators
   #:make-cipher #:encrypt #:decrypt #:encrypt-in-place #:decrypt-in-place

   ;; arguments to (MAKE-CIPHER ... :MODE X)
   #:ecb #:cbc #:ctr #:ofb #:cfb #:stream

   ;; KDFs
   #:pbkdf1 #:pbkdf2 #:scrypt-kdf #:argon2i
   #:make-kdf #:derive-key

   ;; KDF convenience functions
   #:make-random-salt #:pbkdf2-hash-password
   #:pbkdf2-hash-password-to-combined-string
   #:pbkdf2-check-password

   ;; public-key encryption operations
   #:make-public-key #:destructure-public-key
   #:make-private-key #:destructure-private-key
   #:generate-key-pair
   #:make-signature #:destructure-signature
   #:make-message #:destructure-message
   #:sign-message #:verify-signature
   #:encrypt-message #:decrypt-message
   #:diffie-hellman

   ;; public-key encryption/signature padding
   #:oaep-encode #:oaep-decode #:pss-encode #:pss-verify

   ;; public-key slot readers
   #:dsa-key-p #:dsa-key-q #:dsa-key-g #:dsa-key-y #:dsa-key-x
   #:elgamal-key-p #:elgamal-key-g #:elgamal-key-y #:elgamal-key-x
   #:rsa-key-modulus #:rsa-key-exponent
   #:ed25519-key-x #:ed25519-key-y
   #:ed448-key-x #:ed448-key-y
   #:curve25519-key-x #:curve25519-key-y
   #:curve448-key-x #:curve448-key-y

   ;; pseudo-random number generators
   #:list-all-prngs #:make-prng #:random-data #:read-os-random-seed
   #:read-seed #:write-seed #:random-bits #:*prng* #:strong-random #:prng-reseed

   ;; default OS PRNG
   #:os-prng

   ;; Fortuna PRNG
   #:fortuna-prng #:add-random-event

   ;; Fortuna generator
   #:fortuna-generator

   ;; cryptographic math
   #:generate-prime #:prime-p #:generate-prime-in-range #:egcd
   #:generate-safe-prime #:find-generator

   ;; conditions
   #:ironclad-error #:initialization-vector-not-supplied
   #:invalid-initialization-vector #:invalid-key-length
   #:unsupported-cipher #:unsupported-mode #:unsupported-digest
   #:unsupported-kdf #:unsupported-scrypt-cost-factors
   #:unsupported-argon2i-parameters
   #:insufficient-buffer-space #:invalid-padding
   #:key-not-supplied #:unsupported-mac
   #:invalid-mac-parameter #:invalid-signature-length
   #:invalid-message-length #:missing-key-parameter
   #:missing-message-parameter #:missing-signature-parameter
   #:incompatible-keys #:invalid-curve-point
   #:invalid-public-key-length #:oaep-decoding-error

   ;; utilities
   #:byte-array-to-hex-string #:hex-string-to-byte-array
   #:ascii-string-to-byte-array
   #:octets-to-integer #:integer-to-octets
   #:expt-mod #:expt-mod/unsafe
   #:constant-time-equal

   ;; streams
   #:make-octet-input-stream #:make-octet-output-stream
   #:with-octet-input-stream #:with-octet-output-stream
   #:get-output-stream-octets
   #:make-digesting-stream
   #:execute-with-digesting-stream #:with-digesting-stream
   #:execute-with-digesting-text-stream #:with-digesting-text-stream
   #:make-encrypting-stream #:make-decrypting-stream
   #:with-encrypting-stream #:with-decrypting-stream
   #:make-authenticating-stream #:with-authenticating-stream)
  ;; supported digests
  (:export #:whirlpool #:md2 #:md4 #:md5 #:adler32 #:crc24 #:crc32
           #:tiger #:sha1 #:sha224 #:sha256 #:sha384 #:sha512
           #:tree-hash #:make-tiger-tree-hash #:ripemd-128 #:ripemd-160
           #:skein256 #:skein256/128 #:skein256/160 #:skein256/224
           #:skein512 #:skein512/128 #:skein512/160 #:skein512/224
           #:skein512/256 #:skein512/384
           #:skein1024 #:skein1024/384 #:skein1024/512
           #:sha3 #:sha3/384 #:sha3/256 #:sha3/224
           #:shake128 #:shake256
           #:keccak #:keccak/384 #:keccak/256 #:keccak/224
           #:groestl #:groestl/384 #:groestl/256 #:groestl/224
           #:blake2 #:blake2/384 #:blake2/256 #:blake2/160
           #:blake2s #:blake2s/224 #:blake2s/160 #:blake2s/128
           #:jh #:jh/384 #:jh/256 #:jh/224)
  ;; supported macs
  (:export #:blake2-mac #:blake2s-mac #:cmac #:hmac #:poly1305 #:skein-mac)
  ;; supported block ciphers
  (:export #:blowfish #:tea #:xtea #:square #:rc2 #:rc5 #:rc6 #:des #:3des
           #:aes #:twofish #:cast5 #:idea #:misty1 #:xor
           #:threefish256 #:threefish512 #:threefish1024
           #:serpent #:camellia #:seed #:aria)
  ;; supported stream ciphers
  (:export #:arcfour
           #:salsa20 #:salsa20/12 #:salsa20/8
           #:xsalsa20 #:xsalsa20/12 #:xsalsa20/8
           #:chacha #:chacha/12 #:chacha/8
           #:xchacha #:xchacha/12 #:xchacha/8
           #:sosemanuk))

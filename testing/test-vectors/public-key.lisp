;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :rsa-oaep-encryption (run-test-vector-file :rsa-enc *public-key-encryption-tests*) t)
(rtest:deftest :elgamal-encryption (run-test-vector-file :elgamal-enc *public-key-encryption-tests*) t)

(rtest:deftest :rsa-pss-signature (run-test-vector-file :rsa-sig *public-key-signature-tests*) t)
(rtest:deftest :elgamal-signature (run-test-vector-file :elgamal-sig *public-key-signature-tests*) t)
(rtest:deftest :dsa-signature (run-test-vector-file :dsa *public-key-signature-tests*) t)
(rtest:deftest :ed25519-signature (run-test-vector-file :ed25519 *public-key-signature-tests*) t)

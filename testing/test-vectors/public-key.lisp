;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :rsa-encryption (run-test-vector-file :rsa *public-key-encryption-tests*) t)
(rtest:deftest :elgamal-encryption (run-test-vector-file :elgamal *public-key-encryption-tests*) t)

(rtest:deftest :rsa-signature (run-test-vector-file :rsa *public-key-signature-tests*) t)
(rtest:deftest :elgamal-signature (run-test-vector-file :elgamal *public-key-signature-tests*) t)
(rtest:deftest :dsa-signature (run-test-vector-file :dsa *public-key-signature-tests*) t)
(rtest:deftest :ed25519-signature (run-test-vector-file :ed25519 *public-key-signature-tests*) t)

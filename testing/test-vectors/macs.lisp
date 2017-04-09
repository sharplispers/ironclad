;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :hmac (run-test-vector-file :hmac *mac-tests*) t)
(rtest:deftest :cmac (run-test-vector-file :cmac *mac-tests*) t)
(rtest:deftest :skein-mac (run-test-vector-file :skein-mac *mac-tests*) t)
(rtest:deftest :poly1305 (run-test-vector-file :poly1305 *mac-tests*) t)
(rtest:deftest :blake2-mac (run-test-vector-file :blake2-mac *mac-tests*) t)
(rtest:deftest :blake2s-mac (run-test-vector-file :blake2s-mac *mac-tests*) t)

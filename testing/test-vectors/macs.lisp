;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :hmac (run-test-vector-file :hmac *mac-tests*) t)
(rtest:deftest :cmac (run-test-vector-file :cmac *mac-tests*) t)
(rtest:deftest :skein-mac (run-test-vector-file :skein-mac *mac-tests*) t)

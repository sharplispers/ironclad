;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(rtest:deftest :prng-fortuna (run-test-vector-file :prng *prng-tests*) t)

;;    (random-data (make-prng :fortuna :seed (coerce #(0) 'simple-octet-vector)) 1) #(28))

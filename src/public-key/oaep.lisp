;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; oaep.lisp -- implementation of the optimal asymmetric encryption padding scheme

(in-package :crypto)


;;; Mask generation function
(defun mgf (digest-name seed num-bytes)
  "Expand the SEED to a NUM-BYTES bytes vector using the DIGEST-NAME digest."
  (loop
     with digest-len = (digest-length digest-name)
     with digest = (make-digest digest-name)
     with result = #()
     for counter from 0 to (floor num-bytes digest-len)
     for counter-bytes = (integer-to-octets counter :n-bits 32)
     for tmp = (digest-sequence digest (concatenate '(vector (unsigned-byte 8))
                                                    seed
                                                    counter-bytes))
     do (setf result (concatenate '(vector (unsigned-byte 8)) result tmp))
     finally (return (subseq result 0 num-bytes))))

(defun oaep-encode (digest-name message num-bytes &optional label)
  "Return a NUM-BYTES bytes vector containing the OAEP encoding of the MESSAGE
using the DIGEST-NAME digest (and the optional LABEL octet vector)."
  (let ((digest-len (digest-length digest-name)))
    (assert (<= (length message) (- num-bytes (* 2 digest-len) 2)))
    (let* ((digest (make-digest digest-name))
           (prng (or *prng* (make-prng :fortuna :seed :random)))
           (label (or label (coerce #() '(vector (unsigned-byte 8)))))
           (padding-len (- num-bytes (length message) (* 2 digest-len) 2))
           (padding (make-array padding-len :element-type '(unsigned-byte 8) :initial-element 0))
           (l-hash (digest-sequence digest label))
           (db (concatenate '(vector (unsigned-byte 8)) l-hash padding #(1) message))
           (seed (random-data digest-len prng))
           (db-mask (mgf digest-name seed (- num-bytes digest-len 1)))
           (masked-db (map '(vector (unsigned-byte 8)) #'logxor db db-mask))
           (seed-mask (mgf digest-name masked-db digest-len))
           (masked-seed (map '(vector (unsigned-byte 8)) #'logxor seed seed-mask)))
      (concatenate '(vector (unsigned-byte 8)) #(0) masked-seed masked-db))))

(defun oaep-decode (digest-name message &optional label)
  "Return an octet vector containing the data that was encoded in the MESSAGE with OAEP
using the DIGEST-NAME digest (and the optional LABEL octet vector)."
  (let ((digest-len (digest-length digest-name)))
    (assert (>= (length message) (+ (* 2 digest-len) 2)))
    (let* ((digest (make-digest digest-name))
           (label (or label (coerce #() '(vector (unsigned-byte 8)))))
           (zero-byte (elt message 0))
           (masked-seed (subseq message 1 (1+ digest-len)))
           (masked-db (subseq message (1+ digest-len)))
           (seed-mask (mgf digest-name masked-db digest-len))
           (seed (map '(vector (unsigned-byte 8)) #'logxor masked-seed seed-mask))
           (db-mask (mgf digest-name seed (- (length message) digest-len 1)))
           (db (map '(vector (unsigned-byte 8)) #'logxor masked-db db-mask))
           (l-hash1 (digest-sequence digest label))
           (l-hash2 (subseq db 0 digest-len))
           (padding-len (loop
                           for i from digest-len below (length db)
                           while (zerop (elt db i))
                           finally (return (- i digest-len))))
           (one-byte (elt db (+ digest-len padding-len))))
      (unless (and (zerop zero-byte) (= 1 one-byte) (equalp l-hash1 l-hash2))
        ;; FIXME: "real" ironclad error needed here
        (error "OAEP decoding error"))
      (subseq db (+ digest-len padding-len 1)))))

;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; public-key.lisp -- implementation of common public key components

(in-package :crypto)


(defun list-all-key-pair-kinds ()
  (copy-list '(:curve25519 :curve448 :dsa :ed25519 :ed448 :elgamal
               :rsa :secp256k1 :secp256r1 :secp384r1 :secp521r1)))


;;; class definitions

(defclass discrete-logarithm-group ()
  ((p :initarg :p :reader group-pval)
   (q :initarg :q :reader group-qval)
   (g :initarg :g :reader group-gval)))


;;; Special variable to force the signature nonce during tests instead of
;;; generating a random one.

(defparameter *signature-nonce-for-test* nil)


;;; converting from integers to octet vectors

;;; On 64-bit SBCL, process 7 bytes at a time into fixnum chunks (56 bits
;;; fits in a 62-bit fixnum) to reduce intermediate bignums.  For a 256-byte
;;; RSA key, this produces ~36 intermediate bignums instead of 255, reducing
;;; bignum allocation ~7x.  Other implementations use the portable byte-at-a-
;;; time loop; contributions to extend the optimization are welcome.

#+sbcl
(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  "Convert an octet vector to an integer.  On SBCL, processes 7 bytes at a
time into fixnum chunks to reduce intermediate bignum allocation."
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec)
           (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let* ((end (or end (length octet-vec)))
         (size (- end start)))
    (declare (type fixnum end size start))
    (multiple-value-bind (n-bits n-bytes)
        (if n-bits
            (values n-bits (min (ceiling n-bits 8) size))
            (values (* 8 size) size))
      (declare (type fixnum n-bits n-bytes))
      (cond
        ;; Small case: fits in fixnum (up to 7 bytes / 56 bits)
        ((<= n-bytes 7)
         (if big-endian
             (let ((sum 0))
               (declare (type fixnum sum))
               (loop for i fixnum from (- end n-bytes) below end
                     do (setf sum (the fixnum
                                      (+ (the fixnum (ash sum 8))
                                         (the fixnum (aref octet-vec i))))))
               (ldb (byte n-bits 0) sum))
             (let ((sum 0))
               (declare (type fixnum sum))
               (loop for i fixnum from start below (+ start n-bytes)
                     for j fixnum from 0 by 8
                     do (setf sum (the fixnum
                                      (+ sum (the fixnum
                                                  (ash (the fixnum (aref octet-vec i)) j))))))
               (ldb (byte n-bits 0) sum))))
        ;; Large big-endian: process 7 bytes at a time into fixnum chunks
        (big-endian
         (let ((sum 0)
               (byte-start (- end n-bytes)))
           (declare (type integer sum)
                    (type fixnum byte-start))
           (loop with i fixnum = byte-start
                 while (<= (+ i 7) end) do
                   (let ((chunk 0))
                     (declare (type fixnum chunk))
                     (setf chunk (the fixnum
                                     (logior (the fixnum (ash (the fixnum (aref octet-vec i)) 48))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 1))) 40))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 2))) 32))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 3))) 24))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 4))) 16))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 5))) 8))
                                             (the fixnum (aref octet-vec (+ i 6))))))
                     (setf sum (logior (ash sum 56) chunk)))
                   (incf i 7)
                 finally
                   (loop while (< i end) do
                     (setf sum (+ (ash sum 8) (aref octet-vec i)))
                     (incf i)))
           (ldb (byte n-bits 0) sum)))
        ;; Large little-endian: process 7 bytes at a time
        (t
         (let ((sum 0))
           (declare (type integer sum))
           (loop with i fixnum = start
                 with bit-pos fixnum = 0
                 while (<= (+ i 7) (+ start n-bytes)) do
                   (let ((chunk 0))
                     (declare (type fixnum chunk))
                     (setf chunk (the fixnum
                                     (logior (the fixnum (aref octet-vec i))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 1))) 8))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 2))) 16))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 3))) 24))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 4))) 32))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 5))) 40))
                                             (the fixnum (ash (the fixnum (aref octet-vec (+ i 6))) 48)))))
                     (setf sum (logior sum (ash chunk bit-pos))))
                   (incf i 7)
                   (incf bit-pos 56)
                 finally
                   (loop while (< i (+ start n-bytes)) do
                     (setf sum (logior sum (ash (aref octet-vec i) bit-pos)))
                     (incf i)
                     (incf bit-pos 8)))
           (ldb (byte n-bits 0) sum)))))))

#-sbcl
(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec)
           (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let ((end (or end (length octet-vec))))
    (multiple-value-bind (n-bits n-bytes)
        (let ((size (- end start)))
          (if n-bits
              (values n-bits (min (ceiling n-bits 8) size))
              (values (* 8 size) size)))
      (let ((sum (if big-endian
                     (loop with sum = 0
                           for i from (- end n-bytes) below end
                           do (setf sum (+ (ash sum 8) (aref octet-vec i)))
                           finally (return sum))
                     (loop for i from start below (+ start n-bytes)
                           for j from 0 by 8
                           sum (ash (aref octet-vec i) j)))))
        (ldb (byte n-bits 0) sum)))))

(defun integer-to-octets (bignum &key n-bits (big-endian t))
  (declare (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let* ((n-bits (or n-bits (integer-length bignum)))
         (bignum (ldb (byte n-bits 0) bignum))
         (n-bytes (ceiling n-bits 8))
         (octet-vec (make-array n-bytes :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for index from 0
              do (setf (aref octet-vec index) (ldb (byte 8 (* i 8)) bignum))
              finally (return octet-vec))
        (loop for i from 0 below n-bytes
              for byte from 0 by 8
              do (setf (aref octet-vec i) (ldb (byte 8 byte) bignum))
              finally (return octet-vec)))))

(defun maybe-integerize (thing)
  (etypecase thing
    (integer thing)
    ((simple-array (unsigned-byte 8) (*)) (octets-to-integer thing))))

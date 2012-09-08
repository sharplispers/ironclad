;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto)


;;; scrypt from Colin Percival's
;;; "Stronger Key Derivation via Sequential Memory-Hard Functions"
;;; presented at BSDCan'09, May 2009.
;;; http://www.tarsnap.com/scrypt.html

(defclass scryptkdf ()
 ((N :accessor scrypt-kdf-N
     :initarg :N
     :initform 16384)
  (r :accessor scrypt-kdf-r
     :initarg :r
     :initform 8)
  (p :accessor scrypt-kdf-p
     :initarg :p
     :initform 1)))

(defmacro salsa-vector-4mix (x i4 i8 i12 i0)
  `(setf (aref ,x ,i4) (ldb (byte 32 0) (logxor (aref ,x ,i4) (rol32 (mod32+ (aref ,x ,i0) (aref ,x ,i12)) 7)))
         (aref ,x ,i8) (ldb (byte 32 0) (logxor (aref ,x ,i8) (rol32 (mod32+ (aref ,x ,i4) (aref ,x ,i0)) 9)))
         (aref ,x ,i12) (ldb (byte 32 0) (logxor (aref ,x ,i12) (rol32 (mod32+ (aref ,x ,i8) (aref ,x ,i4)) 13)))
         (aref ,x ,i0) (ldb (byte 32 0) (logxor (aref ,x ,i0) (rol32 (mod32+ (aref ,x ,i12) (aref ,x ,i8)) 18)))))

(defun scrypt-vector-salsa (b)
 (let ((x (make-array 16 :element-type '(unsigned-byte 32)))
       (w (make-array 16 :element-type '(unsigned-byte 32))))
  (declare (type (simple-array (unsigned-byte 32) (16)) x w))
  (fill-block-ub8-le x b 0)
  (replace w x)

  (loop repeat 4 do
    (salsa-vector-4mix x 4 8 12 0)
    (salsa-vector-4mix x 9 13 1 5)
    (salsa-vector-4mix x 14 2 6 10)
    (salsa-vector-4mix x 3 7 11 15)
    (salsa-vector-4mix x 1 2 3 0)
    (salsa-vector-4mix x 6 7 4 5)
    (salsa-vector-4mix x 11 8 9 10)
    (salsa-vector-4mix x 12 13 14 15))

  (dotimes (i 16)
    (setf (nibbles:ub32ref/le b (* i 4)) (mod32+ (aref x i) (aref w i))))))

(defun block-mix (b xy xy-start r)
 (let ((xs (make-array 64 :element-type '(unsigned-byte 8))))
  (replace xs b :start2 (* 64 (1- (* 2 r))) :end1 64)
  (dotimes (i (* 2 r))
    (xor-block 64 xs b (* i 64) xs 0)
    (scrypt-vector-salsa xs)
    (replace xy xs :start1 (+ xy-start (* i 64)) :end2 64))
  (dotimes (i r)
    (replace b xy :start1 (* i 64) :end1 (+ 64 (* i 64)) :start2 (+ xy-start (* 64 2 i))))
  (dotimes (i r)
    (replace b xy :start1 (* 64 (+ i r)) :end1 (+ (* 64 (+ i r)) 64) :start2 (+ xy-start (* 64 (1+ (* i 2))))))))

(defun smix (b b-start r N v xy)
 (let ((x xy)
       (xy-start (* 128 r)))
  (replace x b :end1 (* 128 r) :start2 b-start)
  (dotimes (i N)
    (replace v x :start1 (* i 128 r) :end2 (* 128 r))
    (block-mix x xy xy-start r))
  (dotimes (i N)
    (let ((j (ldb (byte 32 0) (logand (nibbles:ub64ref/le x (* (1- (* 2 r)) 64)) (1- N)))))
      (xor-block (* 128 r) x v (* j 128 r) x 0)
      (block-mix x xy xy-start r)))
  (replace b x :start1 b-start :end1 (+ b-start (* 128 r)))))

(defmethod derive-key ((kdf scryptkdf) passphrase salt iteration-count key-length)
 (declare (ignore iteration-count))
 (let ((xy (make-array (* 256 (scrypt-kdf-r kdf)) :element-type '(unsigned-byte 8)))
       (v (make-array (* 128 (scrypt-kdf-r kdf) (scrypt-kdf-N kdf)) :element-type '(unsigned-byte 8)))
       (b (derive-key (make-kdf 'PBKDF2 :digest 'SHA256) passphrase salt 1 (* (scrypt-kdf-p kdf) 128 (scrypt-kdf-r kdf)))))
  (dotimes (i (scrypt-kdf-p kdf))
    (smix b (* i 128 (scrypt-kdf-r kdf)) (scrypt-kdf-r kdf) (scrypt-kdf-N kdf) v xy))
  (derive-key (make-kdf 'PBKDF2 :digest 'SHA256) passphrase b 1 key-length)))

(defun make-scrypt-kdf (&optional (N 16384 N-supplied-p) (r 8 r-supplied-p) (p 1 p-supplied-p))
 "N is a CPU/memory cost parameter, and must be a power of two greater than 1.
 r and p must satisfy (< (* r p) (expt 2 30)). If the parameters do not satisfy
 the limits, that results in an unsupported-scrypt-costs error condition.

 The recommended paramters for interactive logins as of 2009 are:
 N=16384, r=8, p=1. They should be increased as memory latency and CPU parallelism
 increases."
  (when (or (and N-supplied-p (or (<= N 1) (not (zerop (logand N (1- N))))))
            (and (or r-supplied-p p-supplied-p) (>= (* r p) (expt 2 30))))
    (error 'unsupported-scrypt-cost-factors :N N :r r :p p))
  (make-instance 'scryptkdf :N N :r r :p p))

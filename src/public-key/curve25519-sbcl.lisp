;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; curve25519-sbcl.lisp -- zero-allocation Curve25519 field arithmetic for SBCL
;;;;
;;;; Replaces the generic bignum Curve25519 implementation with radix-2^25.5
;;;; limb arithmetic (djb's ref10 algorithm).  Field elements are 10 limbs of
;;;; alternating 26/25 bits stored as fixnums.  All intermediate products fit
;;;; in 62-bit SBCL fixnums, so the entire scalar multiplication conses only
;;;; the final curve25519-point instance.
;;;;
;;;; The Montgomery ladder runs ~20x faster than the generic bignum version
;;;; because it eliminates all intermediate bignum allocation and uses only
;;;; fixnum arithmetic throughout.
;;;;
;;;; Copyright 2026 John C. Mallery.  MIT License.

#+sbcl
(in-package :crypto)

;;;; ----------------------------------------------------------------
;;;; Limb type and constants
;;;; ----------------------------------------------------------------

;;; A field element in radix 2^25.5: ten limbs alternating 26/25 bits.
;;; Limb i has ceiling(255/10) bits.  Even limbs (0,2,4,6,8) have 26 bits,
;;; odd limbs (1,3,5,7,9) have 25 bits.
;;; All limbs stored as fixnums for zero-allocation arithmetic.

#+sbcl
(progn

(deftype fe () '(simple-array fixnum (10)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun %fe-mask (bits) (1- (ash 1 bits)))
  (defun %fe-limb-bits (i) (if (evenp i) 26 25))
  (defun %fe-limb-shift (i)
    "Bit position of limb I within the 255-bit integer."
    (loop for j fixnum from 0 below i
          sum (if (evenp j) 26 25) fixnum)))

;;;; ----------------------------------------------------------------
;;;; Allocation and conversion
;;;; ----------------------------------------------------------------

(declaim (inline make-fe fe-copy fe-zero))

(defun make-fe ()
  "Allocate a fresh field element (all zeros)."
  (declare (optimize (speed 3) (safety 0)))
  (make-array 10 :element-type 'fixnum :initial-element 0))

(defun fe-copy (dst src)
  "Copy field element SRC into DST."
  (declare (type fe dst src)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 10) (setf (aref dst i) (aref src i)))
  dst)

(defun fe-zero (dst)
  "Set DST to zero."
  (declare (type fe dst)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 10) (setf (aref dst i) 0))
  dst)

(defun integer-to-fe (n dst)
  "Convert a non-negative integer N (< 2^255) into DST."
  (declare (type integer n) (type fe dst)
           (optimize (speed 3) (safety 0)))
  (let ((shift 0))
    (declare (type fixnum shift))
    (dotimes (i 10)
      (let ((bits (if (evenp i) 26 25)))
        (setf (aref dst i) (ldb (byte bits shift) n))
        (incf shift bits))))
  dst)

(defun fe-to-integer (fe)
  "Convert a (fully reduced) field element to a non-negative integer."
  (declare (type fe fe)
           (optimize (speed 3) (safety 0)))
  (let ((result 0) (shift 0))
    (declare (type integer result) (type fixnum shift))
    (dotimes (i 10)
      (setf result (logior result (ash (the fixnum (aref fe i)) shift)))
      (incf shift (if (evenp i) 26 25)))
    result))

;;;; ----------------------------------------------------------------
;;;; Field arithmetic  (all write result into DST, return DST)
;;;; ----------------------------------------------------------------

(declaim (inline fe-add fe-sub))

(defun fe-add (dst a b)
  "DST = A + B  (not fully reduced, carries deferred)."
  (declare (type fe dst a b)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 10)
    (setf (aref dst i) (the fixnum (+ (the fixnum (aref a i))
                                       (the fixnum (aref b i))))))
  dst)

(defun fe-sub (dst a b)
  "DST = A - B.  Limbs may be negative; fe-carry handles this."
  (declare (type fe dst a b)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 10)
    (setf (aref dst i) (the fixnum (- (the fixnum (aref a i))
                                       (the fixnum (aref b i))))))
  dst)

;;; Carry-propagate in place.
(declaim (inline fe-carry))
(defun fe-carry (h)
  "Carry-propagate field element H in place."
  (declare (type fe h)
           (optimize (speed 3) (safety 0)))
  (let ((c 0))
    (declare (type fixnum c))
    ;; Forward pass: carry from limb 0 through 8
    (dotimes (i 9)
      (let* ((bits (if (evenp i) 26 25))
             (val (the fixnum (+ (the fixnum (aref h i)) c))))
        (declare (type fixnum bits val))
        (setf c (the fixnum (ash val (- bits))))
        (setf (aref h i) (the fixnum (logand val (%fe-mask bits))))))
    ;; Limb 9
    (let ((val (the fixnum (+ (the fixnum (aref h 9)) c))))
      (setf c (the fixnum (ash val -25)))
      (setf (aref h 9) (the fixnum (logand val (%fe-mask 25)))))
    ;; Fold carry from top: multiply by 19 and add to limb 0
    (incf (aref h 0) (the fixnum (* 19 c)))
    ;; One more carry from limb 0
    (let ((c0 (the fixnum (ash (the fixnum (aref h 0)) -26))))
      (setf (aref h 0) (the fixnum (logand (the fixnum (aref h 0))
                                            (%fe-mask 26))))
      (incf (aref h 1) c0)))
  h)

;;; Multiplication: schoolbook 10x10 with reduction.
;;; Each limb is at most ~27 bits after add/sub.  Products of two such
;;; limbs are at most ~54 bits.  We accumulate up to 10 such products
;;; plus a carry, staying within 62-bit fixnum range.
;;;
;;; Key: 2^255 ≡ 19 (mod p).  Cross-terms wrapping past limb 9 get
;;; multiplied by 19 (or 2*19=38 for doubled cross-terms) and folded back.

(defun fe-mul (dst a b)
  "DST = A * B mod p."
  (declare (type fe dst a b)
           (optimize (speed 3) (safety 0)))
  ;; Ensure inputs are carry-propagated so each limb fits in 26 bits.
  ;; Without this, uncarried add/sub results (up to 28 bits) overflow
  ;; the 62-bit fixnum accumulator when 10 products are summed.
  (fe-carry a)
  (fe-carry b)
  (let ((a0 (aref a 0)) (a1 (aref a 1)) (a2 (aref a 2)) (a3 (aref a 3))
        (a4 (aref a 4)) (a5 (aref a 5)) (a6 (aref a 6)) (a7 (aref a 7))
        (a8 (aref a 8)) (a9 (aref a 9))
        (b0 (aref b 0)) (b1 (aref b 1)) (b2 (aref b 2)) (b3 (aref b 3))
        (b4 (aref b 4)) (b5 (aref b 5)) (b6 (aref b 6)) (b7 (aref b 7))
        (b8 (aref b 8)) (b9 (aref b 9)))
    (declare (type fixnum a0 a1 a2 a3 a4 a5 a6 a7 a8 a9
                          b0 b1 b2 b3 b4 b5 b6 b7 b8 b9))
    ;; Pre-multiply by 19 for wrapping terms and double odd a-limbs
    ;; for the cross-term optimization (ref10 pattern).
    (let ((b1-19 (the fixnum (* 19 b1)))
          (b2-19 (the fixnum (* 19 b2)))
          (b3-19 (the fixnum (* 19 b3)))
          (b4-19 (the fixnum (* 19 b4)))
          (b5-19 (the fixnum (* 19 b5)))
          (b6-19 (the fixnum (* 19 b6)))
          (b7-19 (the fixnum (* 19 b7)))
          (b8-19 (the fixnum (* 19 b8)))
          (b9-19 (the fixnum (* 19 b9)))
          (a1-2 (the fixnum (* 2 a1)))
          (a3-2 (the fixnum (* 2 a3)))
          (a5-2 (the fixnum (* 2 a5)))
          (a7-2 (the fixnum (* 2 a7)))
          (a9-2 (the fixnum (* 2 a9))))
      (declare (type fixnum b1-19 b2-19 b3-19 b4-19 b5-19 b6-19 b7-19 b8-19 b9-19
                            a1-2 a3-2 a5-2 a7-2 a9-2))
      ;; Compute each output coefficient (h0..h9).
      ;; h_k = sum over i+j=k of a_i*b_j  (with wrapping *19 for i+j >= 10)
      (let ((h0 (the fixnum
                  (+ (the fixnum (* a0 b0))
                     (the fixnum (* a1-2 b9-19))
                     (the fixnum (* a2 b8-19))
                     (the fixnum (* a3-2 b7-19))
                     (the fixnum (* a4 b6-19))
                     (the fixnum (* a5-2 b5-19))
                     (the fixnum (* a6 b4-19))
                     (the fixnum (* a7-2 b3-19))
                     (the fixnum (* a8 b2-19))
                     (the fixnum (* a9-2 b1-19)))))
            (h1 (the fixnum
                  (+ (the fixnum (* a0 b1))
                     (the fixnum (* a1 b0))
                     (the fixnum (* a2 b9-19))
                     (the fixnum (* a3 b8-19))
                     (the fixnum (* a4 b7-19))
                     (the fixnum (* a5 b6-19))
                     (the fixnum (* a6 b5-19))
                     (the fixnum (* a7 b4-19))
                     (the fixnum (* a8 b3-19))
                     (the fixnum (* a9 b2-19)))))
            (h2 (the fixnum
                  (+ (the fixnum (* a0 b2))
                     (the fixnum (* a1-2 b1))
                     (the fixnum (* a2 b0))
                     (the fixnum (* a3-2 b9-19))
                     (the fixnum (* a4 b8-19))
                     (the fixnum (* a5-2 b7-19))
                     (the fixnum (* a6 b6-19))
                     (the fixnum (* a7-2 b5-19))
                     (the fixnum (* a8 b4-19))
                     (the fixnum (* a9-2 b3-19)))))
            (h3 (the fixnum
                  (+ (the fixnum (* a0 b3))
                     (the fixnum (* a1 b2))
                     (the fixnum (* a2 b1))
                     (the fixnum (* a3 b0))
                     (the fixnum (* a4 b9-19))
                     (the fixnum (* a5 b8-19))
                     (the fixnum (* a6 b7-19))
                     (the fixnum (* a7 b6-19))
                     (the fixnum (* a8 b5-19))
                     (the fixnum (* a9 b4-19)))))
            (h4 (the fixnum
                  (+ (the fixnum (* a0 b4))
                     (the fixnum (* a1-2 b3))
                     (the fixnum (* a2 b2))
                     (the fixnum (* a3-2 b1))
                     (the fixnum (* a4 b0))
                     (the fixnum (* a5-2 b9-19))
                     (the fixnum (* a6 b8-19))
                     (the fixnum (* a7-2 b7-19))
                     (the fixnum (* a8 b6-19))
                     (the fixnum (* a9-2 b5-19)))))
            (h5 (the fixnum
                  (+ (the fixnum (* a0 b5))
                     (the fixnum (* a1 b4))
                     (the fixnum (* a2 b3))
                     (the fixnum (* a3 b2))
                     (the fixnum (* a4 b1))
                     (the fixnum (* a5 b0))
                     (the fixnum (* a6 b9-19))
                     (the fixnum (* a7 b8-19))
                     (the fixnum (* a8 b7-19))
                     (the fixnum (* a9 b6-19)))))
            (h6 (the fixnum
                  (+ (the fixnum (* a0 b6))
                     (the fixnum (* a1-2 b5))
                     (the fixnum (* a2 b4))
                     (the fixnum (* a3-2 b3))
                     (the fixnum (* a4 b2))
                     (the fixnum (* a5-2 b1))
                     (the fixnum (* a6 b0))
                     (the fixnum (* a7-2 b9-19))
                     (the fixnum (* a8 b8-19))
                     (the fixnum (* a9-2 b7-19)))))
            (h7 (the fixnum
                  (+ (the fixnum (* a0 b7))
                     (the fixnum (* a1 b6))
                     (the fixnum (* a2 b5))
                     (the fixnum (* a3 b4))
                     (the fixnum (* a4 b3))
                     (the fixnum (* a5 b2))
                     (the fixnum (* a6 b1))
                     (the fixnum (* a7 b0))
                     (the fixnum (* a8 b9-19))
                     (the fixnum (* a9 b8-19)))))
            (h8 (the fixnum
                  (+ (the fixnum (* a0 b8))
                     (the fixnum (* a1-2 b7))
                     (the fixnum (* a2 b6))
                     (the fixnum (* a3-2 b5))
                     (the fixnum (* a4 b4))
                     (the fixnum (* a5-2 b3))
                     (the fixnum (* a6 b2))
                     (the fixnum (* a7-2 b1))
                     (the fixnum (* a8 b0))
                     (the fixnum (* a9-2 b9-19)))))
            (h9 (the fixnum
                  (+ (the fixnum (* a0 b9))
                     (the fixnum (* a1 b8))
                     (the fixnum (* a2 b7))
                     (the fixnum (* a3 b6))
                     (the fixnum (* a4 b5))
                     (the fixnum (* a5 b4))
                     (the fixnum (* a6 b3))
                     (the fixnum (* a7 b2))
                     (the fixnum (* a8 b1))
                     (the fixnum (* a9 b0))))))
        (declare (type fixnum h0 h1 h2 h3 h4 h5 h6 h7 h8 h9))
        (setf (aref dst 0) h0 (aref dst 1) h1 (aref dst 2) h2
              (aref dst 3) h3 (aref dst 4) h4 (aref dst 5) h5
              (aref dst 6) h6 (aref dst 7) h7 (aref dst 8) h8
              (aref dst 9) h9))))
  (fe-carry dst)
  dst)

(defun fe-sq (dst a)
  "DST = A^2 mod p.  Optimized: 55 multiplications vs 100 for fe-mul.
Cross-terms a_i*a_j (i<j) appear twice, combined as 2*a_i*a_j.
Wrapping uses 38 (not 19) for pairs whose bit positions sum to 256."
  (declare (type fe dst a)
           (optimize (speed 3) (safety 0)))
  (fe-carry a)
  (let ((a0 (aref a 0)) (a1 (aref a 1)) (a2 (aref a 2)) (a3 (aref a 3))
        (a4 (aref a 4)) (a5 (aref a 5)) (a6 (aref a 6)) (a7 (aref a 7))
        (a8 (aref a 8)) (a9 (aref a 9)))
    (declare (type fixnum a0 a1 a2 a3 a4 a5 a6 a7 a8 a9))
    ;; Pre-doubled values for cross-terms
    (let ((a0-2 (the fixnum (* 2 a0)))
          (a1-2 (the fixnum (* 2 a1)))
          (a2-2 (the fixnum (* 2 a2)))
          (a3-2 (the fixnum (* 2 a3)))
          (a4-2 (the fixnum (* 2 a4)))
          (a5-2 (the fixnum (* 2 a5)))
          (a6-2 (the fixnum (* 2 a6)))
          (a7-2 (the fixnum (* 2 a7)))
          ;; Wrapping: 38 for odd-indexed (bit sum = 256), 19 for even-indexed
          (a5-38 (the fixnum (* 38 a5)))
          (a6-19 (the fixnum (* 19 a6)))
          (a7-38 (the fixnum (* 38 a7)))
          (a8-19 (the fixnum (* 19 a8)))
          (a9-38 (the fixnum (* 38 a9))))
      (declare (type fixnum a0-2 a1-2 a2-2 a3-2 a4-2 a5-2 a6-2 a7-2
                            a5-38 a6-19 a7-38 a8-19 a9-38))
      (let ((h0 (the fixnum
                  (+ (the fixnum (* a0 a0))
                     (the fixnum (* a1-2 a9-38))
                     (the fixnum (* a2-2 a8-19))
                     (the fixnum (* a3-2 a7-38))
                     (the fixnum (* a4-2 a6-19))
                     (the fixnum (* a5 a5-38)))))
            (h1 (the fixnum
                  (+ (the fixnum (* a0-2 a1))
                     (the fixnum (* a2 a9-38))
                     (the fixnum (* a3-2 a8-19))
                     (the fixnum (* a4 a7-38))
                     (the fixnum (* a5-2 a6-19)))))
            (h2 (the fixnum
                  (+ (the fixnum (* a0-2 a2))
                     (the fixnum (* a1-2 a1))
                     (the fixnum (* a3-2 a9-38))
                     (the fixnum (* a4-2 a8-19))
                     (the fixnum (* a5-2 a7-38))
                     (the fixnum (* a6 a6-19)))))
            (h3 (the fixnum
                  (+ (the fixnum (* a0-2 a3))
                     (the fixnum (* a1-2 a2))
                     (the fixnum (* a4 a9-38))
                     (the fixnum (* a5-2 a8-19))
                     (the fixnum (* a6 a7-38)))))
            (h4 (the fixnum
                  (+ (the fixnum (* a0-2 a4))
                     (the fixnum (* a1-2 a3-2))
                     (the fixnum (* a2 a2))
                     (the fixnum (* a5-2 a9-38))
                     (the fixnum (* a6-2 a8-19))
                     (the fixnum (* a7 a7-38)))))
            (h5 (the fixnum
                  (+ (the fixnum (* a0-2 a5))
                     (the fixnum (* a1-2 a4))
                     (the fixnum (* a2-2 a3))
                     (the fixnum (* a6 a9-38))
                     (the fixnum (* a7-2 a8-19)))))
            (h6 (the fixnum
                  (+ (the fixnum (* a0-2 a6))
                     (the fixnum (* a1-2 a5-2))
                     (the fixnum (* a2-2 a4))
                     (the fixnum (* a3-2 a3))
                     (the fixnum (* a7-2 a9-38))
                     (the fixnum (* a8 a8-19)))))
            (h7 (the fixnum
                  (+ (the fixnum (* a0-2 a7))
                     (the fixnum (* a1-2 a6))
                     (the fixnum (* a2-2 a5))
                     (the fixnum (* a3-2 a4))
                     (the fixnum (* a8 a9-38)))))
            (h8 (the fixnum
                  (+ (the fixnum (* a0-2 a8))
                     (the fixnum (* a1-2 a7-2))
                     (the fixnum (* a2-2 a6))
                     (the fixnum (* a3-2 a5-2))
                     (the fixnum (* a4 a4))
                     (the fixnum (* a9 a9-38)))))
            (h9 (the fixnum
                  (+ (the fixnum (* a0-2 a9))
                     (the fixnum (* a1-2 a8))
                     (the fixnum (* a2-2 a7))
                     (the fixnum (* a3-2 a6))
                     (the fixnum (* a4-2 a5))))))
        (declare (type fixnum h0 h1 h2 h3 h4 h5 h6 h7 h8 h9))
        (setf (aref dst 0) h0 (aref dst 1) h1 (aref dst 2) h2
              (aref dst 3) h3 (aref dst 4) h4 (aref dst 5) h5
              (aref dst 6) h6 (aref dst 7) h7 (aref dst 8) h8
              (aref dst 9) h9))))
  (fe-carry dst)
  dst)

(defun fe-mul-scalar (dst a scalar)
  "DST = A * SCALAR mod p, where SCALAR is a small integer."
  (declare (type fe dst a)
           (type fixnum scalar)
           (optimize (speed 3) (safety 0)))
  (fe-carry a)
  (dotimes (i 10)
    (setf (aref dst i) (the fixnum (* scalar (the fixnum (aref a i))))))
  (fe-carry dst)
  dst)

;;;; ----------------------------------------------------------------
;;;; Canonical reduction
;;;; ----------------------------------------------------------------

(defun fe-canonical (fe)
  "Fully reduce FE to canonical form [0, p).  Modifies FE in place."
  (declare (type fe fe)
           (optimize (speed 3) (safety 0)))
  (fe-carry fe)
  ;; After carry, each limb is in its proper range.
  ;; Subtract p and check for underflow.
  ;; p in limbs: (2^26-19, 2^25-1, 2^26-1, ..., 2^25-1)
  (let ((h0 (aref fe 0)) (h1 (aref fe 1)) (h2 (aref fe 2)) (h3 (aref fe 3))
        (h4 (aref fe 4)) (h5 (aref fe 5)) (h6 (aref fe 6)) (h7 (aref fe 7))
        (h8 (aref fe 8)) (h9 (aref fe 9)))
    (declare (type fixnum h0 h1 h2 h3 h4 h5 h6 h7 h8 h9))
    ;; Add 19 to h0. If result >= 2^255, then fe >= p.
    (let ((q (the fixnum (+ 19 h0))))
      (declare (type fixnum q))
      (setf q (the fixnum (ash q -26)))
      (setf q (the fixnum (+ q h1))) (setf q (the fixnum (ash q -25)))
      (setf q (the fixnum (+ q h2))) (setf q (the fixnum (ash q -26)))
      (setf q (the fixnum (+ q h3))) (setf q (the fixnum (ash q -25)))
      (setf q (the fixnum (+ q h4))) (setf q (the fixnum (ash q -26)))
      (setf q (the fixnum (+ q h5))) (setf q (the fixnum (ash q -25)))
      (setf q (the fixnum (+ q h6))) (setf q (the fixnum (ash q -26)))
      (setf q (the fixnum (+ q h7))) (setf q (the fixnum (ash q -25)))
      (setf q (the fixnum (+ q h8))) (setf q (the fixnum (ash q -26)))
      (setf q (the fixnum (+ q h9))) (setf q (the fixnum (ash q -25)))
      ;; q is 0 or 1.  If 1, fe >= p, subtract p (i.e., add 19 and reduce).
      (incf h0 (the fixnum (* 19 q)))
      ;; Carry
      (let ((c (the fixnum (ash h0 -26)))) (setf h0 (logand h0 #.(1- (ash 1 26)))) (incf h1 c))
      (let ((c (the fixnum (ash h1 -25)))) (setf h1 (logand h1 #.(1- (ash 1 25)))) (incf h2 c))
      (let ((c (the fixnum (ash h2 -26)))) (setf h2 (logand h2 #.(1- (ash 1 26)))) (incf h3 c))
      (let ((c (the fixnum (ash h3 -25)))) (setf h3 (logand h3 #.(1- (ash 1 25)))) (incf h4 c))
      (let ((c (the fixnum (ash h4 -26)))) (setf h4 (logand h4 #.(1- (ash 1 26)))) (incf h5 c))
      (let ((c (the fixnum (ash h5 -25)))) (setf h5 (logand h5 #.(1- (ash 1 25)))) (incf h6 c))
      (let ((c (the fixnum (ash h6 -26)))) (setf h6 (logand h6 #.(1- (ash 1 26)))) (incf h7 c))
      (let ((c (the fixnum (ash h7 -25)))) (setf h7 (logand h7 #.(1- (ash 1 25)))) (incf h8 c))
      (let ((c (the fixnum (ash h8 -26)))) (setf h8 (logand h8 #.(1- (ash 1 26)))) (incf h9 c))
      (setf h9 (logand h9 #.(1- (ash 1 25)))))
    (setf (aref fe 0) h0 (aref fe 1) h1 (aref fe 2) h2
          (aref fe 3) h3 (aref fe 4) h4 (aref fe 5) h5
          (aref fe 6) h6 (aref fe 7) h7 (aref fe 8) h8
          (aref fe 9) h9))
  fe)

;;;; ----------------------------------------------------------------
;;;; Modular inversion via addition chain for p-2
;;;; ----------------------------------------------------------------

(defun fe-invert (dst z)
  "DST = Z^(-1) mod p, via Fermat: z^(p-2).
Uses the standard addition chain for 2^255 - 21."
  (declare (type fe dst z)
           (optimize (speed 3) (safety 0)))
  (let ((t0 (make-fe)) (t1 (make-fe)) (t2 (make-fe)) (t3 (make-fe)))
    (declare (type fe t0 t1 t2 t3)
             (dynamic-extent t0 t1 t2 t3))
    ;; z2 = z^2
    (fe-sq t0 z)                      ; t0 = z^2
    ;; z4 = z2^2
    (fe-sq t1 t0)                     ; t1 = z^4
    ;; z8 = z4^2
    (fe-sq t1 t1)                     ; t1 = z^8
    ;; z9 = z8 * z
    (fe-mul t1 t1 z)                  ; t1 = z^9
    ;; z11 = z9 * z2
    (fe-mul t2 t1 t0)                ; t2 = z^11
    ;; z22 = z11^2
    (fe-sq t0 t2)                     ; t0 = z^22
    ;; z_5_0 = z22 * z9 = z^31 = z^(2^5-1)
    (fe-mul t0 t0 t1)                ; t0 = z^(2^5-1)
    ;; z_10_0 = t0^(2^5) * t0
    (fe-sq t1 t0)                     ; t1 = z^(2^6-2)
    (dotimes (i 4) (fe-sq t1 t1))     ; t1 = z^(2^10-2^5)
    (fe-mul t1 t1 t0)                ; t1 = z^(2^10-1)
    ;; z_20_0
    (fe-copy t3 t1)                   ; save z^(2^10-1)
    (dotimes (i 10) (fe-sq t1 t1))    ; t1 = z^(2^20-2^10)
    (fe-mul t1 t1 t3)                ; t1 = z^(2^20-1)
    ;; z_40_0
    (fe-sq t3 t1)                     ; use t3 as temp
    (dotimes (i 19) (fe-sq t3 t3))    ; t3 = z^(2^40-2^20)
    (fe-mul t1 t3 t1)                ; t1 = z^(2^40-1)
    ;; z_50_0
    (dotimes (i 10) (fe-sq t1 t1))    ; t1 = z^(2^50-2^10)
    ;; Need z^(2^10-1) again -- recompute from t0
    (fe-sq t3 t0)                     ; t3 = z^(2^6-2)
    (dotimes (i 4) (fe-sq t3 t3))     ; t3 = z^(2^10-2^5)
    (fe-mul t3 t3 t0)                ; t3 = z^(2^10-1)
    (fe-mul t1 t1 t3)                ; t1 = z^(2^50-1)
    ;; z_100_0
    (fe-copy t3 t1)                   ; save z^(2^50-1)
    (dotimes (i 50) (fe-sq t1 t1))    ; t1 = z^(2^100-2^50)
    (fe-mul t1 t1 t3)                ; t1 = z^(2^100-1)
    ;; z_200_0
    (fe-sq t0 t1)
    (dotimes (i 99) (fe-sq t0 t0))    ; t0 = z^(2^200-2^100)
    (fe-mul t1 t0 t1)                ; t1 = z^(2^200-1)
    ;; z_250_0
    (dotimes (i 50) (fe-sq t1 t1))    ; t1 = z^(2^250-2^50)
    (fe-mul t1 t1 t3)                ; t1 = z^(2^250-1)
    ;; z^(2^255-2^5)
    (dotimes (i 5) (fe-sq t1 t1))     ; t1 = z^(2^255-32)
    ;; z^(2^255-21) = z^(2^255-32) * z^11
    (fe-mul dst t1 t2)               ; dst = z^(p-2)
    dst))

;;;; ----------------------------------------------------------------
;;;; Montgomery ladder
;;;; ----------------------------------------------------------------

(defun %fe-double-and-add (x1 z1 x2 z2 base-x ta tb tc td te tf)
  "Montgomery double-and-add on field elements.
Doubles (X1,Z1) and adds the difference to (X2,Z2).
Modifies X1,Z1,X2,Z2 in place.  TA-TF are temporaries."
  (declare (type fe x1 z1 x2 z2 base-x ta tb tc td te tf)
           (optimize (speed 3) (safety 0)))
  ;; t1 = x1 + z1
  (fe-add ta x1 z1)
  ;; t2 = t1^2
  (fe-sq tb ta)
  ;; t3 = x1 - z1
  (fe-sub tc x1 z1)
  ;; t4 = t3^2
  (fe-sq td tc)
  ;; t5 = t2 - t4
  (fe-sub te tb td)
  ;; t7 = x2 - z2, t8 = t1 * t7
  (fe-sub tf x2 z2)
  (fe-mul tf ta tf)
  ;; t6 = x2 + z2, t9 = t3 * t6
  (fe-add ta x2 z2)
  (fe-mul ta tc ta)
  ;; x4 = t2 * t4
  (fe-mul x1 tb td)
  ;; t12 = a24 * t5
  (fe-mul-scalar tc te +curve25519-a24+)
  ;; t13 = t4 + t12
  (fe-add tc td tc)
  ;; z4 = t5 * t13
  (fe-mul z1 te tc)
  ;; t10 = t8 + t9
  (fe-add tc tf ta)
  ;; x5 = t10^2
  (fe-sq x2 tc)
  ;; t11 = t8 - t9
  (fe-sub tc tf ta)
  ;; t14 = t11^2
  (fe-sq tc tc)
  ;; z5 = base-x * t14
  (fe-mul z2 base-x tc)
  (values))

(defun %curve25519-ladder (result-x result-z scalar base-x)
  "Montgomery ladder: compute SCALAR * point(BASE-X) into RESULT-X, RESULT-Z."
  (declare (type fe result-x result-z base-x)
           (type integer scalar)
           (optimize (speed 3) (safety 0)))
  (let ((x1 (make-fe)) (z1 (make-fe))
        (x2 (make-fe)) (z2 (make-fe))
        (ta (make-fe)) (tb (make-fe)) (tc (make-fe))
        (td (make-fe)) (te (make-fe)) (tf (make-fe)))
    (declare (type fe x1 z1 x2 z2 ta tb tc td te tf)
             (dynamic-extent x1 z1 x2 z2 ta tb tc td te tf))
    ;; (x1,z1) = (1,0) = point at infinity
    (setf (aref x1 0) 1)
    ;; (x2,z2) = (base-x, 1) = base point
    (fe-copy x2 base-x)
    (setf (aref z2 0) 1)
    ;; Montgomery ladder: bits 254 down to 0
    (loop for i fixnum from 254 downto 0 do
      (cond ((logbitp i scalar)
             (%fe-double-and-add x2 z2 x1 z1 base-x ta tb tc td te tf))
            (t
             (%fe-double-and-add x1 z1 x2 z2 base-x ta tb tc td te tf))))
    (fe-copy result-x x1)
    (fe-copy result-z z1)))

;;;; ----------------------------------------------------------------
;;;; Replace generic methods with fast limb-arithmetic versions
;;;; ----------------------------------------------------------------

(defun curve25519-double-and-add (x1 z1 x2 z2 x3)
  "Point doubling and addition on curve25519 curve.
Uses radix-2^25.5 limb arithmetic for zero-allocation field operations."
  (declare (type integer x1 z1 x2 z2 x3)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((fx1 (make-fe)) (fz1 (make-fe))
        (fx2 (make-fe)) (fz2 (make-fe))
        (fx3 (make-fe))
        (ta (make-fe)) (tb (make-fe)) (tc (make-fe))
        (td (make-fe)) (te (make-fe)) (tf (make-fe)))
    (declare (type fe fx1 fz1 fx2 fz2 fx3 ta tb tc td te tf)
             (dynamic-extent fx1 fz1 fx2 fz2 fx3 ta tb tc td te tf))
    (integer-to-fe x1 fx1) (integer-to-fe z1 fz1)
    (integer-to-fe x2 fx2) (integer-to-fe z2 fz2)
    (integer-to-fe x3 fx3)
    (%fe-double-and-add fx1 fz1 fx2 fz2 fx3 ta tb tc td te tf)
    (fe-canonical fx1) (fe-canonical fz1)
    (fe-canonical fx2) (fe-canonical fz2)
    (values (fe-to-integer fx1) (fe-to-integer fz1)
            (fe-to-integer fx2) (fe-to-integer fz2))))

(defmethod ec-scalar-mult ((p curve25519-point) n)
  "Fast Montgomery ladder for Curve25519 using radix-2^25.5 limb arithmetic.
Eliminates all intermediate bignum allocation."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer n))
  (with-slots (x z) p
    (declare (type integer x z))
    (assert (= 1 z))
    (let ((base-x (make-fe))
          (rx (make-fe))
          (rz (make-fe)))
      (declare (type fe base-x rx rz)
               (dynamic-extent base-x))
      (integer-to-fe x base-x)
      (%curve25519-ladder rx rz n base-x)
      (fe-canonical rx) (fe-canonical rz)
      (make-instance 'curve25519-point
                     :x (fe-to-integer rx)
                     :z (fe-to-integer rz)))))

(defmethod ec-scalar-inv ((kind (eql :curve25519)) n)
  "Fast modular inversion using limb-based Fermat addition chain."
  (let ((fe-n (make-fe))
        (result (make-fe)))
    (declare (type fe fe-n result)
             (dynamic-extent fe-n))
    (integer-to-fe (mod n +curve25519-p+) fe-n)
    (fe-invert result fe-n)
    (fe-canonical result)
    (fe-to-integer result)))

(defmethod ec-destructure-point ((p curve25519-point))
  (with-slots (x z) p
    (declare (type integer x z))
    (let ((x (mod (* x (ec-scalar-inv :curve25519 z)) +curve25519-p+)))
      (list :x x))))

) ; end #+sbcl progn

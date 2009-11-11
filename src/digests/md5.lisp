;;;; This file implements The MD5 Message-Digest Algorithm, as defined in
;;;; RFC 1321 by R. Rivest, published April 1992.
;;;;
;;;; It was written by Pierre R. Mai, with copious input from the
;;;; cmucl-help mailing-list hosted at cons.org, in November 2001 and
;;;; has been placed into the public domain.
;;;;
;;;; $Id: md5.lisp,v 1.3 2003/09/16 12:07:39 crhodes Exp $
;;;;
;;;; While the implementation should work on all conforming Common
;;;; Lisp implementations, it has only been optimized for CMU CL,
;;;; where it achieved comparable performance to the standard md5sum
;;;; utility (within a factor of 1.5 or less on iA32 and UltraSparc
;;;; hardware).
;;;;
;;;; Since the implementation makes heavy use of arithmetic on
;;;; (unsigned-byte 32) numbers, acceptable performance is likely only
;;;; on CL implementations that support unboxed arithmetic on such
;;;; numbers in some form.  For other CL implementations a 16bit
;;;; implementation of MD5 is probably more suitable.
;;;;
;;;; The code implements correct operation for files of unbounded size
;;;; as is, at the cost of having to do a single generic integer
;;;; addition for each call to update-md5-state.  If you call
;;;; update-md5-state frequently with little data, this can pose a
;;;; performance problem.  If you can live with a size restriction of
;;;; 512 MB, then you can enable fast fixnum arithmetic by putting
;;;; :md5-small-length onto *features* prior to compiling this file.
;;;;
;;;; This software is "as is", and has no warranty of any kind.  The
;;;; authors assume no responsibility for the consequences of any use
;;;; of this software.

(in-package :crypto)

;;; Section 3.4:  Table T

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *t* (make-array 64 :element-type '(unsigned-byte 32)
				:initial-contents
				(loop for i from 1 to 64
				      collect
				      (truncate
				       (* 4294967296
					  (abs (sin (float i 0.0d0)))))))))

;;; Section 3.3:  (Initial) MD5 Working Set

(define-digest-registers (md5 :endian :little)
  (a #x67452301)
  (b #xefcdab89)
  (c #x98badcfe)
  (d #x10325476))

(defconst +pristine-md5-registers+ (initial-md5-regs))

;;; Section 3.4:  Operation on 16-Word Blocks

(macrolet ((with-md5-round ((op block) &rest clauses)
             (loop for (a b c d k s i) in clauses
                   collect
                   `(setq ,a (mod32+ ,b (rol32 (mod32+ (mod32+ ,a (,op ,b ,c ,d))
                                                       (mod32+ (aref ,block ,k)
                                                               ,(aref *t* (1- i))))
                                         ,s)))
                   into result
                   finally (return `(progn ,@result)))))
(defun update-md5-block (regs block)
  "This is the core part of the MD5 algorithm.  It takes a complete 16
word block of input, and updates the working state in A, B, C, and D
accordingly."
  (declare (type md5-regs regs)
	   (type (simple-array (unsigned-byte 32) (16)) block)
           #.(burn-baby-burn))
  (let ((a (md5-regs-a regs)) (b (md5-regs-b regs))
	(c (md5-regs-c regs)) (d (md5-regs-d regs)))
    (declare (type (unsigned-byte 32) a b c d))
    (flet ((f (x y z)
             (declare (type (unsigned-byte 32) x y z))
             #+cmu
             (kernel:32bit-logical-xor z
                                       (kernel:32bit-logical-and x
                                                                 (kernel:32bit-logical-xor y z)))
             #-cmu
             (logxor z (logand x (logxor y z))))
           (g (x y z)
             (declare (type (unsigned-byte 32) x y z))
             #+cmu
             (kernel:32bit-logical-xor y
                                       (kernel:32bit-logical-and z
                                                                 (kernel:32bit-logical-xor x y)))
             #-cmu
             (logxor y (logand z (logxor x y))))
           (h (x y z)
             (declare (type (unsigned-byte 32) x y z))
             #+cmu
             (kernel:32bit-logical-xor x (kernel:32bit-logical-xor y z))
             #-cmu
             (logxor x y z))
           (i (x y z)
             (declare (type (unsigned-byte 32) x y z))
             #+cmu
             (kernel:32bit-logical-xor y (kernel:32bit-logical-orc2 x z))
             #-cmu
             (ldb (byte 32 0) (logxor y (logorc2 x z)))))
      (declare (inline f g h i))
      ;; Round 1
      (with-md5-round (f block)
        (A B C D  0  7  1)(D A B C  1 12  2)(C D A B  2 17  3)(B C D A  3 22  4)
        (A B C D  4  7  5)(D A B C  5 12  6)(C D A B  6 17  7)(B C D A  7 22  8)
        (A B C D  8  7  9)(D A B C  9 12 10)(C D A B 10 17 11)(B C D A 11 22 12)
        (A B C D 12  7 13)(D A B C 13 12 14)(C D A B 14 17 15)(B C D A 15 22 16))
      ;; Round 2
      (with-md5-round (g block)
        (A B C D  1  5 17)(D A B C  6  9 18)(C D A B 11 14 19)(B C D A  0 20 20)
        (A B C D  5  5 21)(D A B C 10  9 22)(C D A B 15 14 23)(B C D A  4 20 24)
        (A B C D  9  5 25)(D A B C 14  9 26)(C D A B  3 14 27)(B C D A  8 20 28)
        (A B C D 13  5 29)(D A B C  2  9 30)(C D A B  7 14 31)(B C D A 12 20 32))
      ;; Round 3
      (with-md5-round (h block)
        (A B C D  5  4 33)(D A B C  8 11 34)(C D A B 11 16 35)(B C D A 14 23 36)
        (A B C D  1  4 37)(D A B C  4 11 38)(C D A B  7 16 39)(B C D A 10 23 40)
        (A B C D 13  4 41)(D A B C  0 11 42)(C D A B  3 16 43)(B C D A  6 23 44)
        (A B C D  9  4 45)(D A B C 12 11 46)(C D A B 15 16 47)(B C D A  2 23 48))
      ;; Round 4
      (with-md5-round (i block)
        (A B C D  0  6 49)(D A B C  7 10 50)(C D A B 14 15 51)(B C D A  5 21 52)
        (A B C D 12  6 53)(D A B C  3 10 54)(C D A B 10 15 55)(B C D A  1 21 56)
        (A B C D  8  6 57)(D A B C 15 10 58)(C D A B  6 15 59)(B C D A 13 21 60)
        (A B C D  4  6 61)(D A B C 11 10 62)(C D A B  2 15 63)(B C D A  9 21 64))
      ;; Update and return
      (setf (md5-regs-a regs) (mod32+ (md5-regs-a regs) a)
            (md5-regs-b regs) (mod32+ (md5-regs-b regs) b)
            (md5-regs-c regs) (mod32+ (md5-regs-c regs) c)
            (md5-regs-d regs) (mod32+ (md5-regs-d regs) d))
      regs)))
) ; MACROLET

;;; Mid-Level Drivers

(defstruct (md5
             (:constructor %make-md5-digest)
             (:constructor %make-md5-state (regs amount block buffer buffer-index))
             (:copier nil))
  (regs (initial-md5-regs) :type md5-regs :read-only t)
  (amount 0 :type (unsigned-byte 64))
  (block (make-array 16 :element-type '(unsigned-byte 32))
    :type (simple-array (unsigned-byte 32) (16)) :read-only t)
  (buffer (make-array 64 :element-type '(unsigned-byte 8))
          :type (simple-array (unsigned-byte 8) (64)) :read-only t)
  (buffer-index 0 :type (integer 0 63)))

(defmethod reinitialize-instance ((state md5) &rest initargs)
  (declare (ignore initargs))
  (replace (md5-regs state) +pristine-md5-registers+)
  (setf (md5-amount state) 0
        (md5-buffer-index state) 0)
  state)

(defmethod copy-digest ((state md5) &optional copy)
  (declare (type (or cl:null md5) copy))
  (cond
    (copy
     (replace (md5-regs copy) (md5-regs state))
     (replace (md5-buffer copy) (md5-buffer state))
     (setf (md5-amount copy) (md5-amount state)
           (md5-buffer-index copy) (md5-buffer-index state))
     copy)
    (t
     (%make-md5-state (copy-seq (md5-regs state))
                      (md5-amount state)
                      (copy-seq (md5-block state))
                      (copy-seq (md5-buffer state))
                      (md5-buffer-index state)))))

(define-digest-updater md5
  "Update the given md5-state from sequence, which is either a
simple-string or a simple-array with element-type (unsigned-byte 8),
bounded by start and end, which must be numeric bounding-indices."
  (let* ((regs (md5-regs state))
         (block (md5-block state))
         (buffer (md5-buffer state))
         (buffer-index (md5-buffer-index state))
         (length (- end start)))
    (declare (type md5-regs regs) (type fixnum length)
	     (type (integer 0 63) buffer-index)
	     (type (simple-array (unsigned-byte 32) (16)) block)
	     (type (simple-array (unsigned-byte 8) (64)) buffer))
    ;; Handle old rest
    (unless (zerop buffer-index)
      (let ((amount (min (- 64 buffer-index) length)))
	(declare (type (integer 0 63) amount))
	(copy-to-buffer sequence start amount buffer buffer-index)
	(setq start (the fixnum (+ start amount)))
        (let ((new-index (mod (+ buffer-index amount) 64)))
          (when (zerop new-index)
            (fill-block-ub8-le block buffer 0)
            (update-md5-block regs block))
          (when (>= start end)
            (setf (md5-buffer-index state) new-index)
            (incf (md5-amount state) length)
            (return-from update-digest state)))))
    (loop for offset of-type index from start below end by 64
          until (< (- end offset) 64)
          do
          (fill-block-ub8-le block sequence offset)
          (update-md5-block regs block)
          finally
          (let ((amount (- end offset)))
            (unless (zerop amount)
              (copy-to-buffer sequence offset amount buffer 0))
            (setf (md5-buffer-index state) amount)))
    (incf (md5-amount state) length)
    state))

(define-digest-finalizer (md5 16)
  "If the given md5-state has not already been finalized, finalize it,
by processing any remaining input in its buffer, with suitable padding
and appended bit-length, as specified by the MD5 standard.

The resulting MD5 message-digest is returned as an array of sixteen
 (unsigned-byte 8) values.  Calling UPDATE-MD5-STATE after a call to
FINALIZE-MD5-STATE results in unspecified behaviour."
  (let ((regs (md5-regs state))
        (block (md5-block state))
        (buffer (md5-buffer state))
        (buffer-index (md5-buffer-index state))
        (total-length (* 8 (md5-amount state))))
    (declare (type md5-regs regs)
             (type (integer 0 63) buffer-index)
             (type (simple-array (unsigned-byte 32) (16)) block)
             (type (simple-array (unsigned-byte 8) (64)) buffer))
    ;; Add mandatory bit 1 padding
    (setf (aref buffer buffer-index) #x80)
    ;; Fill with 0 bit padding
    (loop for index of-type (integer 0 64)
       from (1+ buffer-index) below 64
       do (setf (aref buffer index) #x00))
    (fill-block-ub8-le block buffer 0)
    ;; Flush block first if length wouldn't fit
    (when (>= buffer-index 56)
      (update-md5-block regs block)
      ;; Create new fully 0 padded block
      (loop for index of-type (integer 0 16) from 0 below 16
         do (setf (aref block index) #x00000000)))
    ;; Add 64bit message bit length
    (store-data-length block total-length 14)
    ;; Flush last block
    (update-md5-block regs block)
    ;; Done, remember digest for later calls
    (finalize-registers state regs)))

(defdigest md5 :digest-length 16 :block-length 64)

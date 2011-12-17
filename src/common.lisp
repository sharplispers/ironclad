;;;; common.lisp -- efficient implementations of mod32 arithmetic and macros

;;; Functions in this file are intended to be fast
(in-package :crypto)

(defmacro defconst (name value)
  `(defconstant ,name
    (if (boundp ',name)
        (symbol-value ',name)
        ,value)))

;;; CMUCL and SBCL both have an internal type for this, but we'd like to
;;; be portable, so we define our own.

(deftype index () '(mod #.array-dimension-limit))
(deftype index+1 () `(mod ,(1+ array-dimension-limit)))

;;; We write something like this all over the place.

(deftype simple-octet-vector (&optional length)
  (let ((length (or length '*)))
    `(simple-array (unsigned-byte 8) (,length))))


;;; a global specification of optimization settings

(eval-when (:compile-toplevel :load-toplevel :execute)
(defun burn-baby-burn ()
  '(optimize (speed 3) (safety 0) (space 0)
    (debug 0) (compilation-speed 0)))

(defun hold-me-back ()
  '(declare (optimize (speed 3) (space 0) (compilation-speed 0)
             #-cmu (safety 1) #-cmu (debug 1)
             #+cmu (safety 0) #+cmu (debug 0))
    #+cmu (ext:optimize-interface (safety 1) (debug 1))))
) ; EVAL-WHEN


;;; extracting individual bytes from integers

;;; We used to declare these functions with much stricter types (e.g.
;;; (UNSIGNED-BYTE 32) as the lone argument), but we need to access
;;; bytes of both 32-bit and 64-bit words and the types would just get
;;; in our way.  We declare these functions as inline; a good Common
;;; Lisp compiler should be able to generate efficient code from the
;;; declarations at the point of the call.

;;; These functions are named according to big-endian conventions.  The
;;; comment is here because I always forget and need to be reminded.
#.(loop for i from 1 to 8
        collect (let ((name (intern (format nil "~:R-~A" i '#:byte))))
                  `(progn
                    (declaim (inline ,name))
                    (declaim (ftype (function (unsigned-byte) (unsigned-byte 8)) ,name))
                    (defun ,name (ub)
                      (declare (type unsigned-byte ub))
                      (ldb (byte 8 ,(* 8 (1- i))) ub)))) into forms
        finally (return `(progn ,@forms)))


;;; fetching/storing appropriately-sized integers from octet vectors

(eval-when (:compile-toplevel :load-toplevel :execute)
(defun ubref-fun-name (bitsize big-endian-p)
  (intern (format nil "~A~D~A/~A" '#:ub bitsize '#:ref (if big-endian-p '#:be '#:le))))
) ; EVAL-WHEN

(macrolet ((define-fetcher (bitsize &optional big-endian)
             (let ((name (ubref-fun-name bitsize big-endian))
                   (bytes (truncate bitsize 8)))
               `(progn
                 (declaim (inline ,name))
                 (defun ,name (buffer index)
                   (declare (type simple-octet-vector buffer))
                   (declare (type (integer 0 ,(- array-dimension-limit bytes)) index))
                   (logand ,(1- (ash 1 bitsize))
                           ,(loop for i from 0 below bytes
                                  collect (let* ((offset (if big-endian
                                                             i
                                                             (- bytes i 1)))
                                                 (shift (if big-endian
                                                            (* (- bytes i 1) 8)
                                                            (* offset 8))))
                                            `(ash (aref buffer (+ index ,offset)) ,shift)) into forms
                                  finally (return `(logior ,@forms))))))))
           (define-storer (bitsize &optional big-endian)
             (let ((name (ubref-fun-name bitsize big-endian))
                   (bytes (truncate bitsize 8)))
               `(progn
                 (declaim (inline (setf ,name)))
                 (defun (setf ,name) (value buffer index)
                   (declare (type simple-octet-vector buffer))
                   (declare (type (integer 0 ,(- array-dimension-limit bytes)) index))
                   (declare (type (unsigned-byte ,bitsize) value))
                   ,@(loop for i from 1 to bytes
                           collect (let ((offset (if big-endian
                                                     (- bytes i)
                                                     (1- i))))
                                     `(setf (aref buffer (+ index ,offset))
                                       (,(intern (format nil "~:R-~A" i '#:byte)) value))))
                   (values)))))
           (define-fetchers-and-storers (bitsize)
             `(progn
               (define-fetcher ,bitsize) (define-fetcher ,bitsize t)
               (define-storer ,bitsize) (define-storer ,bitsize t))))
  (define-fetchers-and-storers 16)
  (define-fetchers-and-storers 32)
  (define-fetchers-and-storers 64))


;;; efficient 32-bit arithmetic, which a lot of algorithms require

(declaim #+ironclad-fast-mod32-arithmetic (inline mod32+)
	 (ftype (function ((unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32)) mod32+))
(defun mod32+ (a b)
  (declare (type (unsigned-byte 32) a b))
  (ldb (byte 32 0) (+ a b)))

#+cmu
(define-compiler-macro mod32+ (a b)
  `(ext:truly-the (unsigned-byte 32) (+ ,a ,b)))

#+sbcl
(define-compiler-macro mod32+ (a b)
  `(ldb (byte 32 0) (+ ,a ,b)))

;;; mostly needed for CAST*
(declaim #+ironclad-fast-mod32-arithmetic (inline mod32-)
         (ftype (function ((unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32)) mod32-))

(defun mod32- (a b)
  (declare (type (unsigned-byte 32) a b))
  (ldb (byte 32 0) (- a b)))

#+cmu
(define-compiler-macro mod32- (a b)
  `(ext:truly-the (unsigned-byte 32) (- ,a ,b)))

#+sbcl
(define-compiler-macro mod32- (a b)
  `(ldb (byte 32 0) (- ,a ,b)))

;;; mostly needed for RC6
(declaim #+ironclad-fast-mod32-arithmetic (inline mod32*)
         (ftype (function ((unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32)) mod32*))

(defun mod32* (a b)
  (declare (type (unsigned-byte 32) a b))
  (ldb (byte 32 0) (* a b)))

#+cmu
(define-compiler-macro mod32* (a b)
  `(ext:truly-the (unsigned-byte 32) (* ,a ,b)))

#+sbcl
(define-compiler-macro mod32* (a b)
  `(ldb (byte 32 0) (* ,a ,b)))

(declaim #+ironclad-fast-mod32-arithmetic (inline mod32ash)
         (ftype (function ((unsigned-byte 32) (integer -31 31)) (unsigned-byte 32)) mod32ash))

(defun mod32ash (num count)
  (declare (type (unsigned-byte 32) num))
  (declare (type (integer -31 31) count))
  (ldb (byte 32 0) (ash num count)))

#+sbcl
(define-compiler-macro mod32ash (num count)
  ;; work around SBCL optimizing bug as described by APD:
  ;;  http://www.caddr.com/macho/archives/sbcl-devel/2004-8/3877.html
  `(logand #xffffffff (ash ,num ,count)))

(declaim #+ironclad-fast-mod32-arithmetic (inline mod32lognot)
         (ftype (function ((unsigned-byte 32)) (unsigned-byte 32)) mod32lognot))

(defun mod32lognot (num)
  (ldb (byte 32 0) (lognot num)))

#+sbcl
(define-compiler-macro mod32lognot (num)
  `(ldb (byte 32 0) (lognot ,num)))

(declaim #+ironclad-fast-mod32-arithmetic (inline rol32 ror32)
	 (ftype (function ((unsigned-byte 32) (unsigned-byte 5)) (unsigned-byte 32)) rol32 ror32))

(defun rol32 (a s)
  (declare (type (unsigned-byte 32) a) (type (integer 0 32) s))
  #+cmu
  (kernel:32bit-logical-or #+little-endian (kernel:shift-towards-end a s)
			   #+big-endian (kernel:shift-towards-start a s)
			   (ash a (- s 32)))
  #+sbcl
  (sb-rotate-byte:rotate-byte s (byte 32 0) a)
  #-(or sbcl cmu)
  (logior (ldb (byte 32 0) (ash a s)) (ash a (- s 32))))

(defun ror32 (a s)
  (declare (type (unsigned-byte 32) a) (type (integer 0 32) s))
  #+sbcl
  (sb-rotate-byte:rotate-byte (- s) (byte 32 0) a)
  #-sbcl
  (rol32 a (- 32 s)))

(declaim #+ironclad-fast-mod64-arithmetic (inline mod64+ mod64- mod64*)
	 (ftype (function ((unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64)) mod64+))
(defun mod64+ (a b)
  (declare (type (unsigned-byte 64) a b))
  (ldb (byte 64 0) (+ a b)))

#+sbcl
(define-compiler-macro mod64+ (a b)
  `(ldb (byte 64 0) (+ ,a ,b)))

(defun mod64- (a b)
  (declare (type (unsigned-byte 64) a b))
  (ldb (byte 64 0) (- a b)))

#+sbcl
(define-compiler-macro mod64- (a b)
  `(ldb (byte 64 0) (- ,a ,b)))

(defun mod64* (a b)
  (declare (type (unsigned-byte 64) a b))
  (ldb (byte 64 0) (* a b)))

#+sbcl
(define-compiler-macro mod64* (a b)
  `(ldb (byte 64 0) (* ,a ,b)))

(declaim #+ironclad-fast-mod64-arithmetic (inline rol64 ror64)
	 (ftype (function ((unsigned-byte 64) (unsigned-byte 6)) (unsigned-byte 64)) rol64 ror64))

(declaim #+ironclad-fast-mod64-arithmetic (inline mod64ash)
         (ftype (function ((unsigned-byte 64) (integer -63 63)) (unsigned-byte 64)) mod64ash))

(defun mod64ash (num count)
  (declare (type (unsigned-byte 64) num))
  (declare (type (integer -63 63) count))
  (ldb (byte 64 0) (ash num count)))

#+sbcl
(define-compiler-macro mod64ash (num count)
  ;; work around SBCL optimizing bug as described by APD:
  ;;  http://www.caddr.com/macho/archives/sbcl-devel/2004-8/3877.html
  `(logand #xffffffffffffffff (ash ,num ,count)))

(declaim #+ironclad-fast-mod64-arithmetic (inline mod64lognot)
         (ftype (function ((unsigned-byte 64)) (unsigned-byte 64)) mod64lognot))

(defun mod64lognot (num)
  (ldb (byte 64 0) (lognot num)))

#+sbcl
(define-compiler-macro mod64lognot (num)
  `(ldb (byte 64 0) (lognot ,num)))

(defun rol64 (a s)
  (declare (type (unsigned-byte 64) a) (type (integer 0 64) s))
  (logior (ldb (byte 64 0) (ash a s)) (ash a (- s 64))))

(defun ror64 (a s)
  (declare (type (unsigned-byte 64) a) (type (integer 0 64) s))
  (rol64 a (- 64 s)))


;;; 64-bit utilities

(declaim #+ironclad-fast-mod32-arithmetic
         (inline %add-with-carry %subtract-with-borrow))

;;; The names are taken from sbcl and cmucl's bignum routines.
;;; Naturally, they work the same way (which means %SUBTRACT-WITH-BORROW
;;; is a little weird).
(defun %add-with-carry (x y carry)
  (declare (type (unsigned-byte 32) x y)
           (type (mod 2) carry))
  #+(and sbcl 32-bit)
  (sb-bignum:%add-with-carry x y carry)
  #+(and cmucl 32-bit)
  (bignum:%add-with-carry x y carry)
  #-(or (and sbcl 32-bit)
        (and cmucl 32-bit))
  (let* ((temp (mod32+ x y))
         (temp-carry (if (< temp x) 1 0))
         (result (mod32+ temp carry)))
    (values result (logior temp-carry (if (< result temp) 1 0)))))

(defun %subtract-with-borrow (x y borrow)
  (declare (type (unsigned-byte 32) x y)
           (type (mod 2) borrow))
  #+(and sbcl 32-bit)
  (sb-bignum:%subtract-with-borrow x y borrow)
  #+(and cmucl 32-bit)
  (bignum:%subtract-with-borrow x y borrow)
  #-(or (and sbcl 32-bit)
        (and cmucl 32-bit))
  (let ((temp (mod32- x y)))
    (cond
      ((zerop borrow)
       (values (mod32- temp 1) (if (< y x) 1 0)))
      (t
       (values temp (logxor (if (< x y) 1 0) 1))))))

;;; efficient 8-byte -> 32-byte buffer copy routines, mostly used by
;;; the hash functions.  we provide big-endian and little-endian
;;; versions.

(declaim (inline fill-block-le-ub8 fill-block-be-ub8))

(declaim (inline copy-to-buffer))
(defun copy-to-buffer (from from-offset count buffer buffer-offset)
  "Copy a partial segment from input vector from starting at
from-offset and copying count elements into the 64 byte buffer
starting at buffer-offset."
  (declare (type index from-offset)
	   (type (integer 0 127) count buffer-offset)
	   (type simple-octet-vector from)
	   (type simple-octet-vector buffer)
           #.(burn-baby-burn))
  #+cmu
  (kernel:bit-bash-copy
   from (+ (* vm:vector-data-offset vm:word-bits) (* from-offset vm:byte-bits))
   buffer (+ (* vm:vector-data-offset vm:word-bits)
	     (* buffer-offset vm:byte-bits))
   (* count vm:byte-bits))
  #+sbcl
  (sb-kernel:ub8-bash-copy from from-offset buffer buffer-offset count)
  #-(or cmu sbcl)
  (loop for buffer-index of-type (integer 0 64) from buffer-offset
        for from-index of-type fixnum from from-offset
        below (+ from-offset count)
        do
        (setf (aref buffer buffer-index) (aref from from-index))))

(defun fill-block-ub8-le (block buffer offset)
  "Convert a complete 64 (UNSIGNED-BYTE 8) input BUFFER starting from
OFFSET into the given (UNSIGNED-BYTE 32) BLOCK."
  (declare (type (integer 0 #.(- array-dimension-limit 64)) offset)
	   (type (simple-array (unsigned-byte 32) (16)) block)
	   (type simple-octet-vector buffer))
  #+(and :cmu :little-endian)
  (kernel:bit-bash-copy
   buffer (+ (* vm:vector-data-offset vm:word-bits) (* offset vm:byte-bits))
   block (* vm:vector-data-offset vm:word-bits)
   (* 64 vm:byte-bits))
  #+(and :sbcl :little-endian)
  (sb-kernel:ub8-bash-copy buffer offset block 0 64)
  #-(or (and :sbcl :little-endian) (and :cmu :little-endian))
  (loop for i of-type (integer 0 16) from 0
	for j of-type (integer 0 #.array-dimension-limit)
	from offset to (+ offset 63) by 4
	do
	(setf (aref block i) (ub32ref/le buffer j))))

(defun fill-block-ub8-be (block buffer offset)
  "Convert a complete 64 (unsigned-byte 8) input vector segment
starting from offset into the given 16 word SHA1 block.  Calling this function
without subsequently calling EXPAND-BLOCK results in undefined behavior."
  (declare (type (integer 0 #.(- array-dimension-limit 64)) offset)
	   (type (simple-array (unsigned-byte 32) (*)) block)
	   (type simple-octet-vector buffer))
  ;; convert to 32-bit words
  #+(and :cmu :big-endian)
  (kernel:bit-bash-copy
   buffer (+ (* vm:vector-data-offset vm:word-bits)
             (* offset vm:byte-bits))
   block (* vm:vector-data-offset vm:word-bits)
   (* 64 vm:byte-bits))
  #+(and :sbcl :big-endian)
  (sb-kernel:ub8-bash-copy buffer offset block 0 64)
  #-(or (and :sbcl :big-endian) (and :cmu :big-endian))
  (loop for i of-type (integer 0 16) from 0
        for j of-type (integer 0 #.array-dimension-limit)
        from offset to (+ offset 63) by 4
        do (setf (aref block i) (ub32ref/be buffer j))))

(defun fill-block-ub8-le/64 (block buffer offset)
  "Convert a complete 128 (unsigned-byte 8) input vector segment
starting from offset into the given 16 qword SHA1 block.  Calling this
function without subsequently calling EXPAND-BLOCK results in undefined
behavior."
  (declare (type (integer 0 #.(- array-dimension-limit 64)) offset)
	   (type (simple-array (unsigned-byte 64) (*)) block)
	   (type simple-octet-vector buffer)
           #.(burn-baby-burn))
  ;; convert to 64-bit words
  #+(and :cmu :little-endian :64-bit)
  (kernel:bit-bash-copy
   buffer (+ (* vm:vector-data-offset vm:word-bits)
             (* offset vm:byte-bits))
   block (* vm:vector-data-offset vm:word-bits)
   (* 64 vm:byte-bits))
  #+(and :sbcl :little-endian :64-bit)
  (sb-kernel:ub8-bash-copy buffer offset block 0 64)
  #-(or (and :sbcl :little-endian :64-bit) (and :cmu :little-endian :64-bit))
  (loop for i of-type (integer 0 8) from 0
        for j of-type (integer 0 #.array-dimension-limit)
        from offset to (+ offset 63) by 8
        do (setf (aref block i) (ub64ref/le buffer j))))

(defun fill-block-ub8-be/64 (block buffer offset)
  "Convert a complete 128 (unsigned-byte 8) input vector segment
starting from offset into the given 16 qword SHA1 block.  Calling this
function without subsequently calling EXPAND-BLOCK results in undefined
behavior."
  (declare (type (integer 0 #.(- array-dimension-limit 128)) offset)
	   (type (simple-array (unsigned-byte 64) (*)) block)
	   (type simple-octet-vector buffer)
           #.(burn-baby-burn))
  ;; convert to 64-bit words
  #+(and :cmu :big-endian :64-bit)
  (kernel:bit-bash-copy
   buffer (+ (* vm:vector-data-offset vm:word-bits)
             (* offset vm:byte-bits))
   block (* vm:vector-data-offset vm:word-bits)
   (* 128 vm:byte-bits))
  #+(and :sbcl :big-endian :64-bit)
  (sb-kernel:ub8-bash-copy buffer offset block 0 128)
  #-(or (and :sbcl :big-endian) (and :cmu :big-endian))
  (loop for i of-type (integer 0 16) from 0
        for j of-type (integer 0 #.array-dimension-limit)
        from offset to (+ offset 127) by 8
        do (setf (aref block i) (ub64ref/be buffer j))))

(declaim (inline xor-block))
(defun xor-block (block-length input-block1 input-block2 input-block2-start
                               output-block output-block-start)
  (declare (type (simple-array (unsigned-byte 8) (*)) input-block1 input-block2 output-block))
  (declare (type index block-length input-block2-start output-block-start))
  ;; this could be made more efficient by doing things in a word-wise fashion.
  ;; of course, then we'd have to deal with fun things like boundary
  ;; conditions and such like.  maybe we could just win by unrolling the
  ;; loop a bit.  BLOCK-LENGTH should be a constant in all calls to this
  ;; function; maybe a compiler macro would work well.
  (dotimes (i block-length)
    (setf (aref output-block (+ output-block-start i))
          (logxor (aref input-block1 i)
                  (aref input-block2 (+ input-block2-start i))))))

;;; a few functions that are useful during compilation

(defun make-circular-list (&rest elements)
  (let ((list (copy-seq elements)))
    (setf (cdr (last list)) list)))

;;; SUBSEQ is defined to error on circular lists, so we define our own
(defun circular-list-subseq (list start end)
  (let* ((length (- end start))
         (subseq (make-list length)))
    (do ((i 0 (1+ i))
         (list (nthcdr start list) (cdr list))
         (xsubseq subseq (cdr xsubseq)))
        ((>= i length) subseq)
      (setf (first xsubseq) (first list)))))
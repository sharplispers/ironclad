;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; prng.lisp -- common functions for pseudo-random number generators

(in-package :crypto)


(defvar *prng* nil
  "Default pseudo-random-number generator for use by all crypto
  functions.  Defaults to a sensible OS-specific value.")

(defun list-all-prngs () (copy-list '(:os :fortuna :fortuna-generator)))

(defgeneric make-prng (name &key seed)
  (:documentation "Create a new NAME-type random number generator,
  seeding it from SEED.  If SEED is a pathname or namestring, read data
  from the indicated file; if it is sequence of bytes, use those bytes
  directly; if it is :RANDOM then read from /dev/random; if it
  is :URANDOM then read from /dev/urandom; if it is NIL then the
  generator is not seeded."))

(defmethod make-prng :around (name &key (seed :random))
  (let ((prng (call-next-method)))
    (unless (eq name :fortuna-generator)
      (cond
        ((eq seed nil))
        ((find seed '(:random :urandom)) (read-os-random-seed seed prng))
        ((or (pathnamep seed) (stringp seed)) (read-seed seed prng))
        ((typep seed 'simple-octet-vector)
         (prng-reseed seed prng)
         (incf (slot-value prng 'reseed-count)))
        (t (error "SEED must be an octet vector, pathname indicator, :random or :urandom"))))
    prng))

(defgeneric prng-random-data (num-bytes prng)
  (:documentation "Generate NUM-BYTES bytes using PRNG"))

(defun random-data (num-bytes &optional (prng *prng*))
  (prng-random-data num-bytes prng))

(defgeneric prng-reseed (seed prng)
  (:documentation "Reseed PRNG with SEED; SEED must
  be (PRNG-SEED-LENGTH PRNG) bytes long.")
  (:method (seed prng) (declare (ignorable seed prng))))

(defgeneric prng-seed-length (prng)
  (:documentation "Length of seed required by PRNG-RESEED.")
  (:method (prng) (declare (ignorable prng)) 0))

(defun read-os-random-seed (source &optional (prng *prng*))
  (let* ((seed-length (prng-seed-length prng))
         (seed (os-random-seed source seed-length)))
    (assert (= (length seed) seed-length))
    (prng-reseed seed prng)))

(defun random-bits (num-bits &optional (prng *prng*))
  (logand (1- (expt 2 num-bits))
          (octets-to-integer
           (prng-random-data (ceiling num-bits 8) prng))))

(defun strong-random (limit &optional (prng *prng*))
  "Return a strong random number from 0 to limit-1 inclusive.  A drop-in
replacement for COMMON-LISP:RANDOM."
  (assert (plusp limit))
  (assert prng)
  (etypecase limit
    (integer
     (let* ((log-limit (log limit 2))
            (num-bytes (ceiling log-limit 8))
            (mask (1- (expt 2 (ceiling log-limit)))))
       (loop for random = (logand (ironclad:octets-to-integer
                                   (prng-random-data num-bytes prng))
                                  mask)
          until (< random limit)
          finally (return random))))
    (float
     (float (let ((floor (floor 1 long-float-epsilon)))
              (* limit
                 (/ (strong-random floor)
                    floor)))))))

(defun os-random-seed (source num-bytes)
  #+unix(let ((path (cond
                      ((eq source :random) #P"/dev/random")
                      ((eq source :urandom) #P"/dev/urandom")
                      (t (error "Source must be either :random or :urandom"))))
              (seq (make-array num-bytes :element-type '(unsigned-byte 8))))
          (with-open-file (seed-file path :element-type '(unsigned-byte 8))
            (assert (>= (read-sequence seq seed-file) num-bytes))
            seq))
  ;; FIXME: this is _untested_!
  #+(and win32 sb-dynamic-core)(sb-win32:crypt-gen-random num-bytes)
  #-(or unix (and win32 sb-dynamic-core))(error "OS-RANDOM-SEED is not supported on your platform."))

(defun read-seed (path &optional (prng *prng*))
  "Reseed PRNG from PATH.  If PATH doesn't
exist, reseed from /dev/random and then write that seed to PATH."
  (let ((seed-length (prng-seed-length prng))
        seed)
    (if (probe-file path)
        (with-open-file (seed-file path :element-type 'simple-octet-vector)
          (setf seed (make-array seed-length))
          (assert (>= (read-sequence seed seed-file) seed-length)))
        (setf seed (os-random-seed :random seed-length)))
    (prng-reseed seed prng)
    (write-seed path prng))
  (values))

(defun write-seed (path &optional (prng *prng*))
  (with-open-file (seed-file path
                             :direction :output
                             :if-exists :supersede
                             :if-does-not-exist :create
                             :element-type 'simple-octet-vector)
    (write-sequence (random-data (prng-seed-length prng)) seed-file))
  ;; FIXME: this only works under SBCL.  It's important, though,
  ;; as it sets the proper permissions for reading a seedfile.
  #+sbcl(sb-posix:chmod path (logior sb-posix:S-IRUSR sb-posix:S-IWUSR))
  (values))

(defun feed-fifo (prng path)
  "Feed random data into a FIFO"
  (loop while
       (handler-case (with-open-file
                         (fortune-out path :direction :output
                                      :if-exists :overwrite
                                      :element-type '(unsigned-byte 8))
                       (loop do (write-sequence
                                 (random-data (1- (expt 2 20)) prng)
                                 fortune-out)))
         (stream-error () t))))

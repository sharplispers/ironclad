;;;; prng.lisp -- common functions for pseudo-random number generators

(in-package :crypto)


(defclass pseudo-random-number-generator ()
  ()
  (:documentation "A pseudo random number generator.  Base class for
  other PRNGs; not intended to be instantiated."))

(defun list-all-prngs ()
  '(fortuna))

(defgeneric make-prng (name &key seed)
  (:documentation "Create a new NAME-type random number generator,
  seeding it from SEED.  If SEED is a pathname or namestring, read data
  from the indicated file; if it is sequence of bytes, use those bytes
  directly; if it is :RANDOM then read from /dev/random; if it
  is :URANDOM then read from /dev/urandom; if it is NIL then the
  generator is not seeded."))

(defmethod make-prng :around (name &key (seed :random))
  (let ((prng (call-next-method)))
    (cond
      ((eq seed nil))
      ((find seed '(:random :urandom)) (read-os-random-seed prng seed))
      ((or (pathnamep seed) (stringp seed)) (read-seed prng seed))
      ((typep seed 'simple-octet-vector)
       (reseed (slot-value prng 'generator) seed)
       (incf (slot-value prng 'reseed-count)))
      (t (error "SEED must be an octet vector, pathname indicator, :random or :urandom")))
    prng))

(defmethod make-prng ((name (eql :fortuna)) &key seed)
  (make-instance 'fortuna-prng))

(defgeneric random-data (pseudo-random-number-generator num-bytes)
  (:documentation "Generate NUM-BYTES bytes using
  PSEUDO-RANDOM-NUMBER-GENERATOR"))

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
  #+(and win32 sb-dynamic-core)(sb!win32:crypt-gen-random num-bytes)
  #-(or unix (and win32 sb-dynamic-core))(error "OS-RANDOM-SEED is not supported on your platform."))

(defgeneric read-os-random-seed (prng &optional source)
  (:documentation "(Re)seed PRNG from PATH."))

(defun read-seed (pseudo-random-number-generator path)
  "Reseed PSEUDO-RANDOM-NUMBER-GENERATOR from PATH.  If PATH doesn't
exist, reseed from /dev/random and then write that seed to PATH."
  (if (probe-file path)
      (internal-read-seed pseudo-random-number-generator path)
      (progn
	(read-os-random-seed pseudo-random-number-generator)
	(write-seed pseudo-random-number-generator path)
	;; FIXME: this only works under SBCL.  It's important, though,
	;; as it sets the proper permissions for reading a seedfile.
	#+sbcl(sb-posix:chmod path (logior sb-posix:S-IRUSR sb-posix:S-IWUSR)))))

(defgeneric internal-read-seed (prng path)
  (:documentation "Reseed PRNG from PATH.."))

(defgeneric write-seed (prng path)
  (:documentation "Write enough random data from PRNG to PATH to
  properly reseed it."))

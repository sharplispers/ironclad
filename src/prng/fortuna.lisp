;;;; fortuna.lisp -- Fortuna PRNG

(in-package :crypto)

(defvar fortuna :fortuna)


(defparameter +min-pool-size+
  128
  "Minimum pool size before a reseed is allowed.  This should be the
  number of bytes of pool data that are likely to contain 128 bits of
  entropy.  Defaults to a pessimistic estimate of 1 bit of entropy per
  byte.")

(defclass pool ()
  ((digest :initform (make-digest :sha256))
   (length :initform 0))
  (:documentation "A Fortuna entropy pool.  DIGEST contains its current
  state; LENGTH the length in bytes of the entropy it contains."))

(defclass fortuna-prng (pseudo-random-number-generator)
  ((pools :initform (loop for i from 1 to 32
		       collect (make-instance 'pool)))
   (reseed-count :initform 0)
   (last-reseed :initform 0)
   (generator :initform (make-instance 'generator)))
  (:documentation "A Fortuna random number generator.  Contains 32
  entropy pools which are used to reseed GENERATOR."))

(defmethod random-data ((pseudo-random-number-generator
			 fortuna-prng)
			num-bytes)
  (when (plusp num-bytes)
    (with-slots (pools generator reseed-count last-reseed)
	pseudo-random-number-generator
      (when (and (>= (slot-value (first pools) 'length) +min-pool-size+)
		 (> (- (get-internal-run-time) last-reseed) 100))
	(incf reseed-count)
	(loop for i from 0 below (length pools)
	   with seed = (make-array (* 32 32) :element-type '(unsigned-byte 8))
	   while (zerop (mod reseed-count (expt 2 i)))
	   collect (with-slots (digest length) (nth i pools)
		     (setf length 0
			   (subseq seed (* i 32))
			   (digest-sequence :sha256 (produce-digest digest))
			   digest (make-digest :sha256)))
	   finally (reseed generator (subseq seed 0 (* 32 i)))))
      (assert (plusp reseed-count))
      (pseudo-random-data generator num-bytes))))


(defun add-random-event (pseudo-random-number-generator source pool-id event)
  (assert (and (<= 1 (length event) 32)
	       (<= 0 source 255)
	       (<= 0 pool-id 31)))
  (let ((pool (nth pool-id (slot-value pseudo-random-number-generator 'pools))))
    (update-digest (slot-value pool 'digest)
			    (concatenate '(vector (unsigned-byte 8))
					 (integer-to-octets source)
					 (integer-to-octets
					  (length event))
					 event))
    (incf (slot-value pool 'length) (length event))))


(defmethod write-seed ((pseudo-random-number-generator fortuna-prng) path)
  (with-open-file (seed-file path
			     :direction :output
			     :if-exists :supersede
			     :if-does-not-exist :create
			     :element-type '(unsigned-byte 8))
    (write-sequence (random-data pseudo-random-number-generator 64) seed-file)))


(defmethod read-os-random-seed ((pseudo-random-number-generator fortuna-prng)
			    &optional (source :random))
  "Read a random seed from /dev/random or equivalent."
  (reseed (slot-value pseudo-random-number-generator 'generator)
	  (os-random-seed source 64))
  (incf (slot-value pseudo-random-number-generator 'reseed-count)))


(defmethod internal-read-seed ((pseudo-random-number-generator fortuna-prng)
			       path)
  (with-open-file (seed-file path
			     :direction :input
			     :element-type '(unsigned-byte 8))
    (let ((seq (make-array 64 :element-type '(unsigned-byte 8))))
      (assert (>= (read-sequence seq seed-file) 64))
      (reseed (slot-value pseudo-random-number-generator 'generator) seq)
      (incf (slot-value pseudo-random-number-generator 'reseed-count ))))
  (write-seed pseudo-random-number-generator path))


(defun feed-fifo (pseudo-random-number-generator path)
  "Feed random data into a FIFO"
  (loop while
       (handler-case (with-open-file 
			 (fortune-out path :direction :output
				      :if-exists :overwrite
				      :element-type '(unsigned-byte 8))
		       (loop do (write-sequence
				 (random-data pseudo-random-number-generator
						      (1- (expt 2 20)))
				 fortune-out)))
	 (stream-error () t))))




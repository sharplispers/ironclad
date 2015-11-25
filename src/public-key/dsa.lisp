;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; dsa.lisp -- implementation of the Digital Signature Algorithm

(in-package :crypto)


;;; class definitions

(defclass dsa-key ()
  ((group :initarg :group :reader group)))

(defclass dsa-public-key (dsa-key)
  ((y :initarg :y :reader dsa-key-y :type integer)))

(defclass dsa-private-key (dsa-key)
  ((y :initarg :y :reader dsa-key-y :type integer)
   (x :initarg :x :reader dsa-key-x :type integer)))

(defun dsa-key-p (dsa-key)
  (group-pval (group dsa-key)))
(defun dsa-key-q (dsa-key)
  (group-qval (group dsa-key)))
(defun dsa-key-g (dsa-key)
  (group-gval (group dsa-key)))


;;; function definitions

(defmethod make-public-key ((kind (eql :dsa))
                            &key p q g y &allow-other-keys)
  (let ((group (make-instance 'discrete-logarithm-group :p p :q q :g g)))
    (make-instance 'dsa-public-key :group group :y y)))

(defmethod make-private-key ((kind (eql :dsa))
                             &key p q g y x &allow-other-keys)
  (unless (and p q g)
    (error "Must specify all members of the DL group for DSA"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :q q :g g)))
    (make-instance 'dsa-private-key :group group :y y :x x)))

(defmethod generate-key-pair ((kind (eql :dsa)) &key num-bits &allow-other-keys)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (n (cond ((< num-bits 512) (error "This DSA key is too small"))
                  ((<= num-bits 1024) 160)
                  ((<= num-bits 2048) 224)
                  ((<= num-bits 3072) 256)
                  ((<= num-bits 7680) 384)
                  ((<= num-bits 15360) 512)
                  (t (error "This DSA key is too big"))))
         (q (generate-safe-prime n prng))
         (p (loop
               for z = (logior (ash 1 (- num-bits n 1))
                               (random-bits (- num-bits n) prng))
               for p = (1+ (* z q))
               until (and (= num-bits (integer-length p))
                          (prime-p p prng))
               finally (return p)))
         (g (find-subgroup-generator p q prng))
         (x (+ 2 (strong-random (- q 2) prng)))
         (y (expt-mod g x p)))
    (values (make-private-key :dsa :p p :q q :g g :y y :x x)
            (make-public-key :dsa :p p :q q :g g :y y))))

(defun dsa-generate-k (q)
  "Generate a random number K so that 0 < K < Q."
  (assert (> q 3))
  (let ((prng (or *prng* (make-prng :fortuna :seed :random))))
    (1+ (strong-random (1- q) prng))))

;;; Note that hashing is not performed here.
(defmethod sign-message ((key dsa-private-key) message &key (start 0) end)
  (let* ((end (or end (length message)))
         (q (dsa-key-q key))
         (qbits (integer-length q)))
    (when (> (* 8 (- end start)) qbits)
      ;; Only keep the required number of bits of message
      (setf end (+ start (/ qbits 8))))
    (let* ((m (octets-to-integer message :start start :end end))
           (p (dsa-key-p key))
           (g (dsa-key-g key))
           (x (dsa-key-x key))
           (k (dsa-generate-k q))
           (r (mod (expt-mod g k p) q))
           (k-inverse (modular-inverse k q))
           (s (mod (* k-inverse (+ (* x r) m)) q)))
      (assert (= (mod (* k k-inverse) q) 1))
      (if (not (or (zerop r) (zerop s)))
          (concatenate '(simple-array (unsigned-byte 8) (*))
                       (integer-to-octets r :n-bits qbits)
                       (integer-to-octets s :n-bits qbits))
          (sign-message key message :start start :end end)))))

(defmethod verify-signature ((key dsa-public-key) message signature &key (start 0) end)
  (let* ((end (or end (length message)))
         (q (dsa-key-q key))
         (qbits (integer-length q)))
    (unless (= (* 4 (length signature)) qbits)
      (error "Bad signature length"))
    (when (> (* 8 (- end start)) qbits)
      ;; Only keep the required number of bits of message
      (setf end (+ start (/ qbits 8))))
    (let* ((m (octets-to-integer message :start start :end end))
           (p (dsa-key-p key))
           (g (dsa-key-g key))
           (y (dsa-key-y key))
           (r (octets-to-integer (subseq signature 0 (/ qbits 8))))
           (s (octets-to-integer (subseq  signature (/ qbits 8) (/ qbits 4)))))
      (unless (and (< 0 r q) (< 0 s q))
        (return-from verify-signature nil))
      (let* ((w (modular-inverse s q))
             (u1 (mod (* m w) q))
             (u2 (mod (* r w) q))
             (v (mod (mod (* (expt-mod g u1 p) (expt-mod y u2 p)) p) q)))
        (= v r)))))

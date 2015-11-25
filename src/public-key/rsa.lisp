;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; rsa.lisp -- implementation of the RSA public key algorithm

(in-package :crypto)


;;; class definitions

(defclass rsa-key ()
  ((n :initarg :n :reader rsa-key-modulus :type integer)))

(defclass rsa-public-key (rsa-key)
  ((e :initarg :e :reader rsa-key-exponent :type integer)))

(defclass rsa-private-key (rsa-key)
  ((d :initarg :d :reader rsa-key-exponent :type integer)))


;;; function definitions

(defmethod make-public-key ((kind (eql :rsa))
                            &key e n &allow-other-keys)
  (unless (and e n)
    (error "Must specify public exponent and modulus"))
  (make-instance 'rsa-public-key :e e :n n))

(defmethod make-private-key ((kind (eql :rsa))
                             &key d n &allow-other-keys)
  (unless (and d n)
    (error "Must specify private exponent and modulus"))
  (make-instance 'rsa-private-key :d d :n n))

(defmethod generate-key-pair ((kind (eql :rsa)) &key num-bits &allow-other-keys)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (l (floor num-bits 2))
         p q n)
    (loop
       for a = (generate-safe-prime (- num-bits l) prng)
       for b = (generate-safe-prime l prng)
       for c = (* a b)
       until (and (/= a b) (= num-bits (integer-length c)))
       finally (setf p a
                     q b
                     n c))
    (let* ((phi (* (1- p) (1- q)))
           (e (loop
                 for e = (+ 2 (strong-random (- phi 2) prng))
                 until (= 1 (gcd e phi))
                 finally (return e)))
           (d (modular-inverse e phi)))
      (values (make-private-key :rsa :d d :n n)
              (make-public-key :rsa :e e :n n)))))

(defun rsa-core (msg exponent modulus)
  (assert (< msg modulus))
  (expt-mod msg exponent modulus))

(defmethod encrypt-message ((key rsa-public-key) msg &key (start 0) end oaep &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key)))
        (m (subseq msg start end)))
    (when oaep
      (setf m (oaep-encode :sha1 m (/ nbits 8))))
    (setf m (octets-to-integer m))
    (integer-to-octets
     (rsa-core m (rsa-key-exponent key) (rsa-key-modulus key))
     :n-bits nbits)))

(defmethod decrypt-message ((key rsa-private-key) msg &key (start 0) end oaep &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key)))
        (m (octets-to-integer msg :start start :end end)))
    (if oaep
        (oaep-decode :sha1 (integer-to-octets
                            (rsa-core m (rsa-key-exponent key) (rsa-key-modulus key))
                            :n-bits nbits))
        (integer-to-octets
         (rsa-core m (rsa-key-exponent key) (rsa-key-modulus key))))))

(defmethod sign-message ((key rsa-private-key) msg &key (start 0) end pss &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key)))
        (m (subseq msg start end)))
    (when pss
      (setf m (pss-encode :sha1 m (/ nbits 8))))
    (setf m (octets-to-integer m))
  (integer-to-octets
   (rsa-core m (rsa-key-exponent key) (rsa-key-modulus key))
   :n-bits nbits)))

(defmethod verify-signature ((key rsa-public-key) msg signature &key (start 0) end pss &allow-other-keys)
  (let ((nbits (integer-length (rsa-key-modulus key))))
    (unless (= (* 8 (length signature)) nbits)
      (error "Bad signature length"))
    (if pss
        (let ((s (integer-to-octets (rsa-core (octets-to-integer signature)
                                              (rsa-key-exponent key) (rsa-key-modulus key))
                                    :n-bits nbits)))
          (pss-verify :sha1 (subseq msg start end) s))
        (let ((s (integer-to-octets (rsa-core (octets-to-integer signature)
                                              (rsa-key-exponent key) (rsa-key-modulus key)))))
          (equalp s (subseq msg start end))))))

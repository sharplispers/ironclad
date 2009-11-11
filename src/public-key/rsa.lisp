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

(defun rsa-core (msg exponent modulus)
  (expt-mod msg exponent modulus))

(defmethod encrypt-message ((key rsa-private-key) msg &key (start 0) end)
  (integer-to-octets
   (rsa-core (octets-to-integer msg :start start :end end)
             (rsa-key-exponent key) (rsa-key-modulus key))))

(defmethod encrypt-message ((key rsa-public-key) msg &key (start 0) end)
  (integer-to-octets
   (rsa-core (octets-to-integer msg :start start :end end)
             (rsa-key-exponent key) (rsa-key-modulus key))))

(defmethod decrypt-message ((key rsa-private-key) msg &key (start 0) end)
  (integer-to-octets
   (rsa-core (octets-to-integer msg :start start :end end)
             (rsa-key-exponent key) (rsa-key-modulus key))))

(defmethod decrypt-message ((key rsa-public-key) msg &key (start 0) end)
  (integer-to-octets
   (rsa-core (octets-to-integer msg :start start :end end)
             (rsa-key-exponent key) (rsa-key-modulus key))))

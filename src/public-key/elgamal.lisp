;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; elgamal.lisp -- implementation of the ElGamal encryption and signature scheme

(in-package :crypto)


;;; class definitions

(defclass elgamal-key ()
  ((group :initarg :group :reader group)))

(defclass elgamal-public-key (elgamal-key)
  ((y :initarg :y :reader elgamal-key-y :type integer)))

(defclass elgamal-private-key (elgamal-key)
  ((y :initarg :y :reader elgamal-key-y :type integer)
   (x :initarg :x :reader elgamal-key-x :type integer)))

(defun elgamal-key-p (elgamal-key)
  (group-pval (group elgamal-key)))

(defun elgamal-key-g (elgamal-key)
  (group-gval (group elgamal-key)))


;;; function definitions

(defmethod make-public-key ((kind (eql :elgamal))
                            &key p g y &allow-other-keys)
  (unless (and p g y)
    (error "P, G and Y must be specified"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-public-key :group group :y y)))

(defmethod make-private-key ((kind (eql :elgamal))
                             &key p g y x &allow-other-keys)
  (unless (and p g x)
    (error "P, G and X must be specified"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-private-key :group group :x x :y (or y (expt-mod g x p)))))

(defmethod generate-key-pair ((kind (eql :elgamal)) &key num-bits &allow-other-keys)
  (let* ((p (generate-safe-prime num-bits))
         (g (find-generator p))
         (x (+ 2 (strong-random (- p 3))))
         (y (expt-mod g x p)))
    (values (make-private-key :elgamal :p p :g g :y y :x x)
            (make-public-key :elgamal :p p :g g :y y))))

(declaim (notinline elgamal-generate-k))
;; In the tests, this function is redefined to use a constant value
;; instead of a random one. Therefore it must not be inlined or the tests
;; will fail.
(defun elgamal-generate-k (p)
  "Generate a random number K so that 0 < K < P - 1, and K is relatively prime to P - 1."
  (assert (> p 3))
  (loop
     for k = (+ 1 (strong-random (- p 2)))
     until (= 1 (gcd k (- p 1)))
     finally (return k)))

(defmethod make-message ((kind (eql :elgamal)) &key c1 c2 n-bits &allow-other-keys)
  (if (and c1 c2 n-bits)
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   (integer-to-octets c1 :n-bits n-bits)
                   (integer-to-octets c2 :n-bits n-bits))
      (error "C1, C2 and N-BITS must be specified")))

(defmethod destructure-message ((kind (eql :elgamal)) message)
  (let ((length (length message)))
    (if (oddp length)
        (error "Bad message length")
        (let* ((middle (/ length 2))
               (n-bits (* middle 8))
               (c1 (octets-to-integer message :start 0 :end middle))
               (c2 (octets-to-integer message :start middle)))
          (list :c1 c1 :c2 c2 :n-bits n-bits)))))

(defun elgamal-encrypt (msg key)
  (let* ((m (octets-to-integer msg))
         (p (elgamal-key-p key))
         (pbits (integer-length p))
         (g (elgamal-key-g key))
         (y (elgamal-key-y key))
         (k (elgamal-generate-k p))
         (c1 (expt-mod g k p))
         (c2 (mod (* m (expt-mod y k p)) p)))
    (unless (< m p)
      (error "Message can't be bigger than the order of the DL group"))
    (make-message :elgamal :c1 c1 :c2 c2 :n-bits pbits)))

(defun elgamal-decrypt (ciphertext key)
  (let* ((p (elgamal-key-p key))
         (pbits (integer-length p))
         (g (elgamal-key-g key))
         (x (elgamal-key-x key))
         (message-elements (destructure-message :elgamal ciphertext))
         (c1 (getf message-elements :c1))
         (c2 (getf message-elements :c2))
         (m (mod (* c2 (modular-inverse (expt-mod c1 x p) p)) p)))
    (integer-to-octets m)))

(defmethod encrypt-message ((key elgamal-private-key) msg &key (start 0) end &allow-other-keys)
  (let ((public-key (make-public-key :elgamal
                                     :p (elgamal-key-p key)
                                     :g (elgamal-key-g key)
                                     :y (elgamal-key-y key))))
    (encrypt-message public-key msg :start start :end end)))

(defmethod encrypt-message ((key elgamal-public-key) msg &key (start 0) end &allow-other-keys)
  (elgamal-encrypt (subseq msg start end) key))

(defmethod decrypt-message ((key elgamal-private-key) msg &key (start 0) end &allow-other-keys)
  (let* ((p (elgamal-key-p key))
         (end (or end (length msg))))
    (unless (= (* 4 (- end start)) (integer-length p))
      (error "Bad ciphertext length"))
    (elgamal-decrypt (subseq msg start end) key)))

(defmethod make-signature ((kind (eql :elgamal)) &key r s n-bits &allow-other-keys)
  (if (and r s n-bits)
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   (integer-to-octets r :n-bits n-bits)
                   (integer-to-octets s :n-bits n-bits))
      (error "R, S and N-BITS must be specified")))

(defmethod destructure-signature ((kind (eql :elgamal)) signature)
  (let ((length (length signature)))
    (if (oddp length)
        (error "Bad signature length")
        (let* ((middle (/ length 2))
               (n-bits (* middle 8))
               (r (octets-to-integer signature :start 0 :end middle))
               (s (octets-to-integer signature :start middle)))
          (list :r r :s s :n-bits n-bits)))))

(defmethod sign-message ((key elgamal-private-key) msg &key (start 0) end &allow-other-keys)
  (let* ((m (octets-to-integer msg :start start :end end))
         (p (elgamal-key-p key))
         (pbits (integer-length p)))
    (unless (< m (- p 1))
      (error "Message can't be bigger than the order of the DL group minus 1"))
    (let* ((g (elgamal-key-g key))
           (x (elgamal-key-x key))
           (k (elgamal-generate-k p))
           (r (expt-mod g k p))
           (s (mod (* (- m (* r x)) (modular-inverse k (- p 1))) (- p 1))))
      (if (not (zerop s))
          (make-signature :elgamal :r r :s s :n-bits pbits)
          (sign-message key msg :start start :end end)))))

(defmethod verify-signature ((key elgamal-public-key) msg signature &key (start 0) end &allow-other-keys)
  (let* ((m (octets-to-integer msg :start start :end end))
         (p (elgamal-key-p key))
         (pbits (integer-length p)))
    (unless (= (* 4 (length signature)) pbits)
      (error "Bad signature length"))
    (unless (< m (- p 1))
      (error "Message can't be bigger than the order of the DL group minus 1"))
    (let* ((g (elgamal-key-g key))
           (y (elgamal-key-y key))
           (signature-elements (destructure-signature :elgamal signature))
           (r (getf signature-elements :r))
           (s (getf signature-elements :s)))
      (and (< 0 r p)
           (< 0 s (- p 1))
           (= (expt-mod g m p)
              (mod (* (expt-mod y r p) (expt-mod r s p)) p))))))

(defmethod diffie-hellman ((private-key elgamal-private-key) (public-key elgamal-public-key))
  (let ((p (elgamal-key-p private-key))
        (p1 (elgamal-key-p public-key))
        (g (elgamal-key-g private-key))
        (g1 (elgamal-key-g public-key)))
    (unless (and (= p p1) (= g g1))
      (error "The keys are not in the same DL group"))
    (let ((pbits (integer-length p))
          (x (elgamal-key-x private-key))
          (y (elgamal-key-y public-key)))
      (integer-to-octets (expt-mod y x p) :n-bits pbits))))

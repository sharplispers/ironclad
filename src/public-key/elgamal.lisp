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
    (error "Must specify all members of the DL group for ELGAMAL"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-public-key :group group :y y)))

(defmethod make-private-key ((kind (eql :elgamal))
                             &key p g y x &allow-other-keys)
  (unless (and p g y x)
    (error "Must specify all members of the DL group for ELGAMAL"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-private-key :group group :y y :x x)))

(defmethod generate-key-pair ((kind (eql :elgamal)) &key num-bits &allow-other-keys)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (p (generate-safe-prime num-bits prng))
         (g (find-generator p prng))
         (x (+ 2 (strong-random (- p 3) prng)))
         (y (expt-mod g x p)))
    (values (make-private-key :elgamal :p p :g g :y y :x x)
            (make-public-key :elgamal :p p :g g :y y))))

(defun elgamal-generate-k (p)
  "Generate a random number K so that 0 < K < P - 1, and K is relatively prime to P - 1."
  (assert (> p 3))
  (let ((prng (or *prng* (make-prng :fortuna :seed :random))))
    (loop
       for k = (+ 1 (strong-random (- p 2) prng))
       until (= 1 (gcd k (- p 1)))
       finally (return k))))

;; TODO: integer-to-octets as big endian or little endian?
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
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (integer-to-octets c1 :n-bits pbits)
                 (integer-to-octets c2 :n-bits pbits))))

(defun elgamal-decrypt (ciphertext key)
  (let* ((p (elgamal-key-p key))
         (pbits (integer-length p))
         (g (elgamal-key-g key))
         (x (elgamal-key-x key))
         (c1 (octets-to-integer (subseq ciphertext 0 (/ pbits 8))))
         (c2 (octets-to-integer (subseq ciphertext (/ pbits 8) (/ pbits 4))))
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
          (concatenate '(simple-array (unsigned-byte 8) (*))
                       (integer-to-octets r :n-bits pbits)
                       (integer-to-octets s :n-bits pbits))
          (sign-message key msg :start start :end end)))))

(defmethod verify-signature ((key elgamal-public-key) msg signature &key (start 0) end &allow-other-keys)
  (let* ((m (octets-to-integer msg :start start :end end))
         (p (elgamal-key-p key))
         (pbits (integer-length p)))
    (unless (= (* 4 (length signature)) pbits)
      (error "Bad signature length"))
    (unless (< m (- p 1))
      ;; FIXME: "real" ironclad error needed here
      (error "Message can't be bigger than the order of the DL group minus 1"))
    (let* ((g (elgamal-key-g key))
           (y (elgamal-key-y key))
           (r (octets-to-integer (subseq signature 0 (/ pbits 8))))
           (s (octets-to-integer (subseq  signature (/ pbits 8) (/ pbits 4)))))
      (and (< 0 r p)
           (< 0 s (- p 1))
           (= (expt-mod g m p)
              (mod (* (expt-mod y r p) (expt-mod r s p)) p))))))

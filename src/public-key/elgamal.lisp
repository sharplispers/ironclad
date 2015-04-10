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

(defclass elgamal-ciphertext ()
  ((c1 :initarg :c1 :reader elgamal-ciphertext-c1)
   (c2 :initarg :c2 :reader elgamal-ciphertext-c2)))

(defclass elgamal-signature ()
  ((r :initarg :r :reader elgamal-signature-r)
   (s :initarg :s :reader elgamal-signature-s)))

(defun elgamal-key-p (elgamal-key)
  (group-pval (group elgamal-key)))

(defun elgamal-key-g (elgamal-key)
  (group-gval (group elgamal-key)))


;;; function definitions

(defmethod make-public-key ((kind (eql :elgamal))
                            &key p g y &allow-other-keys)
  (unless (and p g y)
    ;; FIXME: "real" ironclad error needed here
    (error "Must specify all members of the DL group for ELGAMAL"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-public-key :group group :y y)))

(defmethod make-private-key ((kind (eql :elgamal))
                             &key p g y x &allow-other-keys)
  (unless (and p g y x)
    ;; FIXME: "real" ironclad error needed here
    (error "Must specify all members of the DL group for ELGAMAL"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :g g)))
    (make-instance 'elgamal-private-key :group group :y y :x x)))

(defmethod generate-new-key-pair ((kind (eql :elgamal)) num-bits
                                  &key &allow-other-keys)
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (p (generate-safe-prime num-bits prng))
         (g (find-generator p prng))
         (x (+ 2 (strong-random (- p 3) prng)))
         (y (expt-mod g x p)))
    (values (make-private-key :elgamal :p p :g g :y y :x x)
            (make-public-key :elgamal :p p :g g :y y))))

(defun make-elgamal-ciphertext (c1 c2)
  (make-instance 'elgamal-ciphertext
                 :c1 (maybe-integerize c1)
                 :c2 (maybe-integerize c2)))

(defun make-elgamal-signature (r s)
  (make-instance 'elgamal-signature
                 :r (maybe-integerize r)
                 :s (maybe-integerize s)))

(defun elgamal-generate-k (p)
  "Generate a random number K so that 0 < K < P - 1, and K is relatively prime to P - 1."
  (assert (> p 3))
  (let ((prng (or *prng* (make-prng :fortuna :seed :random))))
    (loop
       for k = (+ 1 (strong-random (- p 2) prng))
       until (= 1 (gcd k (- p 1)))
       finally (return k))))

(defun elgamal-encrypt (msg key)
  (let* ((p (elgamal-key-p key))
         (g (elgamal-key-g key))
         (y (elgamal-key-y key))
         (k (elgamal-generate-k p))
         (c1 (expt-mod g k p))
         (c2 (mod (* msg (expt-mod y k p)) p)))
    (make-elgamal-ciphertext c1 c2)))

(defun elgamal-decrypt (ciphertext key)
  (let* ((p (elgamal-key-p key))
         (g (elgamal-key-g key))
         (x (elgamal-key-x key))
         (c1 (elgamal-ciphertext-c1 ciphertext))
         (c2 (elgamal-ciphertext-c2 ciphertext)))
    (mod (* c2 (modular-inverse (expt-mod c1 x p) p)) p)))

(defmethod encrypt-message ((key elgamal-private-key) msg &key (start 0) end)
  (let ((public-key (make-public-key :elgamal
                                     :p (elgamal-key-p key)
                                     :g (elgamal-key-g key)
                                     :y (elgamal-key-y key))))
    (encrypt-message public-key msg :start start :end end)))

(defmethod encrypt-message ((key elgamal-public-key) msg &key (start 0) end)
  (let ((m (octets-to-integer msg :start start :end end))
        (p (elgamal-key-p key)))
    (unless (< m p)
      ;; FIXME: "real" ironclad error needed here
      (error "Message can't be bigger than the order of the DL group"))
    (let ((n (integer-length p))
          (c (elgamal-encrypt m key)))
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   (integer-to-octets (elgamal-ciphertext-c1 c) :n-bits n)
                   (integer-to-octets (elgamal-ciphertext-c2 c) :n-bits n)))))

(defmethod decrypt-message ((key elgamal-private-key) msg &key (start 0) end)
  (let* ((p (elgamal-key-p key))
         (g (elgamal-key-g key))
         (x (elgamal-key-x key))
         (end (or end (length msg))))
    (unless (= (- end start) (* 2 (ceiling (integer-length p) 8)))
      ;; FIXME: "real" ironclad error needed here
      (error "Ciphertext size must be twice the order of the DL group"))
    (let* ((half-length (/ (- end start) 2))
           (c1 (octets-to-integer msg :start start :end half-length))
           (c2 (octets-to-integer msg :start half-length :end end))
           (c (make-elgamal-ciphertext c1 c2)))
      (integer-to-octets (elgamal-decrypt c key)))))

(defmethod sign-message ((key elgamal-private-key) msg &key (start 0) end)
  (let* ((m (octets-to-integer msg :start start :end end))
         (p (elgamal-key-p key)))
    (unless (< m (- p 1))
      ;; FIXME: "real" ironclad error needed here
      (error "Message can't be bigger than the order of the DL group minus 1"))
    (let* ((g (elgamal-key-g key))
           (x (elgamal-key-x key))
           (k (elgamal-generate-k p))
           (r (expt-mod g k p))
           (s (mod (* (- m (* r x)) (modular-inverse k (- p 1))) (- p 1))))
      (if (not (zerop s))
          (make-elgamal-signature r s)
          (sign-message key msg :start start :end end)))))

(defmethod verify-signature ((key elgamal-private-key) msg (signature elgamal-signature)
                             &key (start 0) end)
  (let* ((m (octets-to-integer msg :start start :end end))
         (p (elgamal-key-p key)))
    (unless (< m (- p 1))
      ;; FIXME: "real" ironclad error needed here
      (error "Message can't be bigger than the order of the DL group minus 1"))
    (let* ((g (elgamal-key-g key))
           (y (elgamal-key-y key))
           (r (maybe-integerize (elgamal-signature-r signature)))
           (s (maybe-integerize (elgamal-signature-s signature))))
      (and (< 0 r p)
           (< 0 s (- p 1))
           (= (expt-mod g m p)
              (mod (* (expt-mod y r p) (expt-mod r s p)) p))))))

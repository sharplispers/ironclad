;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

(defun hex-string-to-byte-array (string &key (start 0) (end nil))
  ;; This function disappears from profiles if SBCL can inline the
  ;; POSITION call, so declare SPEED high enough to trigger that.
  (declare (type string string) (optimize (speed 2)))
  (let* ((end (or end (length string)))
         (length (/ (- end start) 2))
         (key (make-array length :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) key))
    (flet ((char-to-digit (char)
             (declare (type base-char char))
             (let ((x (cl:position char #.(coerce "0123456789abcdef" 'simple-base-string)
                                   :test #'char-equal)))
               (or x (error "Invalid hex key ~A specified" string)))))
      (loop for i from 0
            for j from start below end by 2
            do (setf (aref key i)
                     (+ (* (char-to-digit (char string j)) 16)
                        (char-to-digit (char string (1+ j)))))
            finally (return key)))))


;;; test vector files

(defun test-vector-filename (ident)
  (merge-pathnames (make-pathname :directory '(:relative "test-vectors")
                                  :name (substitute #\- #\/ (format nil "~(~A~)" ident))
                                  :type "testvec")
                   #.*compile-file-pathname*))

(defun sharp-a (stream sub-char numarg)
  (declare (ignore sub-char numarg))
  (crypto:ascii-string-to-byte-array (read stream t nil t)))

(defun sharp-h (stream sub-char numarg)
  (declare (ignore sub-char numarg))
  (hex-string-to-byte-array (read stream t nil t)))

(defun run-test-vector-file (name function-map)
  (let ((filename (test-vector-filename name))
        (*readtable* (copy-readtable)))
    (set-dispatch-macro-character #\# #\a #'sharp-a *readtable*)
    (set-dispatch-macro-character #\# #\h #'sharp-h *readtable*)
    (with-open-file (stream filename :direction :input
                            :element-type 'character
                            :if-does-not-exist :error)
      (loop for form = (read stream nil stream)
         until (eq form stream) do
         (cond
           ((not (listp form))
            (error "Invalid form in test vector file ~A: ~A" filename form))
           (t
            (let ((test-function (cdr (assoc (car form) function-map))))
              (unless test-function
                (error "No test function defined for ~A" (car form)))
              (apply test-function name (cdr form)))))
         finally (return t)))))

;;; cipher testing

(defun ecb-mode-test (cipher-name hexkey hexinput hexoutput)
  (cipher-test-guts cipher-name :ecb hexkey hexinput hexoutput))

(defun ecb-tweak-mode-test (cipher-name hexkey hextweak hexinput hexoutput)
  (cipher-test-guts cipher-name :ecb hexkey hexinput hexoutput
                    (list :tweak hextweak)))

(defun stream-mode-test (cipher-name hexkey hexinput hexoutput)
  (cipher-test-guts cipher-name :stream hexkey hexinput hexoutput))

(defun stream-nonce-mode-test (cipher-name hexkey hexiv hexinput hexoutput)
  (cipher-test-guts cipher-name :stream hexkey hexinput hexoutput
                    (list :initialization-vector hexiv)))

(defparameter *cipher-tests*
  (list (cons :ecb-mode-test 'ecb-mode-test)
        (cons :ecb-tweak-mode-test 'ecb-tweak-mode-test)
        (cons :stream-mode-test 'stream-mode-test)
        (cons :stream-nonce-mode-test 'stream-nonce-mode-test)))

(defun cipher-test-guts (cipher-name mode key input output
                         &optional extra-make-cipher-args)
  (labels ((frob-hex-string (func input)
             (let ((cipher (apply #'crypto:make-cipher cipher-name
                                  :key key :mode mode
                                  extra-make-cipher-args))
                    (scratch (copy-seq input)))
               (funcall func cipher input scratch)
               scratch))
           (cipher-test (func input output)
             (not (mismatch (frob-hex-string func input) output))))
    (unless (cipher-test 'crypto:encrypt input output)
      (error "encryption failed for ~A on key ~A, input ~A, output ~A"
             cipher-name key input output))
    (unless (cipher-test 'crypto:decrypt output input)
      (error "decryption failed for ~A on key ~A, input ~A, output ~A"
             cipher-name key output input))))

;;; encryption mode consistency checking

;;; tests from NIST

(defun mode-test (mode cipher-name key iv input output)
  (labels ((frob-hex-string (cipher func input)
             (let ((scratch (copy-seq input)))
               (funcall func cipher input scratch)
               scratch))
           (cipher-test (cipher func input output)
             (not (mismatch (frob-hex-string cipher func input) output))))
    (let ((cipher (crypto:make-cipher cipher-name :key key :mode mode
                                      :initialization-vector iv)))
      (unless (cipher-test cipher 'crypto:encrypt input output)
        (error "encryption failed for ~A on key ~A, input ~A, output ~A"
               cipher-name key input output))
      (reinitialize-instance cipher :key key :mode mode
                             :initialization-vector iv)
      (unless (cipher-test cipher 'crypto:decrypt output input)
        (error "decryption failed for ~A on key ~A, input ~A, output ~A"
               cipher-name key output input)))))

(defparameter *mode-tests*
  (list (cons :mode-test 'mode-test)))


;;; digest testing routines

(defun digest-test/base (digest-name input expected-digest)
  (let ((result (crypto:digest-sequence digest-name input)))
    (when (mismatch result expected-digest)
      (error "one-shot ~A digest of ~S failed" digest-name input))))

(defun digest-test/incremental (digest-name input expected-digest)
  (loop with length = (length input)
     with digester = (crypto:make-digest digest-name)
     for i from 0 below length
     do (crypto:update-digest digester input :start i :end (1+ i))
     finally
     (let ((result (crypto:produce-digest digester)))
       (when (mismatch result expected-digest)
         (error "incremental ~A digest of ~S failed" digest-name input)))))

#+(or sbcl cmucl)
(defun digest-test/fill-pointer (digest-name octets expected-digest)
  (let* ((input (let ((x (make-array (* 2 (length octets))
                                     :fill-pointer 0
                                     :element-type '(unsigned-byte 8))))
                  (dotimes (i (length octets) x)
                    (vector-push (aref octets i) x))))
         (result (crypto:digest-sequence digest-name input)))
    (when (mismatch result expected-digest)
      (error "fill-pointer'd ~A digest of ~S failed" digest-name input))))

#+(or lispworks sbcl cmucl openmcl allegro)
(defun digest-test/stream (digest-name input expected-digest)
  (let* ((stream (crypto:make-digesting-stream digest-name)))
    (write-sequence input stream)
    (when (mismatch (crypto:produce-digest stream) expected-digest)
      (error "stream-y ~A digest of ~S failed" digest-name input))))

(defun digest-test/reinitialize-instance (digest-name input expected-digest)
  (let* ((digest (crypto:make-digest digest-name))
         (result (progn
                   (crypto:digest-sequence digest input)
                   (crypto:digest-sequence (reinitialize-instance digest) input))))
    (when (mismatch result expected-digest)
      (error "testing reinitialize-instance ~A digest of ~S failed" digest-name input))))

(defun digest-bit-test (digest-name leading byte trailing expected-digest)
  (let* ((input (let ((vector (make-array (+ 1 leading trailing)
                                          :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
                  (setf (aref vector leading) byte)
                  vector))
         (result (crypto:digest-sequence digest-name input)))
    (when (mismatch result expected-digest)
      (error "individual bit test ~A digest of (~D #x~2,'0X ~D) failed"
             digest-name leading byte trailing))))

(defun xof-digest-test (digest-name output-length input expected-digest)
  (let* ((digest (crypto:make-digest digest-name :output-length output-length))
         (result (crypto:digest-sequence digest input)))
    (when (mismatch result expected-digest)
      (error "one-shot ~A xof digest of ~S failed" digest-name input))))

(defparameter *digest-tests*
  (list (cons :digest-test 'digest-test/base)
        (cons :digest-bit-test 'digest-bit-test)
        (cons :xof-digest-test 'xof-digest-test)))

(defun ignore-test (&rest args)
  (declare (ignore args))
  nil)

(defparameter *digest-incremental-tests*
  (list (cons :digest-test 'digest-test/incremental)
        (cons :digest-bit-test 'ignore-test)
        (cons :xof-digest-test 'ignore-test)))

#+(or sbcl cmucl)
(defparameter *digest-fill-pointer-tests*
  (list (cons :digest-test 'digest-test/fill-pointer)
        (cons :digest-bit-test 'ignore-test)
        (cons :xof-digest-test 'ignore-test)))

#+(or lispworks sbcl cmucl openmcl allegro)
(defparameter *digest-stream-tests*
  (list (cons :digest-test 'digest-test/stream)
        (cons :digest-bit-test 'ignore-test)
        (cons :xof-digest-test 'ignore-test)))

(defparameter *digest-reinitialize-instance-tests*
  (list (cons :digest-test 'digest-test/reinitialize-instance)
        (cons :digest-bit-test 'ignore-test)
        (cons :xof-digest-test 'ignore-test)))


;;; mac testing routines

(defun hmac-test (name digest-name key data expected-digest)
  (declare (ignore name))
  (let ((hmac (ironclad:make-hmac key digest-name)))
    (ironclad:update-hmac hmac data)
    (when (mismatch expected-digest (ironclad:hmac-digest hmac))
      (error "HMAC/~A failed on key ~A, input ~A, output ~A"
             digest-name key data expected-digest))
    (loop
       initially (reinitialize-instance hmac :key key)
       for i from 0 below (length data)
       do (ironclad:update-hmac hmac data :start i :end (1+ i))
       (ironclad:hmac-digest hmac)
       finally (when (mismatch expected-digest (ironclad:hmac-digest hmac))
                 (error "progressive HMAC/~A failed on key ~A, input ~A, output ~A"
                        digest-name key data expected-digest)))))

(defun cmac-test (name cipher-name key data expected-digest)
  (declare (ignore name))
  (let ((cmac (ironclad:make-cmac key cipher-name)))
    (ironclad:update-cmac cmac data)
    (when (mismatch expected-digest (ironclad:cmac-digest cmac))
      (error "CMAC/~A failed on key ~A, input ~A, output ~A"
             cipher-name key data expected-digest))))

(defun skein-mac-test (name block-length digest-length key data expected-digest)
  (declare (ignore name))
  (let ((mac (ironclad:make-skein-mac key
                                      :block-length block-length
                                      :digest-length digest-length)))
    (ironclad:update-skein-mac mac data)
    (when (mismatch expected-digest (ironclad:skein-mac-digest mac))
      (error "SKEIN-MAC(~A/~A) failed on key ~A, input ~A, output ~A"
             block-length digest-length key data expected-digest))
    (loop
       initially (reinitialize-instance mac :key key)
       for i from 0 below (length data)
       do (progn
            (ironclad:update-skein-mac mac data :start i :end (1+ i))
            (ironclad:skein-mac-digest mac))
       finally (when (mismatch expected-digest (ironclad:skein-mac-digest mac))
                 (error "progressive SKEIN-MAC(~A/~A) failed on key ~A, input ~A, output ~A"
                        block-length digest-length key data expected-digest)))))

(defun poly1305-test (name key data expected-digest)
  (declare (ignore name))
  (let ((mac (ironclad:make-poly1305 key)))
    (ironclad:update-poly1305 mac data)
    (when (mismatch expected-digest (ironclad:poly1305-digest mac))
      (error "POLY1305 failed on key ~A, input ~A, output ~A"
             key data expected-digest))
    (loop
       initially (reinitialize-instance mac :key key)
       for i from 0 below (length data)
       do (progn
            (ironclad:update-poly1305 mac data :start i :end (1+ i))
            (ironclad:poly1305-digest mac))
       finally (when (mismatch expected-digest (ironclad:poly1305-digest mac))
                 (error "progressive POLY1305 failed on key ~A, input ~A, output ~A"
                        key data expected-digest)))))

(defparameter *mac-tests*
  (list (cons :hmac-test 'hmac-test)
        (cons :cmac-test 'cmac-test)
        (cons :skein-mac-test 'skein-mac-test)
        (cons :poly1305-test 'poly1305-test)))


;;; PRNG testing routines
(defun fortuna-test (name seed entropy expected-sequence)
  (declare (ignore name))
  (let ((prng (crypto:make-prng :fortuna
                                :seed (coerce seed 'crypto::simple-octet-vector)))
        (num-bytes (length expected-sequence)))
    (loop for (source pool-id event) in entropy
       do (crypto:add-random-event source pool-id event prng))
    (equalp expected-sequence
            (crypto:random-data num-bytes prng))))

(defun generator-test (name cipher seeds expected-sequences)
  (declare (ignore name))
  (let ((generator (make-instance 'crypto::generator :cipher cipher)))
    (loop for seed in seeds
       do (crypto::reseed generator (coerce seed '(vector (unsigned-byte 8)))))
    (every (lambda (sequence)
             (assert (zerop (mod (length sequence) 16)))
             (equalp sequence
                     (crypto::generate-blocks generator
                                              (/ (length sequence) 16))))
           expected-sequences)))

(defparameter *prng-tests*
  `((:fortuna-test . ,'fortuna-test)
    (:generator-test . ,'generator-test)))


;;; Public key testing routines

(defun rsa-oaep-encryption-test (name n e d input seed output)
  ;; Redefine oaep-encode to use a defined seed for the test instead of a random one
  (setf (symbol-function 'ironclad:oaep-encode)
        (lambda (digest-name message num-bytes &optional label)
          (let ((digest-len (ironclad:digest-length digest-name)))
            (assert (<= (length message) (- num-bytes (* 2 digest-len) 2)))
            (let* ((digest (ironclad:make-digest digest-name))
                   (label (or label (coerce #() '(vector (unsigned-byte 8)))))
                   (padding-len (- num-bytes (length message) (* 2 digest-len) 2))
                   (padding (make-array padding-len :element-type '(unsigned-byte 8) :initial-element 0))
                   (l-hash (ironclad:digest-sequence digest label))
                   (db (concatenate '(vector (unsigned-byte 8)) l-hash padding #(1) message))
                   (db-mask (ironclad::mgf digest-name seed (- num-bytes digest-len 1)))
                   (masked-db (map '(vector (unsigned-byte 8)) #'logxor db db-mask))
                   (seed-mask (ironclad::mgf digest-name masked-db digest-len))
                   (masked-seed (map '(vector (unsigned-byte 8)) #'logxor seed seed-mask)))
              (concatenate '(vector (unsigned-byte 8)) #(0) masked-seed masked-db)))))

  (let* ((pk (ironclad:make-public-key :rsa :n n :e e))
         (sk (ironclad:make-private-key :rsa :n n :d d))
         (c (ironclad:encrypt-message pk input :oaep t))
         (m (ironclad:decrypt-message sk output :oaep t)))
    (when (mismatch c output)
      (error "encryption failed for ~A on pkey (~A ~A), input ~A, output ~A"
             name n e input output))
    (when (mismatch m input)
      (error "decryption failed for ~A on skey (~A ~A), input ~A, output ~A"
             name n d input output))))

(defun elgamal-encryption-test (name p g x y input k output)
  ;; Redefine elgamal-generate-k to use a defined K for the test instead of a random one
  (setf (symbol-function 'ironclad::elgamal-generate-k)
        (lambda (p)
          (declare (ignore p))
          k))

  (let* ((pk (ironclad:make-public-key :elgamal :p p :g g :y y))
         (sk (ironclad:make-private-key :elgamal :p p :g g :x x :y y))
         (c (ironclad:encrypt-message pk input))
         (m (ironclad:decrypt-message sk output)))
    (when (mismatch c output)
      (error "encryption failed for ~A on pkey (~A ~A ~A), input ~A, output ~A"
             name p g y input output))
    (when (mismatch m input)
      (error "decryption failed for ~A on skey (~A ~A ~A ~A), input ~A, output ~A"
             name p g x y input output))))

(defun rsa-pss-signature-test (name n e d input salt signature)
  ;; Redefine pss-encode to use a defined salt for the test instead of a random one
  (setf (symbol-function 'ironclad:pss-encode)
        (lambda (digest-name message num-bytes)
          (let ((digest-len (ironclad:digest-length digest-name)))
            (assert (>= num-bytes (+ (* 2 digest-len) 2)))
            (let* ((m-hash (ironclad:digest-sequence digest-name message))
                   (m1 (concatenate '(vector (unsigned-byte 8)) #(0 0 0 0 0 0 0 0) m-hash salt))
                   (h (ironclad:digest-sequence digest-name m1))
                   (ps (make-array (- num-bytes (* 2 digest-len) 2)
                                   :element-type '(unsigned-byte 8)
                                   :initial-element 0))
                   (db (concatenate '(vector (unsigned-byte 8)) ps #(1) salt))
                   (db-mask (ironclad::mgf digest-name h (- num-bytes digest-len 1)))
                   (masked-db (map '(vector (unsigned-byte 8)) #'logxor db db-mask)))
              (setf (ldb (byte 1 7) (elt masked-db 0)) 0)
              (concatenate '(vector (unsigned-byte 8)) masked-db h #(188))))))

  (let* ((pk (ironclad:make-public-key :rsa :n n :e e))
         (sk (ironclad:make-private-key :rsa :n n :d d))
         (s (ironclad:sign-message sk input :pss t)))
    (when (mismatch s signature)
      (error "signature failed for ~A on skey (~A ~A), input ~A, signature ~A"
             name n d input signature))
    (unless (ironclad:verify-signature pk input signature :pss t)
      (error "signature verification failed for ~A on pkey (~A ~A), input ~A, signature ~A"
             name n e input signature))))

(defun elgamal-signature-test (name p g x y input k signature)
  ;; Redefine elgamal-generate-k to use a defined K for the test instead of a random one
  (setf (symbol-function 'ironclad::elgamal-generate-k)
        (lambda (p)
          (declare (ignore p))
          k))

  (let* ((pk (ironclad:make-public-key :elgamal :p p :g g :y y))
         (sk (ironclad:make-private-key :elgamal :p p :g g :x x :y y))
         (s (ironclad:sign-message sk input)))
    (when (mismatch s signature)
      (error "signature failed for ~A on skey (~A ~A ~A ~A), input ~A, signature ~A"
             name p g x y input signature))
    (unless (ironclad:verify-signature pk input signature)
      (error "signature verification failed for ~A on pkey (~A ~A ~A), input ~A, signature ~A"
             name p g y input signature))))

(defun dsa-signature-test (name p q g x y input k signature)
  ;; Redefine dsa-generate-k to use a defined K for the test instead of a random one
  (setf (symbol-function 'ironclad::dsa-generate-k)
        (lambda (q)
          (declare (ignore q))
          k))

  (let* ((sk (ironclad:make-private-key :dsa :p p :q q :g g :x x :y y))
         (pk (ironclad:make-public-key :dsa :p p :q q :g g :y y))
         (s (ironclad:sign-message sk input)))
    (when (mismatch s signature)
      (error "signature failed for ~A on skey (~A ~A ~A ~A ~A), input ~A, signature ~A"
             name p q g x y input signature))
    (unless (ironclad:verify-signature pk input signature)
      (error "signature verification failed for ~A on pkey (~A ~A ~A ~A), input ~A, signature ~A"
             name p q g y input signature))))

(defun ed25519-signature-test (name skey pkey input signature)
  (let* ((sk (ironclad:make-private-key :ed25519 :x skey :y pkey))
         (pk (ironclad:make-public-key :ed25519 :y pkey))
         (s (ironclad:sign-message sk input)))
    (when (mismatch s signature)
      (error "signature failed for ~A on skey ~A, input ~A, signature ~A"
             name skey input signature))
    (unless (ironclad:verify-signature pk input signature)
      (error "signature verification failed for ~A on pkey ~A, input ~A, signature ~A"
             name pkey input signature))))

(defun ed448-signature-test (name skey pkey input signature)
  (let* ((sk (ironclad:make-private-key :ed448 :x skey :y pkey))
         (pk (ironclad:make-public-key :ed448 :y pkey))
         (s (ironclad:sign-message sk input)))
    (when (mismatch s signature)
      (error "signature failed for ~A on skey ~A, input ~A, signature ~A"
             name skey input signature))
    (unless (ironclad:verify-signature pk input signature)
      (error "signature verification failed for ~A on pkey ~A, input ~A, signature ~A"
             name pkey input signature))))

(defun curve25519-dh-test (name skey1 pkey1 skey2 pkey2 shared-secret)
  (let* ((sk1 (ironclad:make-private-key :curve25519 :x skey1 :y pkey1))
         (pk1 (ironclad:make-public-key :curve25519 :y pkey1))
         (sk2 (ironclad:make-private-key :curve25519 :x skey2 :y pkey2))
         (pk2 (ironclad:make-public-key :curve25519 :y pkey2))
         (ss1 (ironclad:diffie-hellman sk1 pk2))
         (ss2 (ironclad:diffie-hellman sk2 pk1)))
    (when (mismatch ss1 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey1 pkey2 shared-secret))
    (when (mismatch ss2 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey2 pkey1 shared-secret))))

(defun curve448-dh-test (name skey1 pkey1 skey2 pkey2 shared-secret)
  (let* ((sk1 (ironclad:make-private-key :curve448 :x skey1 :y pkey1))
         (pk1 (ironclad:make-public-key :curve448 :y pkey1))
         (sk2 (ironclad:make-private-key :curve448 :x skey2 :y pkey2))
         (pk2 (ironclad:make-public-key :curve448 :y pkey2))
         (ss1 (ironclad:diffie-hellman sk1 pk2))
         (ss2 (ironclad:diffie-hellman sk2 pk1)))
    (when (mismatch ss1 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey1 pkey2 shared-secret))
    (when (mismatch ss2 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey2 pkey1 shared-secret))))

(defun elgamal-dh-test (name p g skey1 pkey1 skey2 pkey2 shared-secret)
  (let* ((sk1 (ironclad:make-private-key :elgamal :p p :g g :x skey1 :y pkey1))
         (pk1 (ironclad:make-public-key :elgamal :p p :g g :y pkey1))
         (sk2 (ironclad:make-private-key :elgamal :p p :g g :x skey2 :y pkey2))
         (pk2 (ironclad:make-public-key :elgamal :p p :g g :y pkey2))
         (ss1 (ironclad:diffie-hellman sk1 pk2))
         (ss2 (ironclad:diffie-hellman sk2 pk1)))
    (when (mismatch ss1 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey1 pkey2 shared-secret))
    (when (mismatch ss2 shared-secret)
      (error "shared secret computation failed for ~A on skey ~A, pkey ~A, secret ~A"
             name skey2 pkey1 shared-secret))))

(defparameter *public-key-encryption-tests*
  (list (cons :rsa-oaep-encryption-test 'rsa-oaep-encryption-test)
        (cons :elgamal-encryption-test 'elgamal-encryption-test)))

(defparameter *public-key-signature-tests*
  (list (cons :rsa-pss-signature-test 'rsa-pss-signature-test)
        (cons :elgamal-signature-test 'elgamal-signature-test)
        (cons :dsa-signature-test 'dsa-signature-test)
        (cons :ed25519-signature-test 'ed25519-signature-test)
        (cons :ed448-signature-test 'ed448-signature-test)))

(defparameter *public-key-diffie-hellman-tests*
  (list (cons :curve25519-dh-test 'curve25519-dh-test)
        (cons :curve448-dh-test 'curve448-dh-test)
        (cons :elgamal-dh-test 'elgamal-dh-test)))

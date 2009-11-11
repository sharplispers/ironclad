;;;; modes.lisp -- using encryption modes with block ciphers

(in-package :crypto)

;;; internal entry points to assure speed
(defgeneric encrypt-with-mode (cipher mode plaintext ciphertext
                                      &key plaintext-start
                                      plaintext-end
                                      ciphertext-start
                                      handle-final-block)
  (:documentation "Encrypt PLAINTEXT, beginning at PLAINTEXT-START and
continuing until PLAINTEXT-END, according to CIPHER in mode MODE.  Place
the result in CIPHERTEXT, beginning at CIPHERTEXT-START.  PLAINTEXT and
CIPHERTEXT are allowed to be the same array.  Return the number of bytes
encrypted, which may be less than specified."))

(defgeneric decrypt-with-mode (cipher mode ciphertext plaintext
                                      &key ciphertext-start
                                      ciphertext-end
                                      plaintext-start
                                      handle-final-block)
  (:documentation "Decrypt CIPHERTEXT, beginning at CIPHERTEXT-START and
continuing until CIPHERTEXT-END, according to CIPHER in mode MODE.  Place
the result in PLAINTEXT, beginning at PLAINTEXT-START.  CIPHERTEXT and
PLAINTEXT are allowed to be the same array.  Return the number of bytes
encrypted, which may be less than specified."))

(defgeneric encrypted-message-length (cipher mode length
                                      &optional handle-final-block)
  (:documentation "Return the length a message of LENGTH would be if it
were to be encrypted (decrypted) with CIPHER in MODE.  HANDLE-FINAL-BLOCK
indicates whether we are encrypting up to and including the final block
 (so that short blocks may be taken into account, if applicable).

Note that this computation may involve MODE's state."))

(defclass encryption-mode () ())
(defclass ecb-mode (encryption-mode) ())
(defclass stream-mode (encryption-mode) ())
(defclass inititialization-vector-mixin ()
  ((iv :reader iv :initarg :initialization-vector)
   (position :accessor iv-position :initform 0)))
(defclass cbc-mode (encryption-mode inititialization-vector-mixin) ())
(defclass ofb-mode (encryption-mode inititialization-vector-mixin) ())
(defclass cfb-mode (encryption-mode inititialization-vector-mixin) ())
(defclass cfb8-mode (encryption-mode inititialization-vector-mixin)
  ((encrypted-iv :reader encrypted-iv :initarg :encrypted-iv)))
(defclass ctr-mode (encryption-mode inititialization-vector-mixin)
  ((encrypted-iv :reader encrypted-iv :initarg :encrypted-iv)))

(defclass padded-cipher-mode (encryption-mode)
  ((buffer :reader buffer)
   (buffer-index :accessor buffer-index :initform 0)
   (sub-mode :reader sub-mode :initarg :sub-mode)))

(defmethod print-object ((object encryption-mode) stream)
  (print-unreadable-object (object stream :identity t)
    (format stream "~A" (class-name (class-of object)))))

(defmethod initialize-instance :after ((mode cfb8-mode) &key)
  (let ((iv (iv mode)))
    (setf (slot-value mode 'encrypted-iv) (copy-seq iv))))

(defmethod initialize-instance :after ((mode ctr-mode) &key)
  (let ((iv (iv mode)))
    (setf (slot-value mode 'encrypted-iv) (copy-seq iv))))

(defmethod initialize-instance :after ((mode padded-cipher-mode)
                                       &key buffer-length)
  (setf (slot-value mode 'buffer)
        (make-array buffer-length :element-type '(unsigned-byte 8))))

(defvar *supported-modes* (list :ecb :cbc :ofb :cfb :cfb8 :ctr))

(defun mode-supported-p (name)
  (member name *supported-modes*))

(defun list-all-modes ()
  (copy-seq *supported-modes*))

(defmethod encrypt (cipher plaintext ciphertext
                    &key (plaintext-start 0) plaintext-end
                    (ciphertext-start 0))
  (encrypt-with-mode cipher (mode cipher) plaintext ciphertext
                     :plaintext-start plaintext-start
                     :plaintext-end plaintext-end
                     :ciphertext-start ciphertext-start))

(defmethod decrypt (cipher ciphertext plaintext
                    &key (ciphertext-start 0) ciphertext-end
                    (plaintext-start 0))
  (decrypt-with-mode cipher (mode cipher) ciphertext plaintext
                     :ciphertext-start ciphertext-start
                     :ciphertext-end ciphertext-end
                     :plaintext-start plaintext-start))

(defmethod encrypt-message (cipher msg &key (start 0) (end (length msg)))
  (let* ((length (- end start))
         (encrypted-length (encrypted-message-length cipher (mode cipher)
                                                     length t))
         (encrypted-message (make-array encrypted-length
                                        :element-type '(unsigned-byte 8))))
    (encrypt cipher msg encrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    encrypted-message))

(declaim (inline xor-block))
(defun xor-block (block-length input-block1 input-block2 input-block2-start
                               output-block output-block-start)
  (declare (type (simple-array (unsigned-byte 8) (*)) input-block1 input-block2 output-block))
  (declare (type index block-length input-block2-start output-block-start))
  ;; this could be made more efficient by doing things in a word-wise fashion.
  ;; of course, then we'd have to deal with fun things like boundary
  ;; conditions and such like.  maybe we could just win by unrolling the
  ;; loop a bit.  BLOCK-LENGTH should be a constant in all calls to this
  ;; function; maybe a compiler macro would work well.
  (dotimes (i block-length)
    (setf (aref output-block (+ output-block-start i))
          (logxor (aref input-block1 i)
                  (aref input-block2 (+ input-block2-start i))))))

(defun increment-counter-block (block)
  (let ((length (length block))
        (carry 1))
    (loop for i from (1- length) downto 0
          until (zerop carry) do
          (let ((sum (+ (aref block i) carry)))
            (setf (aref block i) (ldb (byte 8 0) sum)
                  carry (ldb (byte 1 8) sum))))
    (values)))

;;; Only really works on big-endian processors...
#+nil
(defun increment-counter-block (block)
  (let ((words (truncate (length block) sb-vm:n-word-bytes))
        (carry 1))
    (loop for i from (1- words) downto 0
          until (zerop carry) do
          (let ((word (sb-kernel:%vector-raw-bits block i)))
            (multiple-value-setq (word carry)
              (sb-bignum:%add-with-carry word 0 carry))
            (setf (sb-kernel:%vector-raw-bits block i) word)))
    (values)))
          
;;; This way is kind of ugly, but I don't know a better way.
(macrolet ((define-mode-function (&environment env)
             `(progn
                ,(macroexpand '(mode-definition t ((block-length (block-length cipher)))
                                block-length) env)
                ,(macroexpand '(mode-definition 16-byte-block-mixin nil 16) env)
                ,(macroexpand '(mode-definition 8-byte-block-mixin nil 8) env))))


;;; ECB mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ecb-mode) plaintext ciphertext
                                            &key (plaintext-start 0) plaintext-end
                                            (ciphertext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with offset = plaintext-start
                     with plaintext-end = (or plaintext-end (length plaintext))
                     with encrypt-function = (encrypt-function cipher)
                     while (<= offset (- plaintext-end ,block-length-expr))
                     do (funcall encrypt-function cipher plaintext offset
                                 ciphertext ciphertext-start)
                     (incf offset ,block-length-expr)
                     (incf ciphertext-start ,block-length-expr)
                     finally (return-from encrypt-with-mode
                               (let ((n-bytes-encrypted (- offset plaintext-start)))
                                 (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ecb-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with offset = ciphertext-start
                     with ciphertext-end = (or ciphertext-end (length ciphertext))
                     with decrypt-function of-type function = (decrypt-function cipher)
                     while (<= offset (- ciphertext-end ,block-length-expr))
                     do (funcall decrypt-function cipher ciphertext offset
                                 plaintext plaintext-start)
                     (incf offset ,block-length-expr)
                     (incf plaintext-start ,block-length-expr)
                     finally (return-from decrypt-with-mode
                               (let ((n-bytes-decrypted (- offset ciphertext-start)))
                                 (values n-bytes-decrypted n-bytes-decrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ecb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                (let ,block-length-binding
                  ;; Just count the number of full blocks.
                  (truncate length ,block-length-expr)))))
  (define-mode-function))


;;; CBC mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode cbc-mode) plaintext ciphertext
                                            &key (plaintext-start 0) plaintext-end
                                            (ciphertext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with offset = plaintext-start
                     with plaintext-end = (or plaintext-end (length plaintext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     while (<= offset (- plaintext-end ,block-length-expr))
                     do (xor-block ,block-length-expr iv plaintext offset
                                   ciphertext ciphertext-start)
                     (funcall encrypt-function cipher ciphertext ciphertext-start
                              ciphertext ciphertext-start)
                     (replace iv ciphertext :start1 0 :end1 ,block-length-expr
                              :start2 ciphertext-start)
                     (incf offset ,block-length-expr)
                     (incf ciphertext-start ,block-length-expr)
                     finally (return-from encrypt-with-mode
                               (let ((n-bytes-encrypted (- offset plaintext-start)))
                                 (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode cbc-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (let ((temp-block (make-array ,block-length-expr :element-type '(unsigned-byte 8))))
                    (declare (type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                             `,block-length-expr
                                                             '*)) temp-block))
                    (declare (dynamic-extent temp-block))
                    (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                       with offset = ciphertext-start
                       with ciphertext-end = (or ciphertext-end (length ciphertext))
                       with decrypt-function of-type function = (decrypt-function cipher)
                       while (<= offset (- ciphertext-end ,block-length-expr))
                       do (replace temp-block ciphertext :start1 0
                                   :end1 ,block-length-expr :start2 offset)
                       (funcall decrypt-function cipher ciphertext offset
                                plaintext plaintext-start)
                       (xor-block ,block-length-expr iv plaintext plaintext-start
                                  plaintext plaintext-start)
                       (replace iv temp-block :end1 ,block-length-expr
                                :end2 ,block-length-expr)
                       (incf offset ,block-length-expr)
                       (incf plaintext-start ,block-length-expr)
                       finally (return-from decrypt-with-mode
                                 (let ((n-bytes-decrypted (- offset ciphertext-start)))
                                   (values n-bytes-decrypted n-bytes-decrypted)))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cbc-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                (let ,block-length-binding
                  ;; Just count the number of full blocks.
                  (truncate length ,block-length-expr)))))
  (define-mode-function))


;;; CFB mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
           `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                          (mode cfb-mode) plaintext ciphertext
                                          &key (plaintext-start 0) plaintext-end
                                          (ciphertext-start 0) handle-final-block)
              (declare (type simple-octet-vector plaintext ciphertext))
              (declare (ignorable handle-final-block))
              (let ,block-length-binding
                (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                `,block-length-expr
                                                                '*)) = (iv mode)
                   with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                            `(,block-length-expr)
                                                            '*)) = (iv-position mode)
                   with plaintext-end = (or plaintext-end (length plaintext))
                   with encrypt-function of-type function = (encrypt-function cipher)
                   for i from plaintext-start below plaintext-end
                   for j from ciphertext-start
                   do (when (zerop iv-position)
                        (funcall encrypt-function cipher iv 0 iv 0))
                   (let ((b (logxor (aref plaintext i) (aref iv iv-position))))
                     (setf (aref ciphertext j) b)
                     (setf (aref iv iv-position) b)
                     (setf iv-position (mod (1+ iv-position) ,block-length-expr)))
                   finally (return-from encrypt-with-mode
                             (let ((n-bytes-encrypted (- plaintext-end plaintext-start)))
                               (setf (iv-position mode) iv-position)
                               (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode cfb-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                              `(,block-length-expr)
                                                              '*)) = (iv-position mode)
                     with ciphertext-end = (or ciphertext-end (length ciphertext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from ciphertext-start below ciphertext-end
                     for j from plaintext-start
                     do (when (zerop iv-position)
                          (funcall encrypt-function cipher iv 0 iv 0))
                     (let ((b (logxor (aref ciphertext i) (aref iv iv-position))))
                       (setf (aref iv iv-position) (aref ciphertext i))
                       (setf (aref plaintext j) b)
                       (setf iv-position (mod (1+ iv-position) ,block-length-expr)))
                     finally (return-from decrypt-with-mode
                               (let ((n-bytes-decrypted (- ciphertext-end ciphertext-start)))
                                 (setf (iv-position mode) iv-position)
                                 (values n-bytes-decrypted n-bytes-decrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             (declare (ignore block-length-binding block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cfb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function))


;;; CFB8 mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
           `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                          (mode cfb8-mode) plaintext ciphertext
                                          &key (plaintext-start 0) plaintext-end
                                          (ciphertext-start 0) handle-final-block)
              (declare (type simple-octet-vector plaintext ciphertext))
              (declare (ignorable handle-final-block))
              (let ,block-length-binding
                (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                `,block-length-expr
                                                                '*)) = (iv mode)
                   with encrypted-iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                       `,block-length-expr
                                                                       '*)) = (encrypted-iv mode)
                   with plaintext-end = (or plaintext-end (length plaintext))
                   with encrypt-function of-type function = (encrypt-function cipher)
                   for i from plaintext-start below plaintext-end
                   for j from ciphertext-start
                   do (replace encrypted-iv iv :end1 ,block-length-expr :end2 ,block-length-expr)
                     (funcall encrypt-function cipher encrypted-iv 0 encrypted-iv 0)
                   (let ((b (logxor (aref plaintext i) (aref encrypted-iv 0))))
                     (setf (aref ciphertext j) b)
                     (replace iv iv :start1 0 :start2 1
                              :end1 (1- ,block-length-expr) :end2 ,block-length-expr)
                     (setf (aref iv (1- ,block-length-expr)) b))
                   finally (return-from encrypt-with-mode
                             (let ((n-bytes-encrypted (- plaintext-end plaintext-start)))
                               (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode cfb8-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with encrypted-iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                         `,block-length-expr
                                                                         '*)) = (encrypted-iv mode)
                     with ciphertext-end = (or ciphertext-end (length ciphertext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from ciphertext-start below ciphertext-end
                     for j from plaintext-start
                     do (replace encrypted-iv iv :end1 ,block-length-expr :end2 ,block-length-expr)
                       (funcall encrypt-function cipher encrypted-iv 0 encrypted-iv 0)
                       (replace iv iv :start1 0 :start2 1
                                :end1 (1- ,block-length-expr) :end2 ,block-length-expr)
                       (let ((b (aref ciphertext i)))
                         (setf (aref iv (1- ,block-length-expr)) b)
                         (setf (aref plaintext j) (logxor b (aref encrypted-iv 0))))
                     finally (return-from decrypt-with-mode
                               (let ((n-bytes-decrypted (- ciphertext-end ciphertext-start)))
                                 (values n-bytes-decrypted n-bytes-decrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             (declare (ignore block-length-binding block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cfb8-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function))


;;; OFB mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ofb-mode) plaintext ciphertext
                                            &key (plaintext-start 0) plaintext-end
                                            (ciphertext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                              `(,block-length-expr)
                                                              '*)) = (iv-position mode)
                     with plaintext-end = (or plaintext-end (length plaintext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from plaintext-start below plaintext-end
                     for j from ciphertext-start
                     do (when (zerop iv-position)
                          (funcall encrypt-function cipher iv 0 iv 0))
                     (setf (aref ciphertext j) (logxor (aref plaintext i)
                                                       (aref iv iv-position)))
                     (setf iv-position (mod (1+ iv-position) ,block-length-expr))
                     finally (return-from encrypt-with-mode
                               (let ((n-bytes-encrypted (- plaintext-end plaintext-start)))
                                 (setf (iv-position mode) iv-position)
                                 (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ofb-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                              `(,block-length-expr)
                                                              '*)) = (iv-position mode)
                     with ciphertext-end = (or ciphertext-end (length ciphertext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from ciphertext-start below ciphertext-end
                     for j from plaintext-start
                     do (when (zerop iv-position)
                          (funcall encrypt-function cipher iv 0 iv 0))
                     (setf (aref plaintext j) (logxor (aref ciphertext i)
                                                      (aref iv iv-position)))
                     (setf iv-position (mod (1+ iv-position) ,block-length-expr))
                     finally (return-from decrypt-with-mode
                               (let ((n-bytes-decrypted (- ciphertext-end ciphertext-start)))
                                 (setf (iv-position mode) iv-position)
                                 (values n-bytes-decrypted n-bytes-decrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             (declare (ignore block-length-binding block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ofb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function))


;;; CTR mode

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ctr-mode) plaintext ciphertext
                                            &key (plaintext-start 0) plaintext-end
                                            (ciphertext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                              `(,block-length-expr)
                                                              '*)) = (iv-position mode)
                     with encrypted-iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                         `,block-length-expr
                                                                         '*)) = (encrypted-iv mode)
                     with plaintext-end = (or plaintext-end (length plaintext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from plaintext-start below plaintext-end
                     for j from ciphertext-start
                     do (when (zerop iv-position)
                          (funcall encrypt-function cipher iv 0 encrypted-iv 0)
                          (increment-counter-block iv))
                     (setf (aref ciphertext j) (logxor (aref plaintext i)
                                                       (aref encrypted-iv iv-position)))
                     (setf iv-position (mod (1+ iv-position) ,block-length-expr))
                     finally (return-from encrypt-with-mode
                               (let ((n-bytes-encrypted (- plaintext-end plaintext-start)))
                                 (setf (iv-position mode) iv-position)
                                 (values n-bytes-encrypted n-bytes-encrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode ctr-mode) ciphertext plaintext
                                            &key (ciphertext-start 0) ciphertext-end
                                            (plaintext-start 0) handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (loop with iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                  `,block-length-expr
                                                                  '*)) = (iv mode)
                     with iv-position of-type (integer 0 ,(if (constantp `,block-length-expr)
                                                              `(,block-length-expr)
                                                              '*)) = (iv-position mode)
                     with encrypted-iv of-type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                                         `,block-length-expr
                                                                         '*)) = (encrypted-iv mode)
                     with ciphertext-end = (or ciphertext-end (length ciphertext))
                     with encrypt-function of-type function = (encrypt-function cipher)
                     for i from ciphertext-start below ciphertext-end
                     for j from plaintext-start
                     do (when (zerop iv-position)
                          (funcall encrypt-function cipher iv 0 encrypted-iv 0)
                          (increment-counter-block iv))
                     (setf (aref plaintext j) (logxor (aref ciphertext i)
                                                      (aref encrypted-iv iv-position)))
                     (setf iv-position (mod (1+ iv-position) ,block-length-expr))
                     finally (return-from decrypt-with-mode
                               (let ((n-bytes-decrypted (- ciphertext-end ciphertext-start)))
                                 (setf (iv-position mode) iv-position)
                                 (values n-bytes-decrypted n-bytes-decrypted))))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             (declare (ignore block-length-binding block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ctr-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function))


;;; Padded modes

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode padded-cipher-mode)
                                            plaintext ciphertext
                                            &key (plaintext-start 0)
                                            plaintext-end
                                            (ciphertext-start 0)
                                            handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (let* ((buffer (buffer mode))
                         (sub-mode (sub-mode mode))
                         (buffer-index (buffer-index mode))
                         (amount (- ,block-length-expr buffer-index))
                         (plaintext-length (- plaintext-end plaintext-start))
                         (n-bytes-encrypted 0))
                    (declare (type (simple-octet-vector ,(if (constantp `,block-length-expr)
                                                             `,block-length-expr
                                                             '*)) buffer))
                    (when (> plaintext-length amount)
                      (replace buffer plaintext :start1 buffer-index
                               :end1 ,block-length-expr
                               :start2 plaintext-start)
                      (encrypt-with-mode cipher sub-mode plaintext ciphertext
                                         :plaintext-start plaintext-start
                                         :plaintext-end plaintext-end
                                         :ciphertext-start ciphertext-start)
                      (setf buffer-index 0)
                      (decf plaintext-length amount)
                      (incf plaintext-start amount)
                      (incf n-bytes-encrypted amount)
                      (loop while (> plaintext-length ,block-length-expr)
                         do (encrypt-with-mode cipher sub-mode
                                               plaintext ciphertext
                                               :plaintext-start plaintext-start
                                               :plaintext-end (+ plaintext-start
                                                                 ,block-length-expr)
                                               :ciphertext-start (+ ciphertext-start
                                                                    n-bytes-encrypted))
                         (decf plaintext-length ,block-length-expr)
                         (incf plaintext-start ,block-length-expr)
                         (incf n-bytes-encrypted ,block-length-expr)))
                    (replace buffer plaintext :start2 plaintext-start
                             :end2 plaintext-end)
                    (setf (buffer-index mode) plaintext-length)
                    (values (+ n-bytes-encrypted plaintext-length)
                            n-bytes-encrypted))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode padded-cipher-mode)
                                            ciphertext plaintext
                                            &key (ciphertext-start 0)
                                            ciphertext-end
                                            (plaintext-start 0)
                                            handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (ignorable handle-final-block))
                (let ,block-length-binding
                  (let* ((buffer (buffer mode))
                         (sub-mode (sub-mode mode))
                         (buffer-index (buffer-index mode))
                         (amount (- ,block-length-expr buffer-index))
                         (ciphertext-length (- ciphertext-end ciphertext-start))
                         (n-bytes-decrypted 0))
                    (when (> ciphertext-length amount)
                      (replace buffer ciphertext :start1 buffer-index
                               :end1 ,block-length-expr
                               :start2 ciphertext-start)
                      (decrypt-with-mode cipher sub-mode ciphertext plaintext
                                         :ciphertext-start ciphertext-start
                                         :ciphertext-end ciphertext-end
                                         :plaintext-start plaintext-start)
                      (setf buffer-index 0)
                      (decf ciphertext-length amount)
                      (incf ciphertext-start amount)
                      (incf n-bytes-decrypted amount)
                      (loop while (> ciphertext-length ,block-length-expr)
                         do (encrypt-with-mode cipher sub-mode
                                               ciphertext plaintext
                                               :ciphertext-start ciphertext-start
                                               :ciphertext-end (+ ciphertext-start
                                                                  ,block-length-expr)
                                               :plaintext-start (+ ciphertext-start
                                                                   n-bytes-decrypted))
                           (decf ciphertext-length ,block-length-expr)
                           (incf ciphertext-start ,block-length-expr)
                           (incf n-bytes-decrypted ,block-length-expr)))
                    (replace buffer ciphertext :start2 ciphertext-start
                             :end2 ciphertext-end)
                    (setf (buffer-index mode) ciphertext-length)
                    (values (+ n-bytes-decrypted ciphertext-length)
                            n-bytes-decrypted))))))
  (define-mode-function))

(macrolet ((mode-definition (cipher-specializer block-length-binding
                                                block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode padded-cipher-mode)
                                                   length
                                                   &optional handle-final-block)
                (let ,block-length-binding
                  (let* ((buffer-index (buffer-index mode))
                         (total-amount (+ buffer-index length)))
                    (cond
                      (handle-final-block
                       ;; Calculate how much padding we will need.
                       (multiple-value-bind (full-blocks leftover)
                           (ceiling total-amount ,block-length-expr)
                         (declare (ignore leftover))
                         (* full-blocks ,block-length-expr)))
                      (t
                       ;; Return the number of full blocks we will encrypt.
                       (multiple-value-bind (full-blocks leftover)
                           (floor total-amount ,block-length-expr)
                         (declare (ignore leftover))
                         (* full-blocks ,block-length-expr)))))))))
  (define-mode-function))

) ; DEFINE-MODE-FUNCTION MACROLET

(defmethod encrypt-with-mode (context (mode stream-mode)
                              plaintext ciphertext
                              &key (plaintext-start 0) plaintext-end
                              (ciphertext-start 0) handle-final-block)
  (declare (type (simple-array (unsigned-byte 8) (*)) plaintext ciphertext))
  (declare (ignorable handle-final-block mode))
  (let ((length (- (or plaintext-end (length plaintext)) plaintext-start)))
    (when (plusp length)
      (funcall (encrypt-function context) context plaintext plaintext-start
               ciphertext ciphertext-start length))
    (max 0 length)))

(defmethod decrypt-with-mode (context (mode stream-mode)
                              ciphertext plaintext
                              &key (ciphertext-start 0) ciphertext-end
                              (plaintext-start 0) handle-final-block)
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext plaintext))
  (declare (ignorable handle-final-block mode))
  (let ((length (- (or ciphertext-end (length ciphertext)) ciphertext-start)))
    (when (plusp length)
      (funcall (decrypt-function context) context ciphertext ciphertext-start
               plaintext plaintext-start length))
    (max 0 length)))

(defmethod encrypted-message-length (context
                                     (mode stream-mode) length
                                     &optional handle-final-block)
  (declare (ignore context mode handle-final-block))
  (declare (type index length))
  length)

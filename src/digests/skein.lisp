;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; skein.lisp -- implementation of the Skein hash functions

(in-package :crypto)


;;; Parameter identifiers

(defconstant +skein-key+ 0)
(defconstant +skein-cfg+ 4)
(defconstant +skein-prs+ 8)
(defconstant +skein-pk+ 12)
(defconstant +skein-kdf+ 16)
(defconstant +skein-non+ 20)
(defconstant +skein-msg+ 48)
(defconstant +skein-out+ 63)


;;; Initial values

(defconst +skein256-iv-128+ #(96 114 77 150 6 25 17 225
                              28 129 141 124 167 170 61 136
                              122 15 150 145 244 13 8 16
                              194 193 91 180 229 221 247 204))
(defconst +skein256-iv-160+ #(152 94 130 114 20 35 32 20
                              144 229 119 90 162 233 196 42
                              62 214 56 136 86 88 122 212
                              125 171 134 133 150 228 210 45))
(defconst +skein256-iv-224+ #(11 234 229 154 140 138 9 198
                              28 25 197 8 134 86 109 135
                              132 56 245 215 215 136 203 153
                              222 181 221 174 177 221 75 56))
(defconst +skein256-iv-256+ #(73 180 72 208 96 168 157 252
                              51 216 167 159 71 102 202 47
                              15 132 86 102 137 195 59 179
                              105 218 232 253 32 233 84 106))
(defconst +skein512-iv-128+ #(82 159 191 111 243 123 188 168
                              170 240 26 189 206 114 152 30
                              211 144 33 179 144 23 155 48
                              92 128 148 63 84 184 251 188
                              27 177 49 110 205 27 166 13
                              227 50 106 212 234 235 24 26
                              130 170 132 206 24 91 204 162
                              45 152 70 157 40 171 130 105))
(defconst +skein512-iv-160+ #(145 189 19 224 42 26 184 40
                              143 247 189 181 104 22 241 194
                              18 111 165 246 243 216 96 23
                              79 144 57 130 88 71 183 79
                              86 80 175 126 127 224 237 33
                              184 112 237 99 46 146 8 217
                              250 82 203 236 255 118 236 184
                              110 122 242 163 184 123 164 1))
(defconst +skein512-iv-224+ #(36 114 103 72 98 97 208 204
                              239 57 35 169 243 92 166 203
                              100 75 255 82 214 105 205 140
                              180 144 184 58 123 237 138 57
                              208 43 125 69 177 209 89 15
                              61 235 212 117 101 254 118 103
                              233 19 116 153 14 199 251 153
                              247 30 196 225 207 252 44 158))
(defconst +skein512-iv-256+ #(19 62 219 47 161 68 208 204
                              235 169 121 26 48 144 53 232
                              111 110 129 79 97 160 174 85
                              219 148 155 174 164 103 39 42
                              131 118 221 116 94 2 6 236
                              81 98 116 196 205 54 164 231
                              133 209 58 57 249 186 111 195
                              19 252 237 51 24 186 237 62))
(defconst +skein512-iv-384+ #(95 239 117 58 191 198 246 163
                              164 250 132 253 204 249 254 176
                              254 12 119 61 102 221 119 157
                              218 253 104 180 243 203 152 215
                              101 68 14 138 102 166 196 27
                              7 116 128 229 52 212 215 126
                              214 68 236 212 172 193 143 84
                              248 143 161 106 84 23 110 38))
(defconst +skein512-iv-512+ #(206 81 156 116 255 173 3 73
                              3 223 70 151 57 222 149 13
                              206 155 199 39 65 147 209 143
                              177 44 53 255 41 86 37 154
                              176 167 108 223 153 37 182 93
                              244 195 213 169 76 57 190 234
                              35 181 117 26 199 18 17 153
                              51 204 15 102 11 164 24 174))
(defconst +skein1024-iv-384+ #(53 74 137 193 184 182 2 81
                               26 241 138 254 227 201 235 254
                               113 237 43 227 6 127 128 12
                               246 145 26 180 82 58 193 96
                               56 124 145 212 93 211 22 151
                               58 29 211 111 18 223 128 231
                               58 48 152 200 182 70 120 121
                               59 42 87 179 168 194 114 177
                               108 74 16 166 3 130 188 201
                               244 36 86 215 56 147 144 101
                               160 129 63 75 104 197 188 148
                               70 253 236 16 30 245 187 62
                               66 133 176 238 11 15 245 45
                               22 101 188 13 48 101 90 59
                               225 188 123 22 210 156 75 72
                               234 175 203 212 71 105 19 45))
(defconst +skein1024-iv-512+ #(24 27 27 124 93 14 236 202
                               2 232 3 95 4 14 27 160
                               133 40 145 237 81 4 132 51
                               28 46 236 234 4 251 74 55
                               247 129 53 129 226 160 37 223
                               210 249 18 139 147 64 0 228
                               182 57 237 194 57 213 98 166
                               90 199 216 69 207 133 139 250
                               150 231 237 41 142 237 22 131
                               184 145 159 46 192 137 50 5
                               115 139 81 109 29 239 248 195
                               46 51 239 213 196 195 206 189
                               135 68 151 34 82 126 154 84
                               22 152 116 91 114 8 7 103
                               209 27 88 240 251 40 205 185
                               116 73 128 21 184 64 41 14))
(defconst +skein1024-iv-1024+ #(85 35 231 65 7 218 147 213
                                12 224 115 172 17 229 181 21
                                240 196 242 186 174 229 128 81
                                175 175 188 252 211 65 189 3
                                152 168 131 25 253 198 174 28
                                159 88 208 205 139 11 81 110
                                218 74 57 198 253 189 226 119
                                163 176 220 36 181 29 30 193
                                181 154 50 198 249 74 209 214
                                13 126 182 110 252 11 155 106
                                50 19 255 204 13 198 67 146
                                212 2 63 116 222 29 31 26
                                184 11 237 16 60 117 150 9
                                154 150 180 242 34 221 114 101
                                154 87 10 208 98 48 253 97
                                57 229 130 134 110 83 224 29))


;;; Functions to generate and update the tweak

(defun skein-increment-counter (tweak n)
  (let ((length 12)
        (carry n))
    (loop
       for i from 0 below length
       until (zerop carry)
       do (let ((sum (+ (aref tweak i) carry)))
            (setf (aref tweak i) (ldb (byte 8 0) sum)
                  carry (ash sum -8))))
    (values)))

(defun skein-update-tweak (tweak &key
                                   (first nil first-p)
                                   (final nil final-p)
                                   (type nil type-p)
                                   (position nil position-p)
                                   (position-increment nil position-increment-p))
  (when first-p
    (setf (ldb (byte 1 6) (aref tweak 15)) (if first 1 0)))
  (when final-p
    (setf (ldb (byte 1 7) (aref tweak 15)) (if final 1 0)))
  (when type-p
    (setf (ldb (byte 6 0) (aref tweak 15)) type))
  (when position-p
    (replace tweak
             (integer-to-octets position :n-bits 96 :big-endian nil)
             :end1 12
             :end2 12))
  (when position-increment-p
    (skein-increment-counter tweak position-increment))
  (values))

(defun skein-make-tweak (first final type position)
  (let ((tweak (make-array 16
                           :element-type '(unsigned-byte 8)
                           :initial-element 0)))
    (skein-update-tweak tweak
                        :first first
                        :final final
                        :type type
                        :position position)
    tweak))

(defun skein-make-configuration-string (output-length)
  (let ((cfg (make-array 32
                         :element-type '(unsigned-byte 8)
                         :initial-element 0)))
    (setf (subseq cfg 0 4) #(83 72 65 51))
    (setf (subseq cfg 4 6) (integer-to-octets 1 :n-bits 16 :big-endian nil))
    (setf (subseq cfg 8 16) (integer-to-octets output-length :n-bits 64 :big-endian nil))
    cfg))


;;; UBI (unique block iteration chaining)

(defgeneric skein-value (state))
(defgeneric skein-tweak (state))
(defgeneric skein-buffer (state))
(defgeneric skein-buffer-length (state))

(defun skein-ubi (state message &optional final)
  (let* ((value (skein-value state))
         (block-length (length value))
         (tweak (skein-tweak state))
         (buffer (skein-buffer state))
         (buffer-length (skein-buffer-length state)))
    (setf buffer (concatenate '(vector (unsigned-byte 8))
                              (subseq buffer 0 buffer-length)
                              message))
    (incf buffer-length (length message))

    (do* ((ciphertext (make-array block-length
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0))
          cipher
          block)
         ((if final
              (< buffer-length block-length)
              (<= buffer-length block-length)))
      (setf block (subseq buffer 0 block-length))
      (setf buffer (subseq buffer block-length))
      (decf buffer-length block-length)
      (unless final
        (skein-update-tweak tweak :position-increment block-length))
      (setf cipher (make-cipher :threefish256
                                :key value
                                :mode :ecb
                                :tweak tweak))
      (encrypt cipher block ciphertext)
      (skein-update-tweak tweak :first nil)
      (setf value (map '(vector (unsigned-byte 8)) #'logxor ciphertext block)))

    (replace (skein-value state) value)
    (replace (skein-tweak state) tweak)
    (replace (skein-buffer state) buffer :end1 buffer-length :end2 buffer-length)
    (setf (skein-buffer-length state) buffer-length)
    (values)))


;;; Implementation for blocks of 256 bits

(defstruct (skein256
             (:constructor %make-skein256-digest nil)
             (:copier nil))
  (value (coerce +skein256-iv-256+ '(simple-array (unsigned-byte 8) (32)))
         :type (simple-array (unsigned-byte 8) (32)))
  (tweak (skein-make-tweak t nil +skein-msg+ 0)
         :type (simple-array (unsigned-byte 8) (16)))
  (cfg (skein-make-configuration-string 256)
       :type (simple-array (unsigned-byte 8) (32)))
  (buffer (make-array 32 :element-type '(unsigned-byte 8))
          :type (simple-array (unsigned-byte 8) (32)))
  (buffer-length 0 :type integer))

(defstruct (skein256/128
             (:include skein256)
             (:constructor %make-skein256/128-digest
                           (&aux (value (coerce +skein256-iv-128+
                                                '(simple-array (unsigned-byte 8) (32))))
                                 (cfg (skein-make-configuration-string 128))))
             (:copier nil)))

(defstruct (skein256/160
             (:include skein256)
             (:constructor %make-skein256/160-digest
                           (&aux (value (coerce +skein256-iv-160+
                                                '(simple-array (unsigned-byte 8) (32))))
                                 (cfg (skein-make-configuration-string 160))))
             (:copier nil)))

(defstruct (skein256/224
             (:include skein256)
             (:constructor %make-skein256/224-digest
                           (&aux (value (coerce +skein256-iv-224+
                                                '(simple-array (unsigned-byte 8) (32))))
                                 (cfg (skein-make-configuration-string 224))))
             (:copier nil)))

(defmethod skein-value ((state skein256))
  (skein256-value state))

(defmethod skein-tweak ((state skein256))
  (skein256-tweak state))

(defmethod skein-buffer ((state skein256))
  (skein256-buffer state))

(defmethod skein-buffer-length ((state skein256))
  (skein256-buffer-length state))

(defmethod (setf skein-buffer-length) (n (state skein256))
  (setf (skein256-buffer-length state) n))

(defmethod reinitialize-instance ((state skein256) &rest initargs)
  (declare (ignore initargs))
  (replace (skein256-value state) +skein256-iv-256+)
  (replace (skein256-tweak state) (skein-make-tweak t nil +skein-msg+ 0))
  (replace (skein256-cfg state) (skein-make-configuration-string 256))
  (setf (skein256-buffer-length state) 0)
  state)

(defmethod reinitialize-instance ((state skein256/128) &rest initargs)
  (declare (ignore initargs))
  (replace (skein256-value state) +skein256-iv-128+)
  (replace (skein256-tweak state) (skein-make-tweak t nil +skein-msg+ 0))
  (replace (skein256-cfg state) (skein-make-configuration-string 128))
  (setf (skein256-buffer-length state) 0)
  state)

(defmethod reinitialize-instance ((state skein256/160) &rest initargs)
  (declare (ignore initargs))
  (replace (skein256-value state) +skein256-iv-160+)
  (replace (skein256-tweak state) (skein-make-tweak t nil +skein-msg+ 0))
  (replace (skein256-cfg state) (skein-make-configuration-string 160))
  (setf (skein256-buffer-length state) 0)
  state)

(defmethod reinitialize-instance ((state skein256/224) &rest initargs)
  (declare (ignore initargs))
  (replace (skein256-value state) +skein256-iv-224+)
  (replace (skein256-tweak state) (skein-make-tweak t nil +skein-msg+ 0))
  (replace (skein256-cfg state) (skein-make-configuration-string 224))
  (setf (skein256-buffer-length state) 0)
  state)

(defmethod copy-digest ((state skein256) &optional copy)
  (declare (type (or cl:null skein256) copy))
  (let ((copy (if copy
                  copy
                  (etypecase state
                    (skein256/128 (%make-skein256/128-digest))
                    (skein256/160 (%make-skein256/160-digest))
                    (skein256/224 (%make-skein256/224-digest))
                    (skein256 (%make-skein256-digest))))))
    (declare (type skein256 copy))
    (replace (skein256-value copy) (skein256-value state))
    (replace (skein256-tweak copy) (skein256-tweak state))
    (replace (skein256-cfg copy) (skein256-cfg state))
    (replace (skein256-buffer copy) (skein256-buffer state))
    (setf (skein256-buffer-length copy) (skein256-buffer-length state))
    copy))

(define-digest-updater skein256
  (skein-ubi state (subseq sequence start end))
  state)

(define-digest-finalizer ((skein256 32)
                          (skein256/224 28)
                          (skein256/160 20)
                          (skein256/128 16))
  (let ((block-length (block-length state))
        (digest-length (digest-length state))
        padding)
    ;; Process remaining data after padding it
    (setf padding (make-array (- block-length (skein256-buffer-length state))
                              :element-type '(unsigned-byte 8)
                              :initial-element 0))
    (skein-update-tweak (skein256-tweak state)
                        :final t
                        :position-increment (skein256-buffer-length state))
    (skein-ubi state padding t)

    ;; Generate output
    (skein-update-tweak (skein256-tweak state)
                        :first t
                        :final t
                        :type +skein-out+
                        :position 8)
    (skein-ubi state (integer-to-octets 0 :n-bits 256 :big-endian nil) t)

    (let ((value (skein256-value state)))
      (etypecase digest
        ((simple-array (unsigned-byte 8) (*))
         (progn
           (replace digest value :start1 digest-start :end2 digest-length)
           digest))
        (cl:null
         (make-array digest-length
                     :element-type '(unsigned-byte 8)
                     :initial-contents (subseq value 0 digest-length)))))))

(defdigest skein256 :digest-length 32 :block-length 32)
(defdigest skein256/128 :digest-length 16 :block-length 32)
(defdigest skein256/160 :digest-length 20 :block-length 32)
(defdigest skein256/224 :digest-length 28 :block-length 32)

;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; conditions.lisp -- various error conditions

(in-package :ironclad)

(define-condition ironclad-error (simple-error)
  ())

(define-condition key-not-supplied (ironclad-error)
  ((cipher :initarg :cipher :reader cipher))
  (:report (lambda (condition stream)
             (format stream "Cipher ~A requires a key" (cipher condition))))
  (:documentation "Signaled when a key is not provided at the initialization
of a cipher."))

(define-condition initialization-vector-not-supplied (ironclad-error)
  ((mode :initarg :mode :reader mode))
  (:report (lambda (condition stream)
             (format stream "Mode ~A requires an initialization vector"
                     (mode condition))))
  (:documentation "Signaled when an initialization vector is required
for a particular mode of operation but not supplied."))

(define-condition invalid-initialization-vector (ironclad-error)
  ((cipher :initarg :cipher :reader cipher)
   (block-length :initarg :block-length :reader block-length))
  (:report (lambda (condition stream)
             (format stream "Cipher ~A requires an initialization vector of length ~D"
                     (cipher condition)
                     (block-length condition))))
  (:documentation "Signaled when an invalid initialization vector is supplied to MAKE-CIPHER."))

(define-condition invalid-key-length (ironclad-error)
  ((cipher :initarg :cipher :reader cipher)
   (lengths :initarg :accepted-lengths :reader accepted-lengths))
  (:report (lambda (condition stream)
             (format stream "Cipher ~A only accepts keys of these lengths: ~A"
                     (cipher condition)
                     (accepted-lengths condition))))
  (:documentation "Signaled when a key is not the proper length for a cipher."))

(define-condition unsupported-cipher (ironclad-error)
  ((cipher :initarg :name :reader cipher))
  (:report (lambda (condition stream)
             (format stream "Cipher ~A is not a supported cipher"
                     (cipher condition))))
  (:documentation "Signaled when an invalid cipher name is provided to MAKE-CIPHER."))

(define-condition unsupported-mode (ironclad-error)
  ((mode :initarg :mode :reader mode)
   (cipher :initarg :cipher :reader cipher))
  (:report (lambda (condition stream)
             (if (cipher condition)
                 (format stream "Mode ~A is not a supported mode for ~A"
                         (mode condition) (cipher condition))
                 (format stream "Mode ~A is not a supported mode"
                         (mode condition)))))
  (:documentation "Signaled when an invalid mode name is provided to MAKE-CIPHER."))

(define-condition unsupported-digest (ironclad-error)
  ((digest :initarg :name :reader digest))
  (:report (lambda (condition stream)
             (format stream "Digest ~A is not a supported digest"
                     (digest condition))))
  (:documentation "Signaled when an invalid digest name is provided to MAKE-DIGEST."))

(define-condition unsupported-scrypt-cost-factors (ironclad-error)
  ((N :initarg :N :reader cost-N)
   (r :initarg :r :reader cost-r)
   (p :initarg :p :reader cost-p))
  (:report (lambda (condition stream)
             (format stream "Scrypt cost factors not supported. N=~A must be a power of two and (r=~A * p=~A) <= 2^30."
                     (cost-N condition) (cost-r condition) (cost-p condition))))
  (:documentation "Signaled when a invalid cost factors are provided to MAKE-SCRYPT-KDF."))

(define-condition insufficient-buffer-space (ironclad-error)
  ((buffer :initarg :buffer :reader insufficient-buffer-space-buffer)
   (start :initarg :start :reader insufficient-buffer-space-start)
   (length :initarg :length :reader insufficient-buffer-space-length))
  (:report (lambda (condition stream)
             (format stream "Buffer ~A cannot accomodate ~D elements starting at index ~D"
                     (insufficient-buffer-space-buffer condition)
                     (insufficient-buffer-space-length condition)
                     (insufficient-buffer-space-start condition))))
  (:documentation "Signaled when insufficient buffer space exists for an operation."))

(define-condition invalid-padding (ironclad-error)
  ((padding-name :initarg :name :reader invalid-padding-padding-name)
   (block :initarg :block :reader invalid-padding-block))
  (:report (lambda (condition stream)
             (format stream "The ~A padding in block ~A is invalid"
                     (invalid-padding-padding-name condition)
                     (invalid-padding-block condition))))
  (:documentation "Signaled when padding in a block is determined to be invalid."))


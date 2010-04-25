(in-package :sb-vm)

#+(or x86 x86-64)
(progn
(define-vop (fill-block-ub8)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg))
         (buffer :scs (descriptor-reg))
         (offset :scs (unsigned-reg)))
  (:variant-vars big-endian-p bytes-to-copy 64-bit-p)
  (:temporary (:sc unsigned-reg) temp buffer-index block-index)
  (:generator 50
    (let* ((data-offset (- (* n-word-bytes vector-data-offset)
                             other-pointer-lowtag))
           (block-disp (+ data-offset bytes-to-copy))
           (ea-size #+x86 :dword #+x86-64 :qword)
           (loop (gen-label)))
      (move buffer-index offset)
      (inst mov block-index (- (truncate bytes-to-copy n-word-bytes)))
      (emit-label loop)
      (inst mov temp (make-ea ea-size :base buffer
                              :index buffer-index
                              :disp data-offset))
      (when big-endian-p
        (inst bswap temp)
        #+x86-64
        (unless 64-bit-p
          (inst rol temp 32)))
      (inst mov (make-ea ea-size :base block
                         :index block-index
                         :scale n-word-bytes
                         :disp block-disp) temp)
      (inst add buffer-index n-word-bytes)
      (inst add block-index 1)
      (inst jmp :nz loop))))

(define-vop (fill-block-ub8-le fill-block-ub8)
  (:translate ironclad::fill-block-ub8-le)
  (:arg-types simple-array-unsigned-byte-32
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant nil 64 nil))

(define-vop (fill-block-ub8-be fill-block-ub8)
  (:translate ironclad::fill-block-ub8-be)
  (:arg-types simple-array-unsigned-byte-32
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant t 64 nil))

#+x86-64
(define-vop (fill-block-ub8-le/64 fill-block-ub8)
  (:translate ironclad::fill-block-ub8-le/64)
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant nil 64 t))

#+x86-64
(define-vop (fill-block-ub8-be/64 fill-block-ub8)
  (:translate ironclad::fill-block-ub8-be/64)
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant t 128 t))
) ; PROGN

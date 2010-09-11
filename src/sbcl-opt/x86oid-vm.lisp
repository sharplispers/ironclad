(in-package :sb-vm)

#+(or x86 x86-64)
(progn
(define-vop (fill-block-ub8)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg))
         (buffer :scs (descriptor-reg))
         (offset :scs (unsigned-reg immediate) :target buffer-index))
  (:variant-vars big-endian-p bytes-to-copy 64-bit-p)
  (:temporary (:sc unsigned-reg) temp buffer-index block-index)
  (:generator 50
    (let* ((data-offset (- (* n-word-bytes vector-data-offset)
                             other-pointer-lowtag))
           (block-disp (+ data-offset bytes-to-copy))
           (ea-size #+x86 :dword #+x86-64 :qword)
           (immediate-offset (sc-is offset immediate))
           (unroll (if immediate-offset 2 1))
           (loop (gen-label)))
      (flet ((ea-for-buffer (&optional (offset 0))
               (if immediate-offset
                   (make-ea ea-size :base buffer
                            :index block-index
                            :scale n-word-bytes
                            :disp (+ block-disp offset))
                   (make-ea ea-size :base buffer
                            :index buffer-index :disp data-offset)))
             (ea-for-block (&optional (offset 0))
               (make-ea ea-size :base block
                        :index block-index
                        :scale n-word-bytes
                        :disp (+ block-disp offset)))
             (handle-endianness (x)
               (when big-endian-p
                 (inst bswap x)
                 #+x86-64
                 (unless 64-bit-p
                   (inst rol x 32)))))
        (unless immediate-offset
          (move buffer-index offset))
        (inst mov block-index (- (truncate bytes-to-copy n-word-bytes)))
        (emit-label loop)
        (inst mov temp (ea-for-buffer 0))
        (when immediate-offset
          (inst mov buffer-index (ea-for-buffer n-word-bytes)))
        (handle-endianness temp)
        (when immediate-offset
          (handle-endianness buffer-index))
        (inst mov (ea-for-block) temp)
        (when immediate-offset
          (inst mov (ea-for-block n-word-bytes) buffer-index))
        (unless immediate-offset
          (inst add buffer-index n-word-bytes))
        (inst add block-index unroll)
        (inst jmp :nz loop)))))

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
  ;; Yes.  Really.  Inconsistent naming FTW.
  (:variant nil 64 t))

#+x86-64
(define-vop (fill-block-ub8-be/64 fill-block-ub8)
  (:translate ironclad::fill-block-ub8-be/64)
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant t 128 t))

(define-vop (expand-block)
  (:translate ironclad::expand-block)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-32)
  (:temporary (:sc unsigned-reg) temp count)
  (:generator 100
    (flet ((block-word (elem-offset)
             (make-ea :dword :base block
                      :index count
                      :scale 4
                      :disp (+ (- (* n-word-bytes vector-data-offset)
                                  other-pointer-lowtag)
                               (* 4 (+ 80 elem-offset))))))
      (let ((loop (gen-label))
            #+x86-64 (temp (reg-in-size temp :dword)))
        (inst mov count -64)
        (emit-label loop)
        (inst mov temp (block-word -3))
        (inst xor temp (block-word -8))
        (inst xor temp (block-word -14))
        (inst xor temp (block-word -16))
        (inst rol temp 1)
        (inst mov (block-word 0) temp)
        (inst add count 1)
        (inst jmp :nz loop)))))

(define-vop (sha256-expand-block)
  (:translate ironclad::sha256-expand-block)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-32)
  (:temporary (:sc unsigned-reg) t1 t2 t3 t4 count)
  (:generator 100
    (flet ((block-word (elem-offset)
             (make-ea :dword :base block
                      :index count
                      :scale 4
                      :disp (+ (- (* n-word-bytes vector-data-offset)
                                  other-pointer-lowtag)
                               (* 4 (+ 64 elem-offset))))))
      (let ((loop (gen-label))
            #+x86-64 (t1 (reg-in-size t1 :dword))
            #+x86-64 (t2 (reg-in-size t2 :dword))
            #+x86-64 (t3 (reg-in-size t3 :dword))
            #+x86-64 (t4 (reg-in-size t4 :dword)))
        ;; The code could definitely be improved for x86-64 by using
        ;; more temporaries, but this version works on both 32- and
        ;; 64-bit and eliminates many of the stupidities in the modular
        ;; arithmetic version (mostly on 64-bit, but some lameness in
        ;; the 32-bit version as well).
        (inst mov count -48)
        (emit-label loop)
        (inst mov t1 (block-word -2))
        ;; sigma1
        (inst mov t2 t1)
        (inst rol t2 15)
        (inst mov t3 t1)
        (inst rol t3 13)
        (inst xor t2 t3)
        (inst shr t1 10)
        (inst xor t1 t2)
        (inst mov t2 (block-word -15))
        ;; sigma0
        (inst mov t3 t2)
        (inst rol t3 25)
        (inst mov t4 t2)
        (inst rol t4 14)
        (inst xor t3 t4)
        (inst shr t2 3)
        (inst xor t2 t3)
        (inst add t1 (block-word -7))
        (inst add t2 (block-word -16))
        (inst add t1 t2)
        (inst mov (block-word 0) t1)
        (inst add count 1)
        (inst jmp :nz loop)))))
        
) ; PROGN

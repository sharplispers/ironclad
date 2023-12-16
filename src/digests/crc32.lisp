;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; crc32.lisp

(in-package :crypto)
(in-ironclad-readtable)

(declaim (type (simple-array (unsigned-byte 32) (256))
               +crc32-table+ +crc32c-table+))
(defconst +crc32-table+
  #32@(#x00000000 #x77073096 #xEE0E612C #x990951BA
       #x076DC419 #x706AF48F #xE963A535 #x9E6495A3
       #x0EDB8832 #x79DCB8A4 #xE0D5E91E #x97D2D988
       #x09B64C2B #x7EB17CBD #xE7B82D07 #x90BF1D91
       #x1DB71064 #x6AB020F2 #xF3B97148 #x84BE41DE
       #x1ADAD47D #x6DDDE4EB #xF4D4B551 #x83D385C7
       #x136C9856 #x646BA8C0 #xFD62F97A #x8A65C9EC
       #x14015C4F #x63066CD9 #xFA0F3D63 #x8D080DF5
       #x3B6E20C8 #x4C69105E #xD56041E4 #xA2677172
       #x3C03E4D1 #x4B04D447 #xD20D85FD #xA50AB56B
       #x35B5A8FA #x42B2986C #xDBBBC9D6 #xACBCF940
       #x32D86CE3 #x45DF5C75 #xDCD60DCF #xABD13D59
       #x26D930AC #x51DE003A #xC8D75180 #xBFD06116
       #x21B4F4B5 #x56B3C423 #xCFBA9599 #xB8BDA50F
       #x2802B89E #x5F058808 #xC60CD9B2 #xB10BE924
       #x2F6F7C87 #x58684C11 #xC1611DAB #xB6662D3D
       #x76DC4190 #x01DB7106 #x98D220BC #xEFD5102A
       #x71B18589 #x06B6B51F #x9FBFE4A5 #xE8B8D433
       #x7807C9A2 #x0F00F934 #x9609A88E #xE10E9818
       #x7F6A0DBB #x086D3D2D #x91646C97 #xE6635C01
       #x6B6B51F4 #x1C6C6162 #x856530D8 #xF262004E
       #x6C0695ED #x1B01A57B #x8208F4C1 #xF50FC457
       #x65B0D9C6 #x12B7E950 #x8BBEB8EA #xFCB9887C
       #x62DD1DDF #x15DA2D49 #x8CD37CF3 #xFBD44C65
       #x4DB26158 #x3AB551CE #xA3BC0074 #xD4BB30E2
       #x4ADFA541 #x3DD895D7 #xA4D1C46D #xD3D6F4FB
       #x4369E96A #x346ED9FC #xAD678846 #xDA60B8D0
       #x44042D73 #x33031DE5 #xAA0A4C5F #xDD0D7CC9
       #x5005713C #x270241AA #xBE0B1010 #xC90C2086
       #x5768B525 #x206F85B3 #xB966D409 #xCE61E49F
       #x5EDEF90E #x29D9C998 #xB0D09822 #xC7D7A8B4
       #x59B33D17 #x2EB40D81 #xB7BD5C3B #xC0BA6CAD
       #xEDB88320 #x9ABFB3B6 #x03B6E20C #x74B1D29A
       #xEAD54739 #x9DD277AF #x04DB2615 #x73DC1683
       #xE3630B12 #x94643B84 #x0D6D6A3E #x7A6A5AA8
       #xE40ECF0B #x9309FF9D #x0A00AE27 #x7D079EB1
       #xF00F9344 #x8708A3D2 #x1E01F268 #x6906C2FE
       #xF762575D #x806567CB #x196C3671 #x6E6B06E7
       #xFED41B76 #x89D32BE0 #x10DA7A5A #x67DD4ACC
       #xF9B9DF6F #x8EBEEFF9 #x17B7BE43 #x60B08ED5
       #xD6D6A3E8 #xA1D1937E #x38D8C2C4 #x4FDFF252
       #xD1BB67F1 #xA6BC5767 #x3FB506DD #x48B2364B
       #xD80D2BDA #xAF0A1B4C #x36034AF6 #x41047A60
       #xDF60EFC3 #xA867DF55 #x316E8EEF #x4669BE79
       #xCB61B38C #xBC66831A #x256FD2A0 #x5268E236
       #xCC0C7795 #xBB0B4703 #x220216B9 #x5505262F
       #xC5BA3BBE #xB2BD0B28 #x2BB45A92 #x5CB36A04
       #xC2D7FFA7 #xB5D0CF31 #x2CD99E8B #x5BDEAE1D
       #x9B64C2B0 #xEC63F226 #x756AA39C #x026D930A
       #x9C0906A9 #xEB0E363F #x72076785 #x05005713
       #x95BF4A82 #xE2B87A14 #x7BB12BAE #x0CB61B38
       #x92D28E9B #xE5D5BE0D #x7CDCEFB7 #x0BDBDF21
       #x86D3D2D4 #xF1D4E242 #x68DDB3F8 #x1FDA836E
       #x81BE16CD #xF6B9265B #x6FB077E1 #x18B74777
       #x88085AE6 #xFF0F6A70 #x66063BCA #x11010B5C
       #x8F659EFF #xF862AE69 #x616BFFD3 #x166CCF45
       #xA00AE278 #xD70DD2EE #x4E048354 #x3903B3C2
       #xA7672661 #xD06016F7 #x4969474D #x3E6E77DB
       #xAED16A4A #xD9D65ADC #x40DF0B66 #x37D83BF0
       #xA9BCAE53 #xDEBB9EC5 #x47B2CF7F #x30B5FFE9
       #xBDBDF21C #xCABAC28A #x53B39330 #x24B4A3A6
       #xBAD03605 #xCDD70693 #x54DE5729 #x23D967BF
       #xB3667A2E #xC4614AB8 #x5D681B02 #x2A6F2B94
       #xB40BBE37 #xC30C8EA1 #x5A05DF1B #x2D02EF8D))

(defconst +crc32c-table+
  #32@(#x00000000 #xF26B8303 #xE13B70F7 #x1350F3F4
       #xC79A971F #x35F1141C #x26A1E7E8 #xD4CA64EB
       #x8AD958CF #x78B2DBCC #x6BE22838 #x9989AB3B
       #x4D43CFD0 #xBF284CD3 #xAC78BF27 #x5E133C24
       #x105EC76F #xE235446C #xF165B798 #x030E349B
       #xD7C45070 #x25AFD373 #x36FF2087 #xC494A384
       #x9A879FA0 #x68EC1CA3 #x7BBCEF57 #x89D76C54
       #x5D1D08BF #xAF768BBC #xBC267848 #x4E4DFB4B
       #x20BD8EDE #xD2D60DDD #xC186FE29 #x33ED7D2A
       #xE72719C1 #x154C9AC2 #x061C6936 #xF477EA35
       #xAA64D611 #x580F5512 #x4B5FA6E6 #xB93425E5
       #x6DFE410E #x9F95C20D #x8CC531F9 #x7EAEB2FA
       #x30E349B1 #xC288CAB2 #xD1D83946 #x23B3BA45
       #xF779DEAE #x05125DAD #x1642AE59 #xE4292D5A
       #xBA3A117E #x4851927D #x5B016189 #xA96AE28A
       #x7DA08661 #x8FCB0562 #x9C9BF696 #x6EF07595
       #x417B1DBC #xB3109EBF #xA0406D4B #x522BEE48
       #x86E18AA3 #x748A09A0 #x67DAFA54 #x95B17957
       #xCBA24573 #x39C9C670 #x2A993584 #xD8F2B687
       #x0C38D26C #xFE53516F #xED03A29B #x1F682198
       #x5125DAD3 #xA34E59D0 #xB01EAA24 #x42752927
       #x96BF4DCC #x64D4CECF #x77843D3B #x85EFBE38
       #xDBFC821C #x2997011F #x3AC7F2EB #xC8AC71E8
       #x1C661503 #xEE0D9600 #xFD5D65F4 #x0F36E6F7
       #x61C69362 #x93AD1061 #x80FDE395 #x72966096
       #xA65C047D #x5437877E #x4767748A #xB50CF789
       #xEB1FCBAD #x197448AE #x0A24BB5A #xF84F3859
       #x2C855CB2 #xDEEEDFB1 #xCDBE2C45 #x3FD5AF46
       #x7198540D #x83F3D70E #x90A324FA #x62C8A7F9
       #xB602C312 #x44694011 #x5739B3E5 #xA55230E6
       #xFB410CC2 #x092A8FC1 #x1A7A7C35 #xE811FF36
       #x3CDB9BDD #xCEB018DE #xDDE0EB2A #x2F8B6829
       #x82F63B78 #x709DB87B #x63CD4B8F #x91A6C88C
       #x456CAC67 #xB7072F64 #xA457DC90 #x563C5F93
       #x082F63B7 #xFA44E0B4 #xE9141340 #x1B7F9043
       #xCFB5F4A8 #x3DDE77AB #x2E8E845F #xDCE5075C
       #x92A8FC17 #x60C37F14 #x73938CE0 #x81F80FE3
       #x55326B08 #xA759E80B #xB4091BFF #x466298FC
       #x1871A4D8 #xEA1A27DB #xF94AD42F #x0B21572C
       #xDFEB33C7 #x2D80B0C4 #x3ED04330 #xCCBBC033
       #xA24BB5A6 #x502036A5 #x4370C551 #xB11B4652
       #x65D122B9 #x97BAA1BA #x84EA524E #x7681D14D
       #x2892ED69 #xDAF96E6A #xC9A99D9E #x3BC21E9D
       #xEF087A76 #x1D63F975 #x0E330A81 #xFC588982
       #xB21572C9 #x407EF1CA #x532E023E #xA145813D
       #x758FE5D6 #x87E466D5 #x94B49521 #x66DF1622
       #x38CC2A06 #xCAA7A905 #xD9F75AF1 #x2B9CD9F2
       #xFF56BD19 #x0D3D3E1A #x1E6DCDEE #xEC064EED
       #xC38D26C4 #x31E6A5C7 #x22B65633 #xD0DDD530
       #x0417B1DB #xF67C32D8 #xE52CC12C #x1747422F
       #x49547E0B #xBB3FFD08 #xA86F0EFC #x5A048DFF
       #x8ECEE914 #x7CA56A17 #x6FF599E3 #x9D9E1AE0
       #xD3D3E1AB #x21B862A8 #x32E8915C #xC083125F
       #x144976B4 #xE622F5B7 #xF5720643 #x07198540
       #x590AB964 #xAB613A67 #xB831C993 #x4A5A4A90
       #x9E902E7B #x6CFBAD78 #x7FAB5E8C #x8DC0DD8F
       #xE330A81A #x115B2B19 #x020BD8ED #xF0605BEE
       #x24AA3F05 #xD6C1BC06 #xC5914FF2 #x37FACCF1
       #x69E9F0D5 #x9B8273D6 #x88D28022 #x7AB90321
       #xAE7367CA #x5C18E4C9 #x4F48173D #xBD23943E
       #xF36E6F75 #x0105EC76 #x12551F82 #xE03E9C81
       #x34F4F86A #xC69F7B69 #xD5CF889D #x27A40B9E
       #x79B737BA #x8BDCB4B9 #x988C474D #x6AE7C44E
       #xBE2DA0A5 #x4C4623A6 #x5F16D052 #xAD7D5351))

(defun crc32-table (state)
  (etypecase state
    (crc32c +crc32c-table+)
    (crc32 +crc32-table+)))

(defstruct (crc32
             (:constructor %make-crc32-digest nil)
             (:constructor %make-crc32-state (crc))
             (:copier nil))
  (crc 4294967295 :type (unsigned-byte 32)))

(defstruct (crc32c
             (:include crc32)
             (:constructor %make-crc32c-digest nil)
             (:copier nil)))

(defmethod reinitialize-instance ((state crc32) &rest initargs)
  (declare (ignore initargs))
  (setf (crc32-crc state) #xffffffff)
  state)

(defmethod copy-digest ((state crc32) &optional copy)
  (check-type copy (or null crc32))
  (cond
    (copy
     (setf (crc32-crc copy) (crc32-crc state))
     copy)
    (t
     (%make-crc32-state (crc32-crc state)))))

(define-digest-updater crc32
  (let ((crc (crc32-crc state)))
    (declare (type (unsigned-byte 32) crc))
    (do ((i start (1+ i))
         (table (crc32-table state)))
        ((>= i end)
         (setf (crc32-crc state) crc)
         state)
      (setf crc (logxor (aref table
                              (logand (logxor crc (aref sequence i)) #xff))
                        (mod32ash crc -8))))))

(define-digest-finalizer (crc32 4)
  (flet ((stuff-state (crc digest start)
           (declare (type (simple-array (unsigned-byte 8) (*)) digest))
           (declare (type (integer 0 #.(- array-dimension-limit 4)) start))
           (setf (ub32ref/be digest start) crc)
           digest))
    (declare (inline stuff-state))
    (let ((result (logxor #xffffffff (crc32-crc state))))
      (stuff-state result digest digest-start))))

(defdigest crc32 :digest-length 4 :block-length 1)
(defdigest crc32c :digest-length 4 :block-length 1)

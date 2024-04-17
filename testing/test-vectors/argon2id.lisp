;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)


(rtest:deftest argon2id-1
    (run-kdf-test (crypto:make-kdf 'crypto:argon2id :block-count 12)
                  (crypto:ascii-string-to-byte-array "somepassword")
                  (crypto:ascii-string-to-byte-array "somesalt")
                  3
                  32
                  (ironclad:hex-string-to-byte-array "e77e03eafc1b9e867a1e7f38832e7d9fb73b04ef403ec2267f8e14e873448f0b"))
  t)

(rtest:deftest argon2id-2
    (run-kdf-test (crypto:make-kdf 'crypto:argon2id :block-count 32)
                  (crypto:ascii-string-to-byte-array "0123456789abcdefgh")
                  (crypto:ascii-string-to-byte-array "0123456789")
                  3
                  32
                  (ironclad:hex-string-to-byte-array "955d9f804edbd323ca241d2e53e43585c339535ca67d11a0768f60c7acd9e434"))
  t)

(rtest:deftest argon2id-3
    (run-kdf-test (crypto:make-kdf 'crypto:argon2id :block-count 64)
                  (crypto:ascii-string-to-byte-array "0000000000000000")
                  (crypto:ascii-string-to-byte-array "00000000")
                  4
                  32
                  (ironclad:hex-string-to-byte-array "ff40a8eabe934ba7831abf10fe86d368590470882c7af2a83aacd99d9877b0db"))
  t)

(rtest:deftest argon2id-4
    (run-kdf-test (crypto:make-kdf 'crypto:argon2id :block-count 128)
                  (crypto:ascii-string-to-byte-array "zzzzzzzzyyyyyyyyxxxxx")
                  (crypto:ascii-string-to-byte-array "wwwwwwwwvvvvv")
                  3
                  111
                  (ironclad:hex-string-to-byte-array "a2978bd1ef90d5f623ccfa74348e5f4ae72dca1af4fc1161b3a38ef6820f3600cdb70cc557c1f029960d725df5159b47af5163e174ce20a2fbb4e2b37ab5d66800f8467b23d848a8c8cb5347d8b93c56ae9525c5990c91153a9ce26ce06cc2d350d8db43cb89761bc43698a9f7e08c"))
  t)

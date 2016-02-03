# ===========================================
# Federico Maggi - 797295
# Progetto Architetture degli Elaborati II
# ===========================================
#
# Recursive MIPS Ceasar Cipher 
# 
# Main:
#   $s0 -> operazione
#   $s1 -> chiave
#
.data
opprompt:   .asciiz "Quale operazione vuoi fare? (1: cifra - 2: decifra - 0: esci)\n> "
keyprompt:  .asciiz "Inserisci la chiave (deve essere maggiore di 0):\n> "
opcprompt:  .asciiz "CIFRO CON CHIAVE: "
opdprompt:  .asciiz "DECIFRO CON CHIAVE: "
txtprompt:  .asciiz "Inserisci il testo:\n> "
resprompt:  .asciiz "Risultato:\n"
conprompt:  .asciiz "Premi '1' per continuare:\n> "
byeprompt:  .asciiz "Arrivederci!\n"
endl:       .asciiz "\n"

string:     .space 255

.globl main
.text
main:                           # Chiedo l'operazione da eseguire
  li $v0, 4
  la $a0, opprompt
  syscall

  li $v0, 5
  syscall

  beq $v0, $zero, __exit
  bltz $v0, main
  bgt $v0, 2, main
  addi $s0, $v0, 0              # Salvo in $s0 l'operazione che vuole eseguire

__keyask:                       # Chiedo la chiave
  li $v0, 4
  la $a0, keyprompt
  syscall

  li $v0, 5
  syscall

  li $t0, 26                    # Modulus value (26)
  div $v0, $t0
  mfhi $t1                      # $t1 <- $v0 % 26

  beqz $t1, __keyask
  blt $t1, $0, __keyask
  addi $s1, $t1, 0              # Salvo in $s1 la chiave

__stringask:                    # Richiedo la stringa da manipolare
  li $v0, 4
  la $a0, txtprompt
  syscall

  li $v0, 8
  la $a0, string
  li $a1, 255
  syscall

__opselect:
  beq $s0, 1, __cipherprompt
  beq $s0, 2, __decipherprompt
  j main

__cipherprompt:                 # stampo che stiamo per cifrare con chiave $s1
  li $v0, 4
  la $a0, opcprompt
  syscall

  li $v0, 1
  addi $a0, $s1, 0
  syscall

  li $v0, 4
  la $a0, endl
  syscall

  ## CALL CIPHER

  j __done

__decipherprompt:               # stampo che stiamo per decifrare con chiave $s1
  li $v0, 4
  la $a0, opdprompt
  syscall

  li $v0, 1
  addi $a0, $s1, 0
  syscall

  li $v0, 4
  la $a0, endl
  syscall

  ## CALL DECHIPHER

  j __done

__done:                          # Stampo il risultato dell'operazione
  li $v0, 4
  la $a0, resprompt
  syscall

  #
  # Print the operation output
  #

  li $a0, 4
  la $a0, endl
  syscall

  li $v0, 4                     # Stampo richiesta per continuare
  la $a0, conprompt
  syscall

  li $v0, 5                     # Leggo risposta
  syscall

  addi $t0, $v0, 0              # $t0 <- risposta

  li $v0, 4                     # Stampo un \n
  la $a0, endl
  syscall

  beq $t0, 1, main              # $t0 == 1 -> continua

__exit:
  li $v0, 4
  la $a0, byeprompt
  syscall

  li $v0, 10
  syscall


### Procedures ###


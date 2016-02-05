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
#   $s2 -> lunghezza stringa
#   $s3 -> indirizzo stringa risultato
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

string:     .space 256

.globl main

.text

main:                           # Legge l'operazione da eseguire
  li $v0, 4
  la $a0, opprompt             
  syscall

  li $v0, 5
  syscall

  beq $v0, $zero, __exit        # OP = 0 -> EXIT
  bltz $v0, main                # OP < 0 -> MAIN
  bgt $v0, 2, main              # OP > 2 -> MAIN

  addi $s0, $v0, 0              # Salva in $s0 l'operazione da eseguire

__keyask:                       # Legge la chiave
  li $v0, 4                     #   NOTA: La chiave deve essere diversa da 0   
  la $a0, keyprompt             #         inoltre viene ridotta in modulo 26
  syscall                       #         cifrare con chiave 1 o chiave 27 porta allo stesso risultato

  li $v0, 5
  syscall

  li $t0, 26                    # Salva nel registro il valore del modulo
  div $v0, $t0
  mfhi $t1                      # $t1 <- $v0 % 26

  beqz $t1, __keyask
  blt $t1, $0, __keyask
  addi $s1, $t1, 0              # Salva in $s1 la chiave

__stringask:                    # Legge la stringa da manipolare
  li $v0, 4
  la $a0, txtprompt
  syscall

  li $v0, 8
  la $a0, string
  li $a1, 255
  syscall

  la $a0, string
  jal __strlen

  beq $v1, 0, __stringok
  j __stringask

__stringok:
  addi $s2, $v0, 0              # $s2 <- strlen( stringa )

__allocation:
  li $v0,9                      # Alloca un'area di memoria
  addi $a0, $s2, 0              # per salvare la stringa computata
  syscall

  addi $s3, $v0, 0

__opselect:
  beq $s0, 1, __cipherprompt
  beq $s0, 2, __decipherprompt
  j main

__decipherprompt:               # Stampa che stiamo per decifrare con chiave $s1

  ## Calcola il complementare della chiave per la decifratura
  add $t0, $s1, $s1
  sub $s1, $s1, $t0

  li $v0, 4
  la $a0, opdprompt
  syscall

  li $v0, 1
  addi $a0, $s1, 0
  syscall

  li $v0, 4
  la $a0, endl
  syscall

  j __invokecipher

__cipherprompt:                 # Stampa la chiave di cifratura in $s1
  li $v0, 4
  la $a0, opcprompt
  syscall

  li $v0, 1
  addi $a0, $s1, 0
  syscall

  li $v0, 4
  la $a0, endl
  syscall

__invokecipher:                 # Invoca la procedura di cifratura con i parametri:
  addi $a0, $s2, 0              #   $a0 <- Lunghezza della stringa
  li $a1, 0                     #   $a1 <- Indice corrente (inizia da 0)
  addi $a2, $s3, 0              #   $a2 <- Indirizzo stringa risultato
  jal __ciphercore

  j __done

__done:                         # Stampa il risultato dell'operazione
  li $v0, 4
  la $a0, resprompt
  syscall

  #
  # Print the operation output
  #
  addi $a0, $s3, 0
  li $v0, 4
  syscall

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

  beq $t0, 1, main              # $t0 != 1 -> esci

__exit:                         # Stampa messaggio di saluto ed esce
  li $v0, 4
  la $a0, byeprompt
  syscall

  li $v0, 10
  syscall

##################
### Procedures ###
##################

# =================================================
# CipherCore
#
# NOTA:
#   L'algoritmo di cifratura è il seguente:
#     c = ((p - l) + k) % 26) + l
#
#     p = ((c - l) - k) % 26) + l
#
#   Dove:
#       c = ciphertext
#       p = plaintext
#       l = codice ASCII del carattere 'a'/'z' o 'A'/'Z'
#           a seconda che p sia maiuscola o minuscola
#       k = chiave di cifratura
#
# Parametri
#   $a0 <- Lunghezza della stringa
#   $a1 <- Indice corrente
#   $a2 <- Indirizzo della stringa risultato
#
# Valori di ritorno
#   $v0 <- lunghezza della stringa
#   $v1 <- errore (-1/0)
# =================================================
__ciphercore:  
  addi $sp, $sp -16             # Salva:
  sw $a0, 0($sp)                #   Lunghezza della stringa
  sw $a1, 4($sp)                #   Indice corrente
  sw $a2, 8($sp)                #   Indirizzo stringa risultato
  sw $ra, 12($sp)               #   Return Address

  bge $a1, $a0, __ciphercoreend

  ## CIPHER CHARACTER
  addi $t1, $a0, 0            

  lb $a0, string($a1)
  jal __islowercase
  bne $v0, 1, __ciphercoreuppercase
  
__ciphercorelowercase:
  beq $s0, 2, __deciphercorelowercase
  li $t2, 97
  j __thecipheralgorithm

__deciphercorelowercase:
  li $t2, 122
  j __thecipheralgorithm

__ciphercoreuppercase:
  beq $s0, 2, __deciphercoreuppercase
  li $t2, 65
  j __thecipheralgorithm

__deciphercoreuppercase:
  li $t2, 90
  j __thecipheralgorithm

__thecipheralgorithm:    
  li $t7, 26
  sub $t3, $a0, $t2
  add $t3, $t3, $s1
  div $t3, $t7
  mfhi $t3
  add $t3, $t3, $t2 

  sb $t3, 0($a2)

  addi $a0, $t1, 0
  addi $a1, $a1, 1
  addi $a2, $a2, 1
  jal __ciphercore

__ciphercoreend:

  lw $a0, 0($sp)
  lw $a1, 4($sp)
  lw $a2, 8($sp)
  lw $ra, 12($sp)
  addi $sp, $sp, 16
  jr $ra

# =================================================
# Parametri
#   $a0 <- indirizzo della stringa da misurare
#
# Valori di ritorno
#   $v0 <- lunghezza della stringa
#   $v1 <- errore (-1/0)
# =================================================
__strlen:

  addi $sp, $sp, -8
  sw $a0, 0($sp)
  sw $ra, 4($sp)

  li $t0, 0
  li $t1, 0
  addi $t2, $a0, 0
  li $t3, 10                  # New line character

  __strlenloop:
    lb $t1, 0($t2)
    beqz $t1, __strlenexit    # $t1 = \00 ?
    beq $t1, $t3 __strlenexit # $t1 = \n  ?

    addi $a0, $t1, 0          # $a0 <- Carattere corrente
    jal __isaletter           # Restituisce 1 se 
    bne $v0, 1, __strlenerror # il carattere inserito è una lettera valida

    addi $t2, $t2, 1
    addi $t0, $t0, 1
    j __strlenloop

  __strlenexit:
    lw $a0, 0($sp)
    lw $ra, 4($sp)
    addi $sp, $sp, 8

    addi $v0, $t0, 0
    li $v1, 0
    jr $ra

  __strlenerror:
    lw $a0, 0($sp)
    lw $ra, 4($sp)
    addi $sp, $sp, 8

    li $v1, -1
    jr $ra

# =================================================
# Parametri
#   $a0 <- Carattere da testare
#
# Valori di ritorno
#   $v0 <- 1: è una lettera
#          0: non è una lettera
# =================================================
__isaletter:
  addi $sp, $sp, -8
  sw $a0, 0($sp)  
  sw $ra, 4($sp)

  jal __islowercase
  beq $v0, 1, __isaletterok
  blt $v0, 0, __isalettererror

  jal __isuppercase
  beq $v0, 1, __isaletterok
  blt $v0, 0, __isalettererror

  __isalettererror:
    lw $a0, 0($sp)
    lw $ra, 4($sp)
    addi $sp, $sp, 8

    li $v0, 0
    jr $ra

  __isaletterok:
    lw $a0, 0($sp)
    lw $ra, 4($sp)
    addi $sp, $sp, 8

    li $v0, 1
    jr $ra

# =================================================
# Parametri
#   $a0 <- Carattere da testare
#
# Valori di ritorno
#   $v0 <- 1: è lowercase
#          0: non è una lowercase
#         -1: non è una lettera
# =================================================
__islowercase:
  blt $a0, 97, __isnotlowercase
  bgt $a0, 122, __islowercaseerror

  li $v0, 1
  jr $ra
  __islowercaseerror:
    li $v0, -1
    jr $ra
  __isnotlowercase:
    li $v0, 0
    jr $ra

# =================================================
# Parametri
#   $a0 <- Carattere da testare
#
# Valori di ritorno
#   $v0 <- 1: è uppercase
#          0: non è una uppercase
#         -1: non è una lettera
# =================================================
__isuppercase:
  blt $a0, 65, __isuppercaseerror
  bgt $a0, 90, __isnotuppercase

  li $v0, 1
  jr $ra
  __isuppercaseerror:
    li $v0, -1
    jr $ra
  __isnotuppercase:
    li $v0, 0
    jr $ra

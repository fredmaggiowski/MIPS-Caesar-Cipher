# ===========================================
# Federico Maggi
# MIPS Caesar Cipher
# ===========================================
#
# Recursive MIPS Ceasar Cipher 
# 
# Main:
#   $s0 -> Operation
#   $s1 -> Key
#   $s2 -> String length
#   $s3 -> Computed string address
#
.data
opprompt:     .asciiz "Choose the operation? (1: cipher - 2: decipher - 0: exit)\n> "
keyprompt:    .asciiz "Insert key (must be greated than 0):\n> "
opcprompt:    .asciiz "Ciphering with key: "
opdprompt:    .asciiz "Deciphering with key: "
txtprompt:    .asciiz "Insert the text:\n> "
resprompt:    .asciiz "Result:\n"
conprompt:    .asciiz "Press '1' to continue:\n> "
byeprompt:    .asciiz "Goodbye!\n"
errstrprompt: .asciiz "Invalid string!\n"
errkeyprompt: .asciiz "Invalid Key!\n"
endl:         .asciiz "\n"

string:       .space 256

.globl main

.text

main:                           
  li $v0, 4
  la $a0, opprompt
  syscall

  li $v0, 5                     # Reads the operation to do
  syscall

  beq $v0, $zero, __exit        # OP = 0 -> EXIT
  bltz $v0, main                # OP < 0 -> MAIN
  bgt $v0, 2, main              # OP > 2 -> MAIN

  addi $s0, $v0, 0              # Save in $s0 the operation

__keyask:                       # Read key
  li $v0, 4                     #   NOTE: The key must not be equal to 0  
  la $a0, keyprompt             #         it is reduced in modulus 26
  syscall

  li $v0, 5
  syscall

  li $t0, 26                    # Save in $t0 modulus value
  div $v0, $t0
  mfhi $t1                      # $t1 <- $v0 % 26

  beqz $t1, __keyask
  blt $t1, $0, __keyask
  addi $s1, $t1, 0              # Save the key in $s1

__stringask:                    # Read the string to manipulate
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
  addi $s2, $v0, 0              # $s2 <- strlen( string )

__allocation:
  li $v0,9                      # Allocate a memory buffer
  addi $a0, $s2, 1              # to save the computed string
  syscall

  addi $s3, $v0, 0

__opselect:
  beq $s0, 1, __cipherprompt
  beq $s0, 2, __decipherprompt
  j main

__decipherprompt:
  add $t0, $s1, $s1             # This calculate the opposite
  sub $s1, $s1, $t0             # of the key

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

__cipherprompt:
  li $v0, 4
  la $a0, opcprompt
  syscall

  li $v0, 1
  addi $a0, $s1, 0
  syscall

  li $v0, 4
  la $a0, endl
  syscall

__invokecipher:                 # Invoke the cipher procedure with paramethers:
  addi $a0, $s2, 0              #   $a0 <- String length
  li $a1, 0                     #   $a1 <- Current index
  addi $a2, $s3, 0              #   $a2 <- Result string address
  jal __ciphercore

  j __done

__done:                         # Print result
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

  li $v0, 4                     # Print "continue" request
  la $a0, conprompt
  syscall

  li $v0, 5                     # Read reply
  syscall

  addi $t0, $v0, 0              # $t0 <- reply

  li $v0, 4                     # Print a \n
  la $a0, endl
  syscall

  beq $t0, 1, main              # $t0 != 1 -> EXIT

__exit:                         # Print goodbye message and exit
  li $v0, 4
  la $a0, byeprompt
  syscall

  li $v0, 10
  syscall

##################
### Procedures ###
##################

# =================================================
# cipherCore
#
# NOTA:
#   The cipher algorithm is the following:
#     c = ((p - l) + k) % 26) + l
#     p = ((c - l) - k) % 26) + l
#
#   Dove:
#       c = ciphertext
#       p = plaintext
#       l = ASCII offset character
#       k = key
#
#   For information about the offset character cfr:
#       __getcharoffset
#
# Paramethers:
#   $a0 <- String length
#   $a1 <- Current index
#   $a2 <- Result string address
#
# Return values
#   $v0 <- String length
#   $v1 <- error (-1/0)
# =================================================
__ciphercore:  
  addi $sp, $sp -16             # Save:
  sw $a0, 0($sp)                #   String length
  sw $a1, 4($sp)                #   Current index
  sw $a2, 8($sp)                #   Result strin address
  sw $ra, 12($sp)               #   Return Address

  li $t5, 0                     # write the end strin character \0
  sb $t5, 0($a2)                # in current position.

  bge $a1, $a0, __ciphercoreend

  ## CIPHER CHARACTER
  addi $t1, $a0, 0            

  lb $a0, string($a1)

  jal __isaspace
  beq $v0, 1, __ciphercoreisspace

  jal __getcharoffset           # this procedure returns the offset in $v0
  addi $t2, $v0, 0              # $t2 <- offset

  __thecipheralgorithm:
    li $t7, 26                  # $t7 <- modulus
    sub $t3, $a0, $t2           # $t3 = Char - offset
    add $t3, $t3, $s1           # $t3 += key
    div $t3, $t7                # $t3 % modulus (26)
    mfhi $t3
    add $t3, $t3, $t2           # $t3 += offset

    sb $t3, 0($a2)

  __ciphercorenextchar:
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

  __ciphercoreisspace:
    li $t5, 32
    sb $t5, 0($a2)
    j __ciphercorenextchar

# =================================================
# getCharOffset
#
# Returns the right offset to execute
# cipher and decipher operation
#
#   The'offset is:
#     During cipher:
#       'a': if the char is lowercase
#       'A': if the char is uppercase
#     During decipher:
#       'z': if the char is lowercase
#       'Z': if the char is uppercase
#
# Paramether:
#   $a0 <- Character to test
#
# Return:
#   $v0 <- offset
# =================================================
__getcharoffset:
  addi $sp, $sp, -8
  sw $a0, 0($sp)
  sw $ra, 4($sp)
  
  jal __islowercase

  lw $a0, 0($sp)
  lw $ra, 4($sp)
  addi $sp, $sp, 8

  bne $v0, 1, __ciphercoreuppercase
  
  __ciphercorelowercase:
    beq $s0, 2, __deciphercorelowercase
    li $v0, 97
    jr $ra

  __deciphercorelowercase:
    li $v0, 122
    jr $ra

  __ciphercoreuppercase:
    beq $s0, 2, __deciphercoreuppercase
    li $v0, 65
    jr $ra

  __deciphercoreuppercase:
    li $v0, 90
    jr $ra

# =================================================
# strLen
#
# The procedure counts the string length and 
# validates it. A valid string must not contain
# any character apart from letters and spaces
#
# Paramether;
#   $a0 <- string to validate
#
# Return:
#   $v0 <- string length
#   $v1 <- error (-1/0)
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

    addi $a0, $t1, 0          # $a0 <- Currenct char
    jal __isavalidchar        # returns 1 if it's valid
    bne $v0, 1, __strlenerror

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

    li $v0, 4
    la $a0, errstrprompt
    syscall

    li $v0, -1
    li $v1, -1
    jr $ra

# =================================================
# isAChar
#
# Paramether
#   $a0 <- Character to test
#
# Returns:
#   $v0 <- 1: valid char
#          0: not valid char
# =================================================
__isavalidchar:
  addi $sp, $sp, -8
  sw $a0, 0($sp)
  sw $ra, 4($sp)

  jal __isaletter
  beq $v0, 1, __validcharfound

  jal __isaspace
  beq $v0, 1, __validcharfound

  lw $a0, 0($sp)
  lw $ra, 4($sp)
  addi $sp, $sp, 8

  li $v0, 0
  jr $ra

  __validcharfound:
    lw $a0, 0($sp)
    lw $ra, 4($sp)
    addi $sp, $sp, 8

    li $v0, 1
    jr $ra

# =================================================
# isALetter
#
# Paramether:
#   $a0 <- Character to test
#
# Returns:
#   $v0 <- 1: is a letter
#          0: not a letter
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
# isASpace
#
# Paramether
#   $a0 <- Char to test
#
# Returns
#   $v0 <- 1: is a space
#          0: not a space
# =================================================
__isaspace:
  bne $a0, 32, __isnotaspace
  
  li $v0, 1
  jr $ra

  __isnotaspace:
    li $v0, 0
    jr $ra

# =================================================
# isLowerCase
#
# Paramether
#   $a0 <- Char to test
#
# Return
#   $v0 <- 1: is lowercase
#          0: not lowercase
#         -1: not a letter
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
# isUpperCase
#
# Paramether
#   $a0 <- character to test
#
# Returns
#   $v0 <- 1: is uppercase
#          0: not uppercase
#         -1: not a letter
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

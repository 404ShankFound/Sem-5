;4. Write a program to multiply two 32 bit numbers using repetitive addition
	AREA RESET, DATA, READONLY
    EXPORT __Vectors
__Vectors
    DCD 0x10001000
    DCD Reset_Handler
    ALIGN
    AREA mycode, CODE, READONLY
    ENTRY
    EXPORT Reset_Handler
Reset_Handler
    LDR R0, =A             ; Address of A
    LDR R1, [R0]           ; R1 = A
    LDR R0, =B             ; Address of B
    LDR R2, [R0]           ; R2 = B
    MOV R3, #1             ; i = 1
LCM_LOOP
    MUL R4, R3, R1         ; R4 = i × A
    UDIV R5, R4, R2        ; R5 = (i × A) / B
    MUL R6, R5, R2         ; R6 = quotient × B
    SUB R7, R4, R6         ; R7 = remainder
    CMP R7, #0             ; Is remainder zero?
    BEQ LCM_FOUND
    ADD R3, R3, #1         ; i++
    B LCM_LOOP
LCM_FOUND
    MUL R4, R3, R1         ; LCM = i × A
    LDR R0, =LCM
    STR R4, [R0]
STOP B STOP
A DCD 12
B DCD 18
    AREA data, DATA, READWRITE
LCM DCD 0
    END
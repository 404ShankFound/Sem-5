;1. Write a program to subtract two 32 bit numbers
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
        LDR R0, =NUMBERS
        LDR R1, [R0]          ; Load first 32-bit number
        LDR R2, [R0, #4]      ; Load second 32-bit number
        SUBS R3, R1, R2      ; R3 = R1 - R2
        LDR R4, =RESULT
        STR R3, [R4]         ; Store result
STOP
        B STOP
        AREA data, DATA, READWRITE
NUMBERS
        DCD 0x55555555, 0x22222222
RESULT
        DCD 0
        END
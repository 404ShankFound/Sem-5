;2. Find the sum of ‘n’ natural numbers using MLA instruction.
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
	LDR R0, =NUM1
	LDR R1, =NUM2
	LDR R2, =RESULT		
	MOV R6, #0
	MOV R5, #4		
	LDR R3, [R0,R6]
	LDR R4, [R1,R6]		
	ADDS R3, R3, R4
	STR R3, [R2, R6]		
	ADD R6, R6, #4
	SUB R5, R5, #1		
ADD_LOOP
	LDR R3, [R0,R6]
	LDR R4, [R1,R6]		
	ADCS R3, R3, R4
	STR R3, [R2, R6]		
	ADD R6, R6, #4
	SUBS R5,R5, #1
	BNE ADD_LOOP		
	MOV R3, #0
	ADC R3, R3, #0
	STR R3, [R2,R6]		
STOP B STOP		
NUM1
    DCD 0x11111111
    DCD 0x22222222
    DCD 0x33333333
    DCD 0x44444444
NUM2
    DCD 0x11111111
    DCD 0x22222222
    DCD 0x33333333
    DCD 0x55555555
    AREA data, DATA, READWRITE
RESULT DCD 0, 0, 0, 0, 0
        END
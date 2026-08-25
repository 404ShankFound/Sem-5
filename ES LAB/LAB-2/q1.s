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
	LDR R0,=SRC
	LDR R1,=DST
	MOV R2,#10
CONT
	LDR R3,[R0],#4
	STR R3,[R1],#4
	SUBS R2,#1
	BNE CONT
STOP
	B STOP  
    AREA DATASEG, DATA, READWRITE
SRC
	DCD 10,11,12,13,14,95,96,97,98,99
	;SRC is label pointing to starting address of the array from which onwards the data 10,..,99 is stored
DST
	DCD 0,0,0,0,0,0,0,0,0,0
	;DEST is the label pointing at which destination array of all zeroes is stored
	;Address of DEST label = address of destination array
	END
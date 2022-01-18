    .section .rodata
    .global rdrPayload
    .type   rdrPayload, @object
    .align  4
rdrPayload:
    .incbin "rdrPayload/rdrPayload.bin"
rdrPayloadEnd:
    .global rdrPayloadSize
    .type   rdrPayloadSize, @object
    .align  4
rdrPayloadSize:
    .int    rdrPayloadEnd - rdrPayload

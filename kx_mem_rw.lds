SECTIONS
{
    . = 0x0;
    .text : { *(.text) }
    .rodata : { *(.rodata) }
    .data : { *(.data) }
    .bss : { *(.bss) }
    .kpm.info : { *(.kpm.info) }
    .kpm.init : { *(.kpm.init) }
    .kpm.exit : { *(.kpm.exit) }
    .kpm.ctl0 : { *(.kpm.ctl0) }
    .kpm.ctl1 : { *(.kpm.ctl1) }
}

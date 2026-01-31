# -*- coding: utf-8 -*-
import idc
import idaapi
import idautils
import os


def main():
    """
    生成 ASM 文件
    """
    idc.Wait()
    PATH = "XXX/asm"
    filename = 'XXX/classifier/magic/asm_and_acfg/sample.asm'
    try:
        idc.GenerateFile(idc.OFILE_LST, filename, 0, idc.BADADDR, 0)
    except:
        print('something wrong')
    idc.Exit(0)


if __name__ == "__main__":
    main()



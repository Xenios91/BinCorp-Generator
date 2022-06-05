from typing import List

import angr


class OffsetFinder():
    '''
    Static class used for generating all basic block offsets
    '''
    _offsets: List[int] = list()

    @staticmethod
    def generate_offsets(filename: str) -> List[int]:
        '''
        Static method used to generate basic block offsets
        '''

        p = angr.Project(filename, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        cfg.normalize()
        for func_node in cfg.functions.values():
            if func_node.name.startswith("__"):
                continue
            else:
                for block in func_node.blocks:
                    function_offset = func_node.offset
                    instruction_offset = abs(func_node.addr - block.addr)
                    OffsetFinder._offsets.append(
                        function_offset + instruction_offset)
        return OffsetFinder._offsets

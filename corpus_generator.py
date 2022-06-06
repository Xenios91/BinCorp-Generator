'''
Module for defining classes related to corpus generation
'''

from typing import List

import angr
import claripy
from tqdm import tqdm


class OffsetFinder():
    '''
    Static class used for generating all basic block offsets
    '''
    _offsets: List[int] = []

    @staticmethod
    def generate_offsets(filename: str) -> List[int]:
        '''
        Static method used to generate basic block offsets
        '''

        project: angr.Project = angr.Project(filename, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        cfg.normalize()
        for func_node in cfg.functions.values():
            if func_node.name.startswith("__"):
                continue

            for block in func_node.blocks:
                function_offset = func_node.offset
                instruction_offset = abs(func_node.addr - block.addr)
                OffsetFinder._offsets.append(
                    function_offset + instruction_offset)
        return OffsetFinder._offsets


class ArgumentDetails():
    '''
    Class to represent the cli argument details for corpus generation
    '''
    arg: str
    argument_size: int

    def __init__(self, argument_size: int) -> None:
        self.arg = "arg"
        self.argument_size = argument_size

    def get_arg(self) -> claripy.BV:
        '''
        Returns a claripy.BV object representing a CLI argument
        '''
        return claripy.BVS(self.arg, self.argument_size)


class CorpusGenerator():
    '''
    Class BinSolver is used to generate a test corpus for a binary executable
    '''
    filename: str
    project: angr.Project
    arg_corpus: set[str] = set()
    stdin_corpus: set[str] = set()
    argument_details: List[ArgumentDetails] = []
    arg_list = []
    offsets: List[int] = list

    def __init__(self, file: str, arguments: list) -> None:
        self.filename = file
        self.project = angr.Project(
            self.filename, main_opts={'base_addr': 0}, auto_load_libs=False)
        self.argument_details = arguments
        self.offsets = OffsetFinder.generate_offsets(self.filename)

    def _write_corpus_to_file(self):
        arg_corpus_name: str = f"arg_corpus_{self.filename}.dump"
        stdin_corpus_name: str = f"stdin_corpus_{self.filename}.dump"

        with open(arg_corpus_name, 'w', encoding='utf=8') as output:
            for value in self.arg_corpus:
                output.write(f"{value}\n")

        with open(stdin_corpus_name, 'w', encoding='utf=8') as output:
            for value in self.stdin_corpus:
                output.write(f"{value}\n")

    def _explore_bin(self) -> List[angr.SimulationManager]:

        print("Starting Binary Analysis... Go grab a coffee because this may take a while...\n")

        state = self.project.factory.entry_state(
            args=self.arg_list)

        si_managers: List[angr.SimulationManager] = []

        for ctr in tqdm(range(len(self.offsets))):
            offset: int = self.offsets[ctr]
            simgr = self.project.factory.simulation_manager(state)
            simgr.explore(find=offset)
            si_managers.append(simgr)

        print("\nBinary Analysis Complete!")

        return si_managers

    def generate_corpus(self):
        '''
        Generates a corpus based on the supplied binary executable and arguments assigned
        '''
        self.arg_list.append(self.filename)

        for arg in self.argument_details:
            self.arg_list.append(arg.get_arg())

        si_managers: List[angr.SimulationManager] = self._explore_bin()

        print("\nStarting Corpus Generation...\n")

        for i in tqdm(range(len(si_managers))):
            simgr: angr.SimulationManager = si_managers[i]
            if len(simgr.found) > 0:
                sig = simgr.found[0]
                for ctr, arg in enumerate(self.arg_list[1:]):
                    corpus_value: str = f"argv[{ctr}] = {sig.solver.eval(arg, cast_to=bytes)}"
                    self.arg_corpus.add(corpus_value)

                ctr: int = 0
                while True:
                    dump = sig.posix.dumps(ctr)
                    if dump == b"":
                        break

                    self.stdin_corpus.add(str(sig.posix.dumps(ctr)))
                    ctr = ctr + 1

        self._write_corpus_to_file()
        print("\nCorpus Generation Complete!")

from typing import List

import angr

from argument_details import ArgumentDetails
from offset_finder import OffsetFinder


class CorpusGenerator():
    '''
    Class BinSolver is used to generate a test corpus for a binary executable
    '''
    filename: str
    project: angr.Project
    arg_corpus: set[str] = set()
    stdin_corpus: set[str] = set()
    argument_details: List[ArgumentDetails] = list()
    arg_list = list()
    offsets: List[int] = list

    def __init__(self, file: str, arguments: list, load_libs=False) -> None:
        self.filename = file
        self.project = angr.Project(
            self.filename, main_opts={'base_addr': 0}, auto_load_libs=load_libs)
        self.argument_details = arguments
        self.offsets = OffsetFinder.generate_offsets(self.filename)

    def _write_corpus_to_file(self):
        arg_corpus_name = f"arg_corpus_{self.filename}.dump"
        stdin_corpus_name = f"stdin_corpus_{self.filename}.dump"

        with open(arg_corpus_name, 'w', encoding='utf=8') as output:
            for value in self.arg_corpus:
                output.write(value)
                output.write("\n")

        with open(stdin_corpus_name, 'w', encoding='utf=8') as output:
            for value in self.stdin_corpus:
                output.write(value)
                output.write("\n")

    def _explore_bin(self) -> List[angr.SimulationManager]:
        state = self.project.factory.entry_state(
            args=self.arg_list)

        si_managers = []

        for offset in self.offsets:
            simgr = self.project.factory.simulation_manager(state)
            simgr.explore(find=offset)
            si_managers.append(simgr)

        return si_managers

    def generate_corpus(self):
        '''
        Generates a corpus based on the supplied binary executable and arguments assigned
        '''
        self.arg_list.append(self.filename)

        for arg in self.argument_details:
            self.arg_list.append(arg.get_arg())

        si_managers = self._explore_bin()

        print("\nStarting Generation\n")

        for simgr in si_managers:
            if len(simgr.found) > 0:
                sig = simgr.found[0]
                for ctr, arg in enumerate(self.arg_list):
                    if ctr == 0:
                        continue

                    corpus_value: str = f"argv[{ctr}] = {sig.solver.eval(arg, cast_to=bytes)}"
                    self.arg_corpus.add(corpus_value)

                print(f"Argv dump complete for offset: [{sig.addr}]!")

                ctr: int = 0
                while(True):
                    dump = sig.posix.dumps(ctr)
                    if dump != b"":
                        self.stdin_corpus.add(str(sig.posix.dumps(ctr)))
                        ctr = ctr + 1
                    else:
                        break

        self._write_corpus_to_file()

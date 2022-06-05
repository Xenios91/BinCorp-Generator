import claripy


class ArgumentDetails():
    '''
    Class to represent the cli argument details for corpus generation
    '''
    arg = "arg"
    argument_size: int

    def __init__(self, argument_size: int) -> None:
        self.argument_size = argument_size

    def get_arg(self) -> claripy.BV:
        '''
        Returns a claripy.BV object representing a CLI argument
        '''
        return claripy.BVS(self.arg, self.argument_size)

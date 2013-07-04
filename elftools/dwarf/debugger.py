#-------------------------------------------------------------------------------
# elftools: dwarf/debugger.py
#
# DWARF accelerated access (for debugger usage). This includes support for 
# .debug_pubnames, .debug_pubtypes section decoding.
#
# Shaheed Haque (srhaque@theiet.org)
# This code is in the public domain
#-------------------------------------------------------------------------------

from ..common.utils import struct_parse
from .die import DIE

class Pubnames(object):
    """ Low level access to global objects and functions via .debug_pubnames.
    """
    def __init__(self, dwarfinfo,  stream, structs,  debug_info):
        self.dwarfinfo = dwarfinfo
        self.stream = stream
        self.structs = structs
        self.debug_info = debug_info

    def get_DIE(self,  name):
        """ Get the DIE for the given name.

        @param name         Byte array comprising the symbol to be found.
        @return The DIE for the given name, or None if the name is not found.
        """
        for cu_shortcut,  symbol_shortcut in self.iter():
            if symbol_shortcut.name == name:
                #if symbol_shortcut.offset > cu_shortcut.debug_info_length:
                #    raise DWARFError("invalid offset {} > {}".format(symbol_shortcut.offset,  cu_shortcut.debug_info_length))
                cu = self.dwarfinfo._parse_CU_at_offset(cu_shortcut.debug_info_offset)
                #
                # Find the specific DIE of interest.
                #
                return DIE(cu=cu, stream=self.debug_info, offset=symbol_shortcut.offset)
        return None

    def iter(self):
        """ Loop over the items in the section.
        This routine attempts to be coded in a reasonably slimline manner, with the hope that it will be fast.
        
        @return A pair of construct.lib.container.Containers representing the CU for the pubnames entry,
        and the entry itself.
        """
        self.stream.seek(0)
        max_offset = len(self.stream.getbuffer())
        while self.stream.tell() < max_offset:
            cu_shortcut = struct_parse(self.structs.Dwarf_by_name_header, self.stream)
            #print(self.stream.tell(),  max_offset, cu_shortcut)
            while True:
                symbol_shortcut  = struct_parse(self.structs.Dwarf_by_name_entry, self.stream)
                if symbol_shortcut.offset == 0:
                    break
                yield cu_shortcut,  symbol_shortcut
        return None,  None

class Pubtypes(Pubnames):
    """ Low level access to global types via .debug_pubtypes.
    """
    pass

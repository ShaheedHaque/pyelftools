#-------------------------------------------------------------------------------
# elftools: dwarf/debugger.py
#
# DWARF accelerated access (for debugger usage). This includes support for 
# .debug_pubnames, .debug_pubtypes section decoding.
#
# Shaheed Haque (srhaque@theiet.org)
# This code is in the public domain
#-------------------------------------------------------------------------------

import os
from ..common.exceptions import DWARFError
from ..common.utils import struct_parse
from .die import DIE

class Pubnames(object):
    """ Low- and high-level access to global objects and functions by name via
    .debug_pubnames.
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
        for cu_shortcut, entry in self.iter():
            if entry.name == name:
                if entry.offset > cu_shortcut.debug_info_length:
                    raise DWARFError("invalid offset {} > {}".format(entry.offset,  cu_shortcut.debug_info_length))
                cu = self.dwarfinfo._parse_CU_at_offset(cu_shortcut.debug_info_offset)
                #
                # Find the specific DIE of interest.
                #
                return DIE(cu=cu, stream=self.debug_info, offset=cu_shortcut.debug_info_offset + entry.offset)
        return None

    def iter(self):
        """ Loop over the items in the section.
        This routine attempts to be coded in a reasonably slimline manner, with
        the hope that it will be fast.
        
        @return A pair of construct.lib.container.Containers representing the 
        CU for the entry, and the entry itself.
        """
        self.stream.seek(0)
        max_offset = len(self.stream.getbuffer())
        while self.stream.tell() < max_offset:
            cu_shortcut = struct_parse(self.structs.Dwarf_by_name_header, self.stream)
            #print(self.stream.tell(),  max_offset, cu_shortcut)
            while True:
                entry = struct_parse(self.structs.Dwarf_by_name_entry, self.stream)
                if entry.offset == 0:
                    break
                yield cu_shortcut, entry
        return None,  None

class Pubtypes(Pubnames):
    """ Low-  and high-level access to global types by name via 
    .debug_pubtypes.
    """
    pass

class ARanges(object):
    """ Low- and high-level access to program text or data by address via
    .debug_aranges.
    """
    def __init__(self, dwarfinfo,  stream, structs,  debug_info):
        self.dwarfinfo = dwarfinfo
        self.stream = stream
        self.structs = structs
        self.debug_info = debug_info

    def get_DIE(self,  address,  segment = None):
        """ Get the CU for the given address.

        @param address       The address to be found.
        @param segment      The segment containing address (or None).
        @return The CU for the given address, or None if the address is not found.
        """
        for cu_shortcut, entry in self.iter():
            if entry.address <= address and address < entry.address + entry.length and entry.segment == segment:
                cu = self.dwarfinfo._parse_CU_at_offset(cu_shortcut.debug_info_offset)
                return cu.get_top_DIE()
        return None

    def iter(self):
        """ Loop over the items in the section.
        This routine attempts to be coded in a reasonably slimline manner, with
        the hope that it will be fast.
        
        @return A construct.lib.container.Container representing the CU, then
        the entry with segment (which may be None), start address and length. 
        """
        self.stream.seek(0)
        max_offset = len(self.stream.getbuffer())
        while self.stream.tell() < max_offset:
            cu_shortcut = struct_parse(self.structs.Dwarf_by_address_header, self.stream)
            #print(self.stream.tell(),  max_offset, cu_shortcut)
            entry_struct = self.structs.Dwarf_by_address_entry_segmented if cu_shortcut.segment_size else self.structs.Dwarf_by_address_entry_flat
            #
            # The documentation is silent on this point, but the values here 
            # seem to be aligned, presumably for performance. TBD: what
            # if segments are in use, and the segment size is not the same
            # as the address size?
            #
            unaligned = self.stream.tell() % cu_shortcut.address_size
            if unaligned:
                self.stream.seek(cu_shortcut.address_size - unaligned,  os.SEEK_CUR)
            while True:
                entry = struct_parse(entry_struct, self.stream)
                if entry.length == 0 and entry.address == 0 and not entry.segment:
                    break
                yield cu_shortcut, entry
        return None,  None

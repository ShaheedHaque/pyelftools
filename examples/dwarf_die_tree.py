#-------------------------------------------------------------------------------
# elftools example: dwarf_die_tree.py
#
# In the .debug_info section, Dwarf Information Entries (DIEs) form a tree.
# pyelftools provides easy access to this tree, as demonstrated here.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import os
import sys

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            print('    Top DIE with tag=%s' % top_DIE.tag)

            # Each DIE holds an OrderedDict of attributes, mapping names to
            # values. Values are represented by AttributeValue objects in
            # elftools/dwarf/die.py
            # We're interested in the filename, which is the join of
            # 'DW_AT_comp_dir' and 'DW_AT_name', either of which may be
            # missing in practice. Note that its value
            # is usually a string taken from the .debug_string section. This
            # is done transparently by the library, and such a value will be
            # simply given as a string.
            try:
                comp_dir_attr = top_DIE.attributes['DW_AT_comp_dir']
                comp_dir = bytes2str(comp_dir_attr.value)
                try:
                    name_attr = top_DIE.attributes['DW_AT_name']
                    name = bytes2str(name_attr.value)
                    name = os.path.join(comp_dir, name)
                except KeyError as e:
                    name = comp_dir
            except KeyError as e:
                name_attr = top_DIE.attributes['DW_AT_name']
                name = "bytes2str(name_attr.value)"
            print('    name=%s' % name)
            #print('    name=%s, %s-%s' % (name, bytes2str(top_DIE.attributes['DW_AT_low_pc'].value), bytes2str(top_DIE.attributes['DW_AT_high_pc'].value)))

            # Display DIEs recursively starting with top_DIE
            die_info_rec(top_DIE)


def die_info_rec(die, indent_level='    '):
    """ A recursive function for showing information about a DIE and its
        children.
    """
    print(indent_level + 'DIE tag=%s' % die.tag)
    child_indent = indent_level + '  '
    for child in die.iter_children():
        die_info_rec(child, child_indent)


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        process_file(filename)







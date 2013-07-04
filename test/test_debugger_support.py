#-------------------------------------------------------------------------------
# elftools tests
# Test the support of .debug_pubnames.
#
# Shaheed Haque (srhaque@theiet.org)
# This code is in the public domain
#-------------------------------------------------------------------------------
try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os

from utils import setup_syspath; setup_syspath()
from elftools.elf.elffile import ELFFile

class TestDebuggerSupport(unittest.TestCase):

    def _test_pubnames(self, testfile):
        with open(os.path.join('test', 'testfiles_for_readelf',
                               testfile), 'rb') as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(b'.debug_pubnames')
            self.assertIsNotNone(section)

            dwarfinfo = elf.get_dwarf_info()
            pubnames = dwarfinfo.pubnames()
            self.assertIsNotNone(pubnames)

            main_DIE = pubnames.get_DIE(b'main')
            self.assertIsNotNone(main_DIE)
            self.assertEqual(main_DIE.attributes['DW_AT_name'].value,  b'main')

    def test_pubnames(self):
        self._test_pubnames('exe_simple64.elf')

if __name__ == '__main__':
    unittest.main()

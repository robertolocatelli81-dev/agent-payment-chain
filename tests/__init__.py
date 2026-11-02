"""The tests as a package. A test module that needs the real corpus (bundles/, oracle/: not distributed with the public
tree) raises unittest.SkipTest at import through tests/real_corpus.py; `unittest discover` turns that into a skip, but
loading by name (`python3 -m unittest tests.test_x`, tools/run_ordered.py) would raise it as an error: the loader is
taught here to report such a module as skipped, with the reason and the rebuild command, never as passed."""
import unittest
import unittest.loader

_orig = unittest.TestLoader.loadTestsFromName


def _skipped(name, reason, suite_class):
    @unittest.skip(reason)
    class ModuleSkipped(unittest.TestCase):
        def test_module(self):
            pass
    ModuleSkipped.__module__ = name
    return suite_class((ModuleSkipped("test_module"),))


def _load(self, name, module=None):
    try:
        return _orig(self, name, module)
    except unittest.SkipTest as e:
        return _skipped(name, str(e), self.suiteClass)


if not getattr(unittest.TestLoader.loadTestsFromName, "_apc_skip_aware", False):
    _load._apc_skip_aware = True
    unittest.TestLoader.loadTestsFromName = _load

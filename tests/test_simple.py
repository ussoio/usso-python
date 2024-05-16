# the inclusion of the tests module is not meant to offer best practices for
# testing in general, but rather to support the `find_packages` example in
# setup.py that excludes installing the "tests" package

import unittest


class TestSimple(unittest.TestCase):
    def test_import(self):
        import usso

        usso.Usso()
        usso.UserData()


if __name__ == "__main__":
    unittest.main()

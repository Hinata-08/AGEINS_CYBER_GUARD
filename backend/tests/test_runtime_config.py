import importlib
import unittest


class RuntimeConfigTests(unittest.TestCase):
    def test_backend_allows_explicit_runtime_configuration(self):
        import os

        os.environ["AGEINS_HOST"] = "0.0.0.0"
        os.environ["AGEINS_PORT"] = "8123"

        import backend.main as main_module

        importlib.reload(main_module)

        self.assertEqual(main_module.get_backend_runtime_config()["host"], "0.0.0.0")
        self.assertEqual(main_module.get_backend_runtime_config()["port"], 8123)


if __name__ == "__main__":
    unittest.main()

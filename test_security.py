import importlib.util
from pathlib import Path
import unittest

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

lan = load('lan', 'lan-scope.py')
agent = load('agent', 'download-agent.py')

class SecurityTests(unittest.TestCase):
    def test_ssh_target_rejects_option_injection(self):
        self.assertTrue(lan.valid_ssh_target('192.168.1.2', 'alice'))
        self.assertFalse(lan.valid_ssh_target('127.0.0.1 -o ProxyCommand=bad', 'alice'))
        self.assertFalse(lan.valid_ssh_target('127.0.0.1', '-o ProxyCommand=bad'))
        self.assertEqual(lan.ssh_args('192.168.1.2', 'alice')[-1], 'alice@192.168.1.2')

    def test_download_url_hides_credentials(self):
        self.assertEqual(agent.public_url('https://u:p@example.test/file?token=secret#frag'), 'https://example.test/file')
        self.assertEqual(agent.public_url('magnet:?xt=secret'), '(redacted)')

if __name__ == '__main__': unittest.main()

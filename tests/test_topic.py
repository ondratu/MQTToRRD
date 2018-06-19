"""Test for working with topics."""
from sys import path as python_path
from os import path
from unittest import TestCase
from collections import OrderedDict

TEST_PATH = path.dirname(__file__)              # noqa
python_path.insert(0, path.abspath(             # noqa
    path.join(TEST_PATH, path.pardir)))

from mqttorrd import Config


class Args():
    """Args mock."""
    config = None


class TestTopicParser(TestCase):
    """Test topic definition parsing."""
    cfg = Config(Args())
    cfg.read_dict(OrderedDict({
        '/root/sub/test': {'step': 1},
        '/root/+/test': {'step': 2},
        '/+/+/test': {'step': 3},
        '#/test': {'step': 4},
        '/root/#': {'step': 5},
        '$SYS/+/node': {'step': '6'},
        '#/root/+/bar': {'step': 7}
    }))

    def test_full_match(self):
        step, ds, rra = self.cfg.find_topic('/root/sub/test')
        assert step == 1

    def test_plus_match(self):
        step, ds, rra = self.cfg.find_topic('/root/plus/test')
        assert step == 2

    def test_more_plus_match(self):
        step, ds, rra = self.cfg.find_topic('/plus/plus/test')
        assert step == 3

    def test_start_hash_match(self):
        step, ds, rra = self.cfg.find_topic('/hash/test')
        assert step == 4

    def test_end_hash_match(self):
        step, ds, rra = self.cfg.find_topic('/root/hash')
        assert step == 5

    def test_SYS_regexp(self):
        step, ds, rra = self.cfg.find_topic('$SYS/bar/node')
        assert step == 6

    def test_mix(self):
        step, ds, rra = self.cfg.find_topic('/foo/root/node/bar')
        assert step == 7

    def test_default(self):
        step, ds, rra = self.cfg.find_topic('/foo/bar')
        assert step == 60

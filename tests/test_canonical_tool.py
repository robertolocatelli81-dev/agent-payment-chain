"""tools/canonical.py: the search of the dispute game that holds a block, on a simulated factory (offline). The factory
also holds games of other types, single and in runs; the search must still find the game of type 621 whose range holds
the block.

  python3 -m unittest tests.test_canonical_tool
"""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import canonical  # noqa: E402

SPAN, ROOTS = 600, 20


def fake_rpc(games):
    """games[i] = (type, l2SequenceNumber or None); the game at index i has address i + 1."""
    sel = canonical.sel

    def rpc(url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_getBlockByNumber":
            return {"number": params[0]}
        to, data = params[0]["to"], params[0]["data"]
        if data == sel("gameCount()"):
            return "0x%064x" % len(games)
        if data.startswith(sel("gameAtIndex(uint256)")):
            i = int(data[10:], 16)
            return "0x%064x%064x%024x%040x" % (games[i][0], 0, 0, i + 1)
        if to == canonical.REGISTRY:
            return "0x%064x" % 0
        seq = games[int(to, 16) - 1][1]
        if data == sel("l2SequenceNumber()"):
            return "0x%064x" % seq
        if data == sel("startingBlockNumber()"):
            return "0x%064x" % (seq - SPAN)
        if data == sel("extraData()"):
            ed = seq.to_bytes(32, "big") + bytes(20) + bytes(32 * ROOTS)
            return "0x" + (32).to_bytes(32, "big").hex() + len(ed).to_bytes(32, "big").hex() + ed.hex() + "00" * (-len(ed) % 32)
        return "0x%064x" % 0
    return rpc


class GameSearch(unittest.TestCase):
    def setUp(self):
        self.saved = canonical.rpc

    def tearDown(self):
        canonical.rpc = self.saved

    def find(self, games, n):
        canonical.rpc = fake_rpc(games)
        return int(canonical.build({"inclusion": {"block_header": {"number": hex(n)}}}, "l1", "l2")["game"], 16) - 1

    def test_other_types_between_621_games(self):
        rnd = random.Random(20261023)
        cases = 0
        for _ in range(300):
            games, seq = [], 1000
            for _ in range(rnd.randint(5, 200)):
                if rnd.random() < 0.3:
                    games.append((rnd.choice([0, 1, 1000]), None))
                else:
                    seq += SPAN
                    games.append((621, seq))
            for _ in range(rnd.randint(0, 3)):
                games.insert(rnd.randrange(len(games) + 1), (1, None))
            idx = [i for i, g in enumerate(games) if g[0] == 621]
            if not idx:
                continue
            j = rnd.choice(idx)
            self.assertEqual(self.find(games, games[j][1] - rnd.randrange(SPAN)), j)
            cases += 1
        self.assertGreater(cases, 250)

    def test_block_after_the_last_game_is_refused(self):
        games = [(621, 1600), (1, None), (621, 2200)]
        with self.assertRaises(RuntimeError):
            self.find(games, 2201)


if __name__ == "__main__":
    unittest.main()

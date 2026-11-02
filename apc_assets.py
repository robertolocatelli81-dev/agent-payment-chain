"""Amendment 0.11.5 (SPEC section 19): stablecoins measured on chain, for the whole world (2026-10-26). For each
(network, asset): symbol and decimals from the token (eth_call symbol(), decimals()), the EIP-712 domain name and
version under which real executed EIP-3009 signatures recover their `from` (oracle/world_20261026, bundles/
real_world_20261026), and whether the deployed token refuses a high-s signature (tools/probe_lows_usdc.py: eth_call of
transferWithAuthorization, value 0, a throwaway key: the low-s call returns, the same signature with s' = n - s
reverts "ECRecover: invalid signature 's' value"). Read only by the report (member `asset`) and by the high-s rule of
Amendment 0.3.2; an asset outside the table is not guessed."""

# (network, asset lower case): (symbol, decimals, EIP-712 name, version, high_s_refused, evidence)
ASSETS = {
    ("eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): ("USDC", 6, "USD Coin", "2", True, "0.3.2, 2026-10-24"),
    ("eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e"): ("USDC", 6, "USDC", "2", True, "0.3.2, 2026-10-24"),
    ("eip155:1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): ("USDC", 6, "USD Coin", "2", True, "probe_eth_usdc"),
    ("eip155:43114", "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"): ("USDC", 6, "USD Coin", "2", True, "probe_avax_usdc"),
    ("eip155:42161", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"): ("USDC", 6, "USD Coin", "2", True, "probe_arb_usdc"),
    ("eip155:10", "0x0b2c639c533813f4aa9d7837caf62653d097ff85"): ("USDC", 6, "USD Coin", "2", True, "probe_op_usdc"),
    ("eip155:143", "0x754704bc059f8c67012fed69bc8a327a5aafb603"): ("USDC", 6, "USDC", "2", True, "probe_monad_usdc"),
    ("eip155:42220", "0xceba9300f2b948710d2653dd7b07f33a8b32118c"): ("USDC", 6, "USDC", "2", True, "probe_celo_usdc"),
    ("eip155:42220", "0x48065fbbe25f71c9282ddf5e1cd6d6a887483d5e"): ("USD\u20ae", 6, "Tether USD", "1", True, "probe_celo_usdt"),
    ("eip155:42220", "0xd2ab3c9a02dbbab236bfec45d1d755df4267f771"): ("USAT", 6, "Tether America USD", "1", True,
                                                                   "probe_celo_usat"),
    ("eip155:8453", "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"): ("EURC", 6, "EURC", "2", True, "probe_base_eurc"),
    ("eip155:137", "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29"): ("JPYC", 18, "JPY Coin", "1", True, "probe_polygon_jpyc"),
}


def info(network, asset, amount):
    """The report member `asset`, or None for an asset outside the table. amount: the atomic integer."""
    a = ASSETS.get((network, asset))
    if a is None:
        return None
    sym, dec, name, ver, _, _ = a
    q, r = divmod(amount, 10 ** dec)
    frac = ("%0*d" % (dec, r)).rstrip("0") if dec else ""
    return {"symbol": sym, "decimals": dec, "amount": "%d%s" % (q, "." + frac if frac else ""),
            "eip712": {"name": name, "version": ver}}

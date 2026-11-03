# agent-payment-chain bundle and link rules — SPEC 0.2, with the 0.3 and 0.4 additions in section 6, 0.5 (Solana) in
# section 7, 0.6 (report tools) in section 8, 0.7 (AP2 mandate binding) in section 9, 0.8 (HTTP exchange) in
# section 10, 0.9.1 (register of checks on an external device, format apc-reg-0.2) in section 11, 0.10 (Permit2 and
# ERC-7710) in section 12 (draft, local),
# 0.11 (signed offers and receipts) in section 13, 0.11.1 (builder code) in section 14, 0.11.2
# (payment-identifier) in section 15, 0.11.3 (MCP and A2A transports) in section 16,
# draft profiles of proposed x402 rules in section 17, 0.11.4 (hosts and URLs outside ASCII) in section 18,
# 0.11.5 (stablecoins measured for the world) in section 19, 0.12 (Stellar) in section 20,
# 0.13 (x402 v1) in section 21,
# 0.14 (signed report key window) in section 22,
# draft profiles, second set, in section 23,
# third set in section 24 (draft, local), 0.15 (scheme auth-capture on EVM) in section 25,
# 0.16 (XRP Ledger) in section 26, 0.16.1 (the Permit2 collect path of auth-capture) in section 25.1 and (the
# every-version amendments read in every bundle version) in section 27, 0.17 (signature rules of the chains, Wycheproof,
# passkey owners) in section 28, 0.18 (the bundle as hostile input: limits, internal errors, fuzzing) in section 29,
# 0.18.2 (the auth-capture receipt and logs bind the transaction's block) in section 25, 0.18.3 (the draft profiles' own
# Keccak-256 budget, the RLP bound counted on lists, exit 74 for a report not written) in section 29 and (a draft
# profile that cannot read the bundle never changes the verdict) in section 17, 0.18.4 (the drafts' budget in every
# draft module, exit 74 with standard error unwritable too) in sections 17 and 29, 0.19 (the evidence level of a
# verdict, `--require-level`) in section 30, 0.19.1 (neutral level names, the facilitator's reply apart in
# `facilitator_reply`, the highest level only with l1_state proven, a closed list of qualified outcomes) in section 30,
# 0.20 (the AP2 mandate as an ap2-evidence-pack) in section 31, 0.21 (a 65-byte signature of a payer with code: USDC's
# (v,r,s) path, the ERC-1271 of Circle_SingleOwnerMSCA 1.0.0 proven from state, `payer_state`) in section 32,
# the list of the real corpus and its rebuild from any endpoint (corpus/MANIFEST.json, format apc-corpus-0.2, then
# apc-corpus-0.3 with the anchored bundles, 33.10; tools/rebuild_corpus.py) in section 33

0.2 adds: `bundle_version` "apc-0.2", the optional `chain_tx.log_transfer` and `chain_tx.log_forward`, rules C3
and F1, indirect calls (C1 `not_applicable:indirect_call`), and smart-wallet payers (`payer_wallet`, L2.sig by
ERC-1271 for a closed list of wallet implementations). An "apc-0.1" bundle is read under the 0.1 rules plus the
corrections that apply to every version: the closed grammar of section 1 and the C2 block comparison of 0.2 (when the
log and the transaction both carry blockHash and blockNumber), Amendments 0.3.1 and 0.3.2, and parts 2 and 3 of Amendment 0.3.3 as they apply to every version (section 6); the additions of 0.2
and 0.3 (C3, F1, payer_wallet, K6, inclusion, canonical) are not applied to it.

A bundle carries the artifacts of ONE payment made by an agent. The verifier checks each artifact with the verifier
of its own layer, then the links between them. Every check ends `verified`, `failed:<reason>` or
`not_evaluated:<reason>` (C1 on an indirect call: `not_applicable:indirect_call`, section 4; O4 of 0.3 also
`pending:game_not_final`, section 6); nothing is skipped silently. Our format, so the rules are written here first, then in code.

Sources the rules are taken from (pinned by commit; copies and sha256 in `sources/` for x402, Circle, Coinbase and ERC-8021;
work-acceptance and AP2 are cited by commit without a copy here):
- x402 v2: x402-foundation/x402 @ 0aee759 — `specs/x402-specification-v2.md` (PaymentRequirements 5.1.2,
  PaymentPayload 5.2.2, SettlementResponse 5.3.2, CAIP-2 11.1), `specs/schemes/exact/scheme_exact.md` (line 39:
  "settlement MUST produce exactly one identifiable transfer of `amount` of `asset` to `payTo`"),
  `specs/schemes/exact/scheme_exact_evm.md` (EIP-3009 phase 2, verification steps 1-5).
- Circle stablecoin-evm @ fc85788 (Apache-2.0), the USDC implementation: `contracts/v2/EIP3009.sol` lines 143-144 and
  223-224 (`_markAuthorizationAsUsed(from, nonce); _transfer(from, to, value);`), line 336 (`emit AuthorizationUsed`),
  `contracts/v1/FiatTokenV1.sol` line 320 (`emit Transfer(from, to, value)` in `_transfer`).
- Work-acceptance profile 1.4.1 @ 06d3b94 (README only): optional signed body member `payment` =
  `{protocol, scheme, network, asset, payer, pay_to, amount, nonce[, settlement_tx]}`; "(network, asset, payer, nonce)
  names one settlement".
- AP2 @ e1ea56d (docs and schemas): amounts in ISO-4217 minor units with a 3-letter currency code; no merchant
  address; no x402 field ("The AP2 compatible x402 extension is coming soon").

## 1. Bundle (closed at every level of this grammar: any other member is refused with its path; from 0.21.5 one exception, the top level of payment_required, 32.14)

```
{
  "bundle_version": "apc-0.1" | "apc-0.2",
  "payment_required": <x402 v2 PaymentRequired>,          optional
  "payment_payload":  <x402 v2 PaymentPayload>,            required
  "settlement":       <x402 v2 SettlementResponse>,        optional
  "chain_tx":         {"network": "eip155:<id>", "tx": <eth_getTransactionByHash result>,
                       "log_authorization_used": <log object>,
                       "log_transfer": <log object>,
                       "log_forward": <log object>},              optional; log_transfer, log_forward only in apc-0.2
  "acceptance":       <work-acceptance record, profile 1.4.1>,    optional
  "mandate":          <ap2-evidence-pack evidence document>       optional
  "payer_wallet":     {"owner_index": <decimal string>, "code": <rpc>, "implementation": <rpc>, "owner": <rpc>}
                                                                  optional, apc-0.2 only
  "payer_state":      <section 32.4>                              optional, apc-0.2 only (0.21); not with payer_wallet
}
<rpc> is a saved JSON-RPC exchange {"method", "params", "result"}: the verifier checks its method and params (the
payer's address, the ERC-1967 slot, the ownerAtIndex call data, one common block) before reading its result.
```
Every JSON string is text: one holding an unpaired UTF-16 surrogate (a `\ud800` escape) is refused (0.3.1), and so is
a number outside the double range (1e400).
Closed levels: bundle, payment_payload (and its `resource`, an x402 ResourceInfo `{url[, description, mimeType]}`;
from 0.21.4 also `serviceName`, `tags`, `iconUrl`, by the rule of 32.13),
accepted, payload, authorization, settlement, chain_tx, payer_wallet and each of its three replies, payment_required (its
`resource` as above; every `accepts` entry an object; `x402Version` 2, else unsupported, and `error` a
string, from 0.7.1; from 0.21.5 a member of payment_required itself that x402 does not define is not refused but
ignored and named in `notes`, 32.14) and acceptance.receipt.payment. Read for the members named below only,
the rest carried and not interpreted: the RPC objects `tx` and the three logs (their members vary by client), the
`extensions` objects (x402 "protocol extensions data"; must be objects), the acceptance record outside `payment`
(war-verify's) and the mandate (ap2-evidence-pack's; must be an object).

Scope of 0.1: scheme `exact`, network namespace `eip155`, asset transfer method EIP-3009 only. Permit2, ERC-7710 and
other networks: refused as `unsupported:<what>` (not failed).

## 2. What is SIGNED and what is only DECLARED
In EIP-3009 the payer signs `from, to, value, validAfter, validBefore, nonce` under the token's EIP-712 domain
`(name, version, chainId, verifyingContract)`. Nothing else in the PaymentPayload is signed by the payer: `resource`,
`accepted` (amount, payTo, network, asset, extra) and `extensions` are an unsigned envelope. The report states, for
each link, whether its two ends are signed (S) or declared (D). A link D–D proves only internal consistency.

## 3. Layer checks (each by the existing verifier of that layer)
- L2.sig (S): EIP-712 digest with the 4-member domain {name: accepted.extra.name, version: accepted.extra.version,
  chainId: from accepted.network, verifyingContract: accepted.asset}; secp256k1 recovery of the 65-byte
  `payload.signature` (v 27/28) must equal `authorization.from`; an s in the upper half of the order: Amendment 0.3.2.
  Library: x402-signature-vectors `lib/` (stdlib). Contract-wallet signatures (not 65 bytes): in apc-0.1
  `not_evaluated:unsupported_signature_length_<n>`; in apc-0.2 see L2.sig-1271.
- L2.sig-1271 (S–chain, apc-0.2). USDC accepts a signature from a payer that has code by asking the payer
  (ERC-1271; Circle's FiatTokenV2_2 `bytes signature` path). On Base the measured case is the Coinbase Smart Wallet:
  payer code = the ERC-1967 minimal proxy (keccak256 of the code `aaa52c8c…890d`, 61 bytes), implementation slot
  0x360894a1…2bbc = 0x000100abaad02f1cfc8bbe32bd5a564817339e72 (Sourcify exact match `CoinbaseSmartWallet`, sources
  in `sources/coinbase_smart_wallet_000100ab`). The same wallet behind EIP-7702: payer code = the delegation
  designator 0xef0100 || 0x7702cb554e6bfb442cb743a7df23154544a7176c (Sourcify exact match `EIP7702Proxy`, sources in
  `sources/coinbase_eip7702proxy_7702cb55`), whose isValidSignature (EIP7702Proxy.sol 123-140) delegatecalls the
  implementation in the ERC-1967 slot of the payer's own storage and, failing that, accepts an ECDSA signature by
  the payer's own key over the raw hash (that case is the 65-byte L2.sig above); measured on Base: the slot holds
  the CoinbaseSmartWallet implementation. Its `isValidSignature(hash, signature)` (ERC1271.sol 69-96,
  CoinbaseSmartWallet.sol 297-325): `signature` = abi.encode(SignatureWrapper{ownerIndex, signatureData}); the owner at
  ownerIndex signs replaySafeHash(hash) = keccak256(0x1901 || domainSeparator || keccak256(abi.encode(
  keccak256("CoinbaseSmartWalletMessage(bytes32 hash)"), hash))), domain {name "Coinbase Smart Wallet", version "1",
  chainId, verifyingContract = the wallet}. The verifier: the three replies are for authorization.from and one block
  (the transaction's block when chain_tx is present: a chain_tx whose `tx.blockNumber` is not a JSON-RPC quantity is then
  refused); code hash and implementation in the closed list above, any
  other `not_evaluated:wallet_implementation_not_known`; the wrapper ABI-decoded strictly (offsets 0x20 and 0x40,
  length, zero padding, nothing after) and its ownerIndex == owner_index; owner bytes of length 32 (an address):
  ECDSA recovery of replaySafeHash(EIP-3009 digest) must be that address; length 64 (a passkey):
  `not_evaluated:passkey_owner_webauthn` (not implemented). Result `verified (ERC-1271 CoinbaseSmartWallet)`.
  What it rests on: the owner and implementation are chain state read by RPC (declared data, like chain_tx); the
  state is the one at the END of that block. Measured (Base, block 52899616+, tx 0x6ce1bacf…): both legs of a split
  payment recover the wallet's owner 0x69835329…; the signatures swapped between the legs recover other addresses.
  Without payer_wallet: `not_evaluated:contract_wallet_needs_payer_wallet`.
  Measured on real data: 34/34 executions of USDC on Base (block 52929129) recover `from`; 3-member domain 0/34.
- L3: the acceptance record is checked by war-verify; L1: the mandate by ap2-evidence-pack. Their verdicts are
  carried unchanged.

## 4. Link rules
Values compared: addresses as 20 bytes (`0x` + 40 hex; case ignored; a mixed-case address whose EIP-55 checksum is
wrong is noted, not refused, since x402 does not require EIP-55); amounts as decimal strings of atomic units with
no sign, no leading zeros, no exponent (anything else is refused, exit 3, reason `amount_not_canonical`; a value of
2^256 or more is refused with `exceeds uint256`); network as CAIP-2 `eip155:`
+ decimal chain id without leading zeros.

Payment payload against its own requirements (x402 scheme_exact.md line 39; scheme_exact_evm.md phase 2 steps 3-4):
- K1 (S–D) authorization.to == accepted.payTo
- K2 (S–D) authorization.value == accepted.amount (exact: equal, not "at least")
- K3 (S–D) chainId of the signed domain == accepted.network; verifyingContract == accepted.asset
- K4 (D–D) if payment_required is present: accepted is deep-equal (as JSON values: `true` is not `1`; 0.3.1) to one
  member of payment_required.accepts, and
  payment_payload.resource.url (if present) == payment_required.resource.url
- K5 (S) validAfter < validBefore; the window length is reported against accepted.maxTimeoutSeconds, not judged
  (the spec does not state the relation for EIP-3009)

Settlement (x402-specification-v2 5.3.2):
- T1 (D–D) settlement.success is true and settlement.transaction is a 32-byte hex hash
- T2 (D–D) settlement.network == accepted.network; settlement.payer (if present) == authorization.from;
  settlement.amount (if present) == accepted.amount

Chain evidence (offline over the supplied objects; the RPC answer is data, not trusted):
- C1 (S–chain) chain_tx.tx.to == accepted.asset and its input is `transferWithAuthorization` whose arguments equal the
  authorization and whose signature equals payload.signature (v,r,s or bytes form)
- C2 chain_tx.tx.hash == settlement.transaction; the log is `AuthorizationUsed(from, nonce)` from the asset with the
  same transaction hash and, when both carry them (always in apc-0.2), the same `blockHash` and `blockNumber` as the
  transaction (`failed:log_block_not_tx_block`); for an EIP-1559 transaction (type 0x2) the hash is recomputed as keccak256(0x02 || rlp([chainId,
  nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList, yParity, r, s])) and must equal
  `tx.hash`, and `tx.chainId` must equal the network's chain id. Other transaction types: C2
  `not_evaluated:tx_type_<t>_hash_not_recomputed`. Measured: 34/34 real hashes recomputed. What C2 does not show: that
  the transaction is in a block of the canonical chain (no block header or receipt proof in 0.1).

Calldata tail (both versions). After the ABI arguments of a direct call the verifier accepts exactly one of: nothing;
an ERC-8021 Schema 2 suffix (x402 builder_code.md); an ERC-8021 Schema 0 suffix `[codes][codesLength 1 byte][0x00]
[marker]`, codes 7-bit ASCII (ERC-8021 is a DRAFT, ethereum/ERCs PR #1209 @ 457532f, text in `sources/`). Each is
reported, not interpreted. Any other tail: C1 `not_evaluated:unrecognized_trailing_calldata`. Measured: of the 1210 direct
calls among 2449 real authorizations, 1 (Base, block 52035616+) carries a Schema 0 suffix (code "bc_o3dj3qk8"), 1065 a
Schema 2 suffix and 144 none; the calldata tail of the 1239 indirect calls is the caller's and is not classified.

Indirect calls (apc-0.2). x402 facilitators other than the direct `transferWithAuthorization` caller settle through
their own contract, a batcher or an ERC-4337 EntryPoint; the calldata then has no common layout. In apc-0.2, when
`tx.to` is not the asset, C1 is `not_applicable:indirect_call` (in apc-0.1 it stays `failed:tx_not_to_asset`) and C2 is
evaluated as for a direct call. Such a bundle can be `chain_verified` only if C3 is `verified`.
- C3 (S–chain, by the token's own logs) `log_transfer` is from the asset, topic `Transfer(address,address,uint256)`,
  topics[1] == authorization.from, topics[2] == authorization.to, data == authorization.value as one 32-byte word;
  same `transactionHash` as `tx.hash` and same `blockHash` and `blockNumber` as `log_authorization_used`; and its `logIndex` is the
  `logIndex` of `log_authorization_used` plus one, the order in which the USDC implementation emits the two events
  (sources above). A Transfer at any other index: `not_evaluated:log_transfer_not_next` (another implementation
  may order its events otherwise; this is not read as a failure). Without `log_transfer`: on a direct call
  `not_evaluated:absent:no_log_transfer`, on an indirect call `not_evaluated:indirect_call_needs_log_transfer`.
  What C3 shows: the token executed an authorization of (from, nonce) that moved `value` from `from` to `to`. Since one
  (from, nonce) can be executed once, and L2.sig shows the payload's signature covers this to and value for that
  (from, nonce), the executed terms are the payload's except possibly the validity window. What C3 does not show
  that C1 does: that the signature bytes in the transaction are the payload's.
  Measured (Base, blocks 52942756-52942805): 120 of 120 AuthorizationUsed logs are followed at logIndex + 1 by a
  Transfer from the same payer; on the 38 direct calls, to, value and nonce equal the calldata in 38 of 38; paired at
  logIndex - 1, + 2 or + 3 instead, 0 of 38.

Forwarding by the payee (apc-0.2). Some facilitators name their own contract as `payTo` and pass the payment on in
the same transaction, less a fee (measured on Base: Meridian 0x8e7769d4, payer to contract 15062538, contract to
seller 14911913). x402 judges the payment at `payTo`, so the verdict does too; F1 only reports what happened next.
- F1 (chain, report only) `log_forward` needs `log_transfer` (else `failed:log_forward_without_log_transfer`); it is
  from the asset, topic Transfer, same `transactionHash`, `blockHash` and `blockNumber` as `log_transfer`, `logIndex` one more than
  `log_transfer`'s, and topics[1] == authorization.to; each mismatch is `failed:log_forward_<what>`, since the bundle
  then carries a log that is not what it claims. When `verified`, a note gives the receiver (topics[2]), the amount
  forwarded and `value` minus it (or says that more than `value` was forwarded). Absent: `not_evaluated:absent:no_log_forward`. F1 never makes a verdict
  `chain_verified` that would not be one without it. What F1 does not show: that no other transfer of the payee,
  later in the transaction or in another one, moved the remainder.

Acceptance (work-acceptance 1.4.1 `payment`, signed by the receipt issuer):
- A1 (S–S) payment.protocol == "x402", scheme == "exact", network == accepted.network, asset == accepted.asset,
  payer == authorization.from, pay_to == authorization.to, amount == authorization.value, nonce == authorization.nonce
- A2 settlement_tx == settlement.transaction. The member is optional in the profile, and the profile says
  "(network, asset, payer, nonce) names one settlement", which A1 already checks; so without it A2 is
  `not_evaluated:absent:no_settlement_tx` and does not block (as the optional members of T2). Without `settlement`
  in the bundle: `not_evaluated:absent:no_settlement`
- A3 the receipt verdict itself comes from war-verify; A1-A2 never change it (the profile makes `payment`
  outcome-neutral). Without a `payment` member: `not_evaluated:no_payment_member`.

Mandate (AP2 v0.2):
- M1 `not_evaluated:ap2_has_no_x402_binding` — the AP2 text pinned above has no token, chain or merchant address
  field, so no link from mandate to payment can be checked from the specification. An explicit profile for a
  currency-to-token mapping may come in a later version, named as ours and never reported as AP2.

## 5. Verdict
A check whose artifact the bundle does not carry is `not_evaluated:absent:<what>` and is listed under `absent`; it
does not block. `chain_verified` only if L2.sig, K1, K2, K3 are `verified`, C3 is `verified` whenever C1 is
`not_applicable:indirect_call`, no check is `failed`, and no check of an
artifact the bundle DOES carry is `not_evaluated` (so a bundle with a mandate is at best `chain_incomplete` in 0.1,
M1). Any `failed` gives `chain_failed` with the list; otherwise `chain_incomplete`. The verdict covers only the
artifacts present: the report lists the absent ones next to it. Whenever chain_tx is present the report
also notes that the transaction and logs are RPC data supplied with the bundle and, without `inclusion` (0.3), that no
inclusion proof is checked; with `inclusion` it notes what B1-B3 bind and that canonicality is not decided by B (with `canonical`: shown only by
O1-O4, from the L1 replies the bundle carries).
Exit codes 0 / 1 / 2; 3 for a bundle outside the grammar, unsupported, or a file that cannot be read (also one that is
not a regular file, or larger than 64 MiB: 0.3.1); 64 usage (an option outside the grammar; since 0.21.2 also the signature
library `APC_SIGLIB` names, or its sibling default, absent, and since 0.21.3 not the two files of tag v1.4.0 at their hashes:
one line on standard error, no report, 32.11 and 32.12 (f)); 74 the report
could not be written (0.18.3, section 29.3).
The verdict does not say how much evidence stands behind it: from 0.19 the report member `evidence_level` does
(from 0.19.1: none < signature < settlement_record < inclusion_proof < finality_proven, section 30), in every bundle
version, the facilitator's reply apart in `facilitator_reply` (verified, failed, absent or not_evaluated; 30.1), and
`--require-level LEVEL` turns a `chain_verified` below LEVEL into `chain_incomplete` (exit 2; section 30.3).

## 6. SPEC 0.3 (draft, 2026-10-22, local) — additions; an apc-0.3 bundle is an apc-0.2 bundle plus what follows

Motivation, not a rule source: arXiv 2607.19545 (USENIX Security 2026) tested 15 x402 facilitators and lists eight
security rules for facilitators (SR1-SR8) and four attack classes (free shopping, asset theft, service denial, gas
abuse). Sections B, D, K6 and the ERC-6492 rule check, AFTER the fact and from evidence, the parts of those classes
that leave a trace a bundle can carry. Service denial and gas abuse leave none in a bundle and are not checked.

Grammar: `bundle_version` "apc-0.3"; one more optional member `inclusion` (only with `chain_tx`; refused in 0.1/0.2):
```
inclusion: { block_header: {header fields, closed list below, plus "hash"}, transaction_index: quantity,
             tx_proof: [hex node, 1..64], receipt_proof: [hex node, 1..64] }
```
Header fields, in this order: parentHash, sha3Uncles, miner, stateRoot, transactionsRoot, receiptsRoot, logsBloom,
difficulty, number, gasLimit, gasUsed, timestamp, extraData, mixHash, nonce, then a PREFIX (no gap) of
baseFeePerGas, withdrawalsRoot, blobGasUsed, excessBlobGas, parentBeaconBlockRoot, requestsHash. Anything else refused.
`hash` is a required string. A quantity (header number, gas, timestamp, `transaction_index`…) is a JSON-RPC quantity:
0x, lower-case ASCII hex, no leading zero, at most 256 bits; hex data (hashes, roots, proof nodes) is 0x and pairs of
ASCII hex digits, nothing else (no sign, `_`, space or non-ASCII digit). `chain_tx.tx` (hash, blockHash, blockNumber,
transactionIndex) and `log_authorization_used` (blockHash, transactionIndex) must carry string members for B1, even
when C1 stopped before reading them; otherwise refused.

- B1 keccak256(rlp(header)) equals `block_header.hash`, `chain_tx.tx.blockHash` and the AuthorizationUsed log's
  blockHash; `block_header.number` equals `chain_tx.tx.blockNumber`; `transaction_index` equals the transaction's
  and the log's `transactionIndex`.
- B2 `tx_proof` is a Merkle-Patricia path in the transactions trie under `transactionsRoot` for key
  rlp(transaction_index); the value it proves hashes (keccak256) to `chain_tx.tx.hash` — which C2 has already tied to
  the transaction's fields and to the settlement's `transaction`.
- B3 `receipt_proof`, same key, under `receiptsRoot`: the proven receipt (EIP-2718 typed or legacy) has status 1,
  holds the bundle's AuthorizationUsed log exactly once (address, topics, data byte-equal), and, when the bundle
  carries `log_transfer`, the very next log of the receipt is that Transfer, byte-equal.
- B4 the block's timestamp t satisfies validAfter < t < validBefore (Circle EIP3009.sol 319-323, `now > validAfter`,
  `now < validBefore`).
- E1 (report only, never decisive) every other Transfer of the asset out of the payer in the same receipt is listed
  (fee splits, several payments settled in one transaction). The payment's own Transfer is told apart only through
  `log_transfer`: without it, every Transfer of the asset out of the payer is listed, the payment's own among them.
- Without `inclusion`: B1-B4 `not_evaluated:absent:no_inclusion` (listed, non-blocking as in 5).
- The report carries `block_bound`: true only when B1-B4 are all `verified`. It binds the payment to a block HASH. It
  does NOT show that this block is on the canonical chain: that hash has to be checked elsewhere (independent
  providers, an L1 output root). The report says so.

- ERC-6492 (Final, ethereum/ERCs 8dd085d, pinned in sources/erc6492_8dd085d): a signature that ends in the 32 magic
  bytes 0x6492…6492 is recognized BEFORE the ERC-1271 and ecrecover paths, as that ERC requires; L2.sig is
  `not_evaluated:erc6492_counterfactual_signature`, never verified, and the report names the risk (the facilitator has
  to run factory calldata chosen by the payer).
- K6 the authorization value is greater than zero, else `failed:zero_amount`. The two x402 c2a8924 files pinned in
  sources/x402_spec_c2a8924 (x402-specification-v2.md, scheme_exact_evm.md) say nothing about a zero amount (a search
  for "zero" finds no rule); other files of that repository were not read for this. This is our rule.

Set checks (apc_batch.py), over the bundles given together; a bundle refused alone is listed and left out:
- D1 one authorization (network, asset, payer, nonce) in two bundles that name different deliveries (resource URL, or
  acceptance receipt) → `failed:same_payment_for_two_deliveries`; verdict `set_failed`.
- D2 the same authorization in several bundles with the same delivery → listed as `duplicate_bundle`, not a failure.

Canonical chain (Base mainnet only), optional member `canonical` (only with `inclusion`):
```
canonical: { l1_network: "eip155:1", game: address, root_index: integer >= 0,
             l1_replies: [8 eth_call replies, in this order, all at ONE L1 block],
             headers: [0..64 L2 headers, from the root's block down to the block right after the bundle's block] }
```
Each header is the same closed object as `inclusion.block_header`. This grammar is checked on every network, before
the Base-only rules. A status reply outside GameStatus (0, 1, 2), or isGameClaimValid true next to a reply that
contradicts it (not proper, not respected, or status other than DEFENDER_WINS; AnchorStateRegistry.sol 307-329), is
refused.
Sources: Base L1 addresses from docs.base.org (DisputeGameFactory 0x43edB88C4B80fDD2AdFF2412A7BebF9dF42cB40e,
AnchorStateRegistry 0x909f6cf47ed12f010A796527f562bFc26C7F4E72, read 2026-10-23); game type 621 = AggregateVerifier,
base/contracts eaa7729 (MIT), pinned in sources/base_contracts_eaa7729; output root = keccak256(bytes32(0) ‖ stateRoot ‖
withdrawal_storage_root ‖ block hash) (ethereum-optimism/specs 21d1ff5, proposals.md; pinned in
sources/optimism_specs_21d1ff5). The replies, in order: game.gameType(),
game.rootClaim(), game.extraData(), game.startingBlockNumber(), game.status(), then registry.isGameProper(game),
isGameRespected(game), isGameClaimValid(game).
- O1 game type 621; extraData = l2SequenceNumber (32) ‖ parent (20) ‖ intermediate roots (32 each)
  (AggregateVerifier.sol extraData()); the last intermediate root equals rootClaim; startingBlockNumber < l2SequenceNumber
  and the range divides by the number of roots (k blocks per root).
- O2 the bundle's block n is in (startingBlockNumber, l2SequenceNumber]; the first header is block
  m = start + (root_index+1)·k, the first root block at or after n (m − n < k); the hash of every header, and of
  `inclusion.block_header`, recomputes (`failed:header_hash_mismatch`, named before the parent links), and parentHash links each header to
  the next one down to `inclusion.block_header` (`failed:header_chain_broken`).
- O3 the output root of block m, with withdrawal_storage_root = the header's withdrawalsRoot (after Isthmus the
  header's withdrawalsRoot is the L2ToL1MessagePasser storage root: isthmus/exec-engine.md 55-59, pinned; measured:
  the recomputed root equals the game's root for all 19 real bundles of bundles/real_v03_canonical, 6 games), equals
  intermediate root `root_index`.
- O4 `failed:game_challenger_wins` when status is CHALLENGER_WINS (1); `not_evaluated:game_not_proper_or_not_respected`
  when isGameProper or isGameRespected is false (isGameProper is also false for a retired game and while the system is
  paused, AnchorStateRegistry.sol 262-284, and the eight calls do not tell these apart from a blacklisting: the
  bundle is then `chain_incomplete`, not `chain_failed`); `verified` when isGameClaimValid is true and status is DEFENDER_WINS (2)
  (AnchorStateRegistry.sol 307-329: proper, respected, finalized, DEFENDER_WINS); otherwise
  `pending:game_not_final` — a `pending:` result neither fails nor blocks the verdict.
- The report carries `canonical`: `final` (block_bound and O1-O4 verified), `proposed` (block_bound, O1-O3 verified, O4
  pending), `failed`, or `not_shown`. A bundle on another network: O1-O4 `not_evaluated:canonical_rules_only_for_base_mainnet`.
- What stays declared: the L1 answers are RPC replies carried by the bundle, not proven by an L1 state proof. The same
  eight calls can be asked again at that L1 block of a node that still holds its state; for an older block that means
  an archive node (measured 2026-10-23 on a block about 1,600 blocks old: two public endpoints refused it as an archive
  request, a third answered and matched all 152 replies of the 19 bundles). The L1 block is the one the bundle names:
  a blacklisting or retirement of the game after that block is not seen.

Amendment 0.3.1 (2026-10-23, every bundle version; verifier apc_verify 0.3.1): a log of `chain_tx`
(log_authorization_used, log_transfer, log_forward) whose `removed` member is true (Ethereum JSON-RPC: the log was
dropped by a chain reorganization) gives `failed:<log>_removed` in C2, C3 or F1, whichever of them is evaluated (when C1
stops, C2 and C3 are `not_evaluated:after_C1`); a `removed` that is not a JSON boolean is refused, in every branch. Until
0.3 the member was not read and such a bundle could be `chain_verified` (tests/test_removed.py). `canonical` reports the
block only: next to a removed log it can still be `final` while the verdict is `chain_failed`.
The `params[0]` of each `canonical.l1_replies` entry is an object with exactly `to` (an address as in section 4) and
`data` (hex data), compared with the call O1 names with case ignored; until 0.3 an upper-case `to` or `data` was
refused.
Every JSON-RPC quantity the verifier reads (chain_tx, payer_wallet, the block of the canonical replies) is held to the
256 bits of the grammar above; until 0.3 a longer one was read (an L1 block of 2^320 left `canonical` final).
B3 reads the bundle's two logs as bytes: their address, topics and data must be hex of their size (as in section 4 and
the hex data of this section), else the bundle is refused; until 0.3 a `data` such as "Zx" was read as empty.
Set check D3 (apc_batch.py): one authorization in two bundles whose settlements (T1 verified) name different
transactions → `failed:same_authorization_two_settlements`, verdict `set_failed` (one (from, nonce) executes once,
section 4 C3); until 0.3 such a set was `set_consistent` with a D2 duplicate.

Amendment 0.3.2 (2026-10-24, every bundle version; verifier apc_verify 0.3.2): EIP-3009 does not require a low s, but
the token decides. A 65-byte `payload.signature` whose s is greater than n/2 (n the secp256k1 order) gives in L2.sig:
- for an asset in the measured list, `failed:high_s_refused_by_token`. List: USDC on Base, `eip155:8453`
  0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 (FiatTokenProxy, implementation 0x2ce6311ddae708829bc0784c967b7d77d19fd779
  on 2026-10-24), and USDC on Base Sepolia, `eip155:84532` 0x036cbd53842c5426634e7929541ec2318f3dcf7e. Circle stablecoin-evm fc85788 `contracts/util/ECRecover.sol` 51-56 reverts on such an s, and for a
  payer without code `SignatureChecker.isValidSignatureNow` (38-47) goes through it. Measured 2026-10-24 on two public
  endpoints (Base Sepolia: one) by eth_call of transferWithAuthorization (value 0, a throwaway key; the script first
  checks the EIP-712 domain against the token's DOMAIN_SEPARATOR()): the low-s signature returns, the same signature with
  s replaced by n - s and v flipped reverts "ECRecover: invalid signature 's' value" (`tools/probe_lows_usdc.py`);
- for any other asset, `not_evaluated:high_s_token_rule_not_measured`.
What this says and what it does not: the signature AS CARRIED is refused by the token when the payer has no code (a
65-byte L2.sig assumes that, as before; a payer with code, a contract wallet or an EOA with an EIP-7702 delegation, goes
through ERC-1271 and this check is not reached). When chain_tx shows the token accepted that very signature (C1
verified: the transaction carries it; C2 verified: the token logged AuthorizationUsed), the payer had code at that block
or the token was not the measured implementation: L2.sig (and K3) is then
`not_evaluated:high_s_accepted_on_chain`, not failed. Its low-s twin (s' = n - s, v flipped) is a valid encoding of the same
authorization that anyone can compute and the token accepts, so a settler that normalises s can still execute the
payment; the report says so in its note. Until 0.3.1 such a signature was `verified` with a note, so a bundle could
carry a verified L2.sig for a signature that the token refuses as carried (tests/test_high_s.py: the 182 real bundles of
the corpus, of 192, that carry a 65-byte signature, each with its signature turned high-s). The upper-half s and its recovery to `authorization.from` stay in the
report.
Second part of 0.3.2 (every bundle version): `settlement.success` that is not a JSON boolean is refused (x402 v2
5.3.2: boolean, required). A settlement reply with `success` false, next to a `chain_tx` that shows this authorization
executed (C1 and C2 verified, and C3 verified or absent from apc-0.2 on; for an indirect call C2 and C3 verified), gives
T1 `failed:settlement_reported_failed_but_executed_on_chain` and a note: the payer was charged, if that transaction is
on the canonical chain (chain_tx is RPC data carried by the bundle, SPEC C2; B and O in apc-0.3). A reply with
`errorReason` `settlement_pending` (x402 v2 section 9, x402 PR #3083 merged 2026-08-17: non-terminal, the broadcast
transaction may still confirm, and the reply MUST carry its hash) does not say the payment failed: T1 is
`not_evaluated:settlement_pending`, `not_evaluated:settlement_pending_executed_on_chain` when chain_tx shows it
executed, and `failed:settlement_pending_without_transaction_hash` when `transaction` is not a 32-byte hash.
When the failed reply names a transaction (a 32-byte hash), the note says whether it is the one chain_tx carries or
another one (the preemption pattern of arXiv 2605.11781 I-B: someone else submitted the authorization first). For a reply other than settlement_pending the
verdict stays `chain_failed`: the reply is wrong about the chain. Until 0.3.1 such a bundle gave only
`failed:settlement_not_successful`, which reads as "not paid". Real case: x402-foundation/x402 issue #1062, the
facilitator answered `settle_exact_node_failure` for transaction 0x8e01aace…e696 that Base executed in block 41551053
(bundles/real_issue1062; tests/test_failed_but_executed.py). The reply quoted in the issue has `errorMessage`
(sent by the x402 SDKs, not a member of SettlementResponse in x402 v2 5.3.2, so refused by the closed grammar) and no
`success`; the bundle carries `success` false and leaves `errorMessage` out. The issue was closed on 2026-09-21, after
x402 added `settlement_pending` for this case.
Third part of 0.3.2: in a `payer_wallet` reply, every string of `params` (and every member value of an `eth_call`
object) is "0x" followed by hex digits, else the bundle is refused; the digits compare with case ignored. Until 0.3.1 the
whole string was lower-cased before the comparison, so "0X…" (not JSON-RPC hex) matched, and a member value that was not
a string was compared as its text.
Fourth part of 0.3.2: K6 (section 6) applies to every bundle version; until 0.3.1 an apc-0.1 or apc-0.2 bundle with
value 0 had no K6 and could be chain_verified (arXiv 2607.19545 SR5: 14 of the 15 facilitators it tested let a
zero-value settlement through).

Amendment 0.3.3 (2026-10-24; verifier apc_verify 0.3.3). Three parts.
Part 1, reverted settlements (apc-0.3 with `inclusion`): `chain_tx.log_authorization_used` (with `log_transfer` and
`log_forward`) may be absent, because a reverted transaction emits no logs and a bundle about one could not be written
before. C2 is then evaluated on the transaction alone (hash recomputed, equal to the settlement's transaction, chainId,
`from`) and ends `not_evaluated:no_log_authorization_used`. B3 decides from the proven receipt: status 0 →
`failed:receipt_status_not_success` and, when B1, B2 and C1 hold and the recomputed hash equals `tx.hash` (so the fields
C1 read are the proven transaction), the report member `reverted` is true with a note: the authorization was not
executed by this transaction and the payer was not charged by it. A settlement reply with `success` true that names
this transaction gives T1 `failed:settlement_reported_success_but_reverted` (arXiv 2607.19545 SR4).
Status 1 without the log is refused: a successful EIP-3009 execution emits AuthorizationUsed (Circle EIP3009.sol fc85788: the transfer and the
receive paths, lines 143 and 223, both call `_markAuthorizationAsUsed`, lines 332-337, which emits it; the v, r, s
variants forward to them, lines 84-104 and 161-181). `log_transfer` or `log_forward` without
`log_authorization_used` is refused; without `inclusion` the log stays required. Real case: Base block 53020172,
transaction 0x860ba697…9226, status 0 (bundles/real_reverted; tests/test_reverted.py).
Part 2, payer equal to payee (every bundle version): report member `payer_is_payee` (true when
`authorization.from` equals `accepted.payTo`) with a note. Reported, not decisive: the transfer is a real execution;
whether it counts as a payment is the reader's policy. Address-level only. Real case: v004 in bundles/real_v03 and
real_v03_canonical (tests/test_self_payment.py).
Part 3, who sent the settlement: the sender of an EIP-1559 settlement transaction is recovered from its own signature
(yParity, r, s over keccak256(0x02 || rlp([chainId .. accessList])); an s above n/2 is not recovered, EIP-2). In every
bundle version a `chain_tx.tx.from` that is not that signer fails C2 (`failed:tx_from_not_its_signer`; until 0.3.2 the
member was not read). In apc-0.3 the report member `settled_by` gives the recovered sender (null for another
transaction type or when C2 does not hold), and an optional member
`facilitator: {"signers": [1..256 addresses], "source": <string>, "fetched": "YYYY-MM-DDTHH:MM:SSZ"}` (declared data,
e.g. a facilitator's /supported signers) gives F2: `verified` when `settled_by` is in the list,
`failed:settled_by_not_a_facilitator_signer` with a note otherwise (someone else submitted the authorization, the
preemption pattern of arXiv 2605.11781 I-B, or the list is out of date), `not_evaluated:absent:no_facilitator`
without it. Measured with the x402scan list pinned in sources/x402scan_5732bb8: of the 39 real apc-0.3 bundles, 27
senders are listed and 12 are not (tests/test_sender.py).

Amendment 0.4 (2026-10-24; verifier apc_verify 0.7.0, apc_l1proof.py) — L1 state proof of the eight replies. An apc-0.3
`canonical` may carry `l1_state`:
```
l1_state: { "headers": [1..8192 L1 headers, from the checkpoint block down to the block of l1_replies],
            "accounts": [1..32 { "address", "accountProof": [1..64 hex nodes],
                                 "storageProof": [0..64 { "key": 32-byte hex slot, "proof": [0..64 hex nodes] }] }],
            "game_code": hex }
```
Closed: an unknown member or a second proof of one account or slot is refused; with `--l1-checkpoint`, so is a proof
the eight replies do not read (without a checkpoint the proofs are not walked, so which ones are read is not known and
the member is checked only for its grammar). No value is carried beside its proof: eth_getProof's `value`, `balance`,
`nonce` are left out. The reader gives the
hash of an L1 block it trusts (`--l1-checkpoint`); the verifier never fetches it. Check L1:
- the first header hashes to the checkpoint, each next one is the parent of the previous (number one less), every
  header's `hash` member is its recomputed hash (`failed:l1_header_hash_mismatch`), and the last one is the block of
  `l1_replies` (`failed:l1_last_header_not_the_replies_block`);
- account proofs under the last header's stateRoot (key keccak256(address)), storage proofs under the account's
  storageRoot (key keccak256(slot); an absent key is zero), the game's code under its codeHash (eth_getProof paths,
  secure trie; a proof that does not hold is `failed:l1_state:<reason>`);
- the eight replies recomputed from those values equal `l1_replies` byte for byte (`failed:l1_reply_not_proven:<name>`):
  1 gameType and 3 extraData's layout from the game implementation pinned by codeHash; 2 rootClaim and 3 extraData
  from the clone's immutable arguments (Solady LibClone CWIA: args [20,52) and [0x54, 0x54 + 0x34 + 32 × roots));
  4 startingBlockNumber, game slot 2; 5 status, game slot 0 byte 16; 7 isGameRespected, game slot 0 byte 18;
  6 isGameProper: registered (DisputeGameFactory slot-103 mapping at keccak256(abi.encode(type, rootClaim, extraData))
  names the game, and the implementation's registry is the Base registry), not blacklisted (registry slot-5 mapping),
  createdAt above retirementTimestamp (registry slot 6 bytes 4..12), not paused (SuperchainConfig slot-0 mapping, for
  address 0 and for the portal, each active while timestamp < t + 7 884 000); 8 isGameClaimValid: proper, respected,
  resolvedAt ≠ 0, status 1 or 2, timestamp − resolvedAt above the finality delay (pinned 0), and status 2;
- proxies: the proxy's codeHash and the implementation's (EIP-1967 slot) are in the pinned table of apc_l1proof.py
  (measured 2026-10-24 on two L1 RPCs: same header hash, codeHash and storageHash for the 10 accounts); another code is
  `not_evaluated:l1_<role>_not_pinned` (an upgrade is never read blindly).
`not_evaluated:absent:no_l1_state` without the member, `not_evaluated:absent:no_l1_checkpoint` without a checkpoint
(listed, not blocking, as section 5). Report member `l1_state`: `proven` (L1 verified), `failed`, or `not_shown` (the
replies stay declared, as in 0.3). Real data: the 8 payments of bundles/real_v03_canonical in game 0x7a3a…, with the
replies and proofs at L1 block 26259631 (bundles/real_v04_l1state): proven, canonical final; and the proofs of a
game in progress, 0x8710… at L1 block 26259645, whose eight recomputed replies equal eth_call (tests/test_l1state.py).
Citation corrected on the way: O4's AnchorStateRegistry lines are of base/contracts eaa7729 (4.0.0); the deployed
registry is 3.7.0 (version(), 2026-10-24), whose validity functions are the same (diff affa48e2..eaa7729: only the
superchainConfig() getter removed).

## 7. SPEC 0.5 (draft, 2026-10-24, local) — Solana: the x402 `exact` scheme on SVM, bundle `apc-0.5`
Source: x402 `specs/schemes/exact/scheme_exact_svm.md` at x402-foundation/x402@4241d56 (sources/x402_4241d56), cited
below as SVM §n. EVM bundles stay apc-0.1 to apc-0.3; an apc-0.5 bundle is about one Solana payment. Code: apc_svm.py
on the primitives of apc_solana.py (base58, the transaction wire format, Ed25519 verification of RFC 8032 5.1.7,
program-derived addresses), standard library only.

Bundle (closed at every level; any other member is refused with its path):
```
{ "bundle_version": "apc-0.5",
  "payment_payload": { "x402Version": 2, "accepted": REQ, "payload": {"transaction": BASE64}, "resource"?, "extensions"? },
  "payment_required"?: { "x402Version": 2, "resource": {...}, "accepts": [...], "error"?, "extensions"? },
  "settlement"?: { "success": bool, "transaction": BASE58 signature, "network", "payer"?, "errorReason"?, "amount"?,
                   "extensions"? },
  "chain_tx"?: { "slot": uint, "blockTime": uint or null, "transaction": BASE64,
                 "meta": { "err", "fee": uint, "preTokenBalances": [...], "postTokenBalances": [...],
                           "innerInstructions": [...], "loadedAddresses": {"writable": [...], "readonly": [...]} } } }
REQ = { "scheme": "exact", "network": "solana:<32 base58 characters>", "amount": decimal u64, "asset": mint,
        "payTo": address, "maxTimeoutSeconds": int,
        "extra": { "feePayer": address, "memo"?: string of at most 256 UTF-8 bytes, "recentBlockhash"?: hash,
                   "lastValidBlockHeight"?: decimal string } }
```
Addresses and hashes are canonical base58 of 32 bytes; BASE64 is RFC 4648 with padding and no other character. Another
`extra` member is reported in a note, not interpreted (as for EVM). `chain_tx` is the RPC's `getTransaction` reply
(encoding base64): DECLARED data. Solana block headers carry no transaction or receipt trie, so no member of this
bundle binds the transaction to a block: the report member `block_bound` is false for every apc-0.5 bundle and a note
says so.

Checks (each `verified`, `failed:<reason>`, `not_evaluated:<reason>`, as in section 5):
- S1 the payload transaction parses (at most 1232 bytes, legacy or v0 message, minimal shortvec lengths of at most
  0xFFFF, indices in range, no trailing bytes; else the bundle is refused; PACKET_DATA_SIZE and ShortU16 as
  anza-xyz/solana-sdk @6437e43 packet/src/lib.rs and short-vec/src/lib.rs, copies in sources/solana_sdk_20261025); account 0 (the fee payer of a Solana transaction) equals `extra.feePayer`
  (`failed:fee_payer_not_account_0`); every required signer other than account 0 signed the message with Ed25519
  (`failed:signer_<i>_signature_invalid`); the fee payer's slot is 64 zero bytes (the partially signed transaction of
  SVM step 4) or its valid signature.
- S2 exactly one `TransferChecked` (spl-token or token-2022, instruction 12) matches: mint = `asset`, destination = the
  associated token account of (`payTo`, that token program, `asset`), amount ≥ `accepted.amount` (SVM §1.1, §1.4).
  Top-level instructions are read from the payload; inner instructions only from `chain_tx.meta.innerInstructions`.
  Zero matches with only known programs (ComputeBudget, the two token programs, Memo, Lighthouse) at top level:
  `failed:no_matching_transfer`; zero matches with another program and no `chain_tx`: `not_evaluated:
  transfer_may_be_inside_a_program_call` (a smart wallet, SVM §3.2, needs the CPI trace); more than one:
  `failed:more_than_one_matching_transfer`. An amount above the requirement is noted (tolerated, SVM §1.4).
- S3 fee payer isolation (SVM §2.1.1, §2.1.2): account 0 is in no instruction's accounts, top-level or inner, and is no
  instruction's program; with address lookup tables, `not_evaluated:lookup_tables_not_resolved` unless `chain_tx.meta.
  loadedAddresses` gives them; the fee payer is never the authority of a transfer.
- S4 signer set (SVM §2.1.4): at most two required signers (`failed:more_than_two_required_signers`).
- S5 memo (SVM §3.1): with `extra.memo`, exactly one top-level Memo instruction whose data is `extra.memo` in UTF-8
  (`failed:memo_count_<n>` / `failed:memo_mismatch`); without it, a transaction with no Memo is noted (the MUST of
  §3.1 binds the client, and whether a payload was x402 v1 or v2 is not in the transaction).
- S6 cost (SVM §2.2.1, SHOULD: notes, never a failure): ComputeBudget instructions other than 2 and 3, a unit limit above
  400 000, a unit price above 50 000 micro-lamports, and the fee bound 5 000 × signatures + ceil(price × limit / 10^6).
- K4 as section 4 (`accepted` offered in `payment_required.accepts`, resource url).
- T1 the settlement reply: `success` true (`failed:settlement_not_successful`; `settlement_pending` is
  `not_evaluated:settlement_pending`, as Amendment 0.3.2); `network` equal to `accepted.network`; `transaction`
  base58 of 64 bytes; `payer`, when given, an address equal to the fee payer (SVM SettlementResponse) or to the
  authority of the matching transfer (x402 v2 5.3.2), else `failed:settlement_payer_mismatch`; `amount`, when given, a
  decimal u64 equal to the matching transfer's amount, else `failed:settlement_amount_mismatch` (not compared, with a
  note, without a single matching transfer); `errorReason` a string and `extensions` an object, else refused.
- C1 `chain_tx.transaction` carries the payload's message bytes and the payload's signatures except the fee payer's, and
  the fee payer's signature in it is valid (`failed:chain_tx_not_the_payload`, `failed:fee_payer_signature_invalid`).
- C2 the transaction id (its first signature, base58) equals `settlement.transaction`
  (`failed:settlement_names_another_transaction`); `meta.err` null, else `failed:transaction_error` and, with a success
  reply, T1 `failed:settlement_reported_success_but_failed` (arXiv 2607.19545 SR4).
- C3 from the declared balances: the destination account's `postTokenBalances` minus `preTokenBalances` amount, same
  mint, is at least `accepted.amount` (`failed:balance_delta_short`).
- Verdict as section 5 (S1-S5 are each verified, failed or not evaluated, so the failed and the not evaluated checks
  decide). Report members: `payer` (the authority of the matching
  transfer, null without one), `fee_payer`, `transaction_id` (C2's id when `chain_tx` is given), `block_bound` false.
Real data (bundles/real_svm, tests/test_svm.py): of 52 transactions signed by the fee payers x402scan@5732bb8 lists for
8 facilitators (fetched 2026-10-24), 45 have the listed fee payer as account 0 and a top-level TransferChecked and are
rebuilt as bundles (the payload is the confirmed transaction with the fee payer's signature set to zeros; the other 7
are listed in the manifest as skipped). 43 are chain_verified; in 2 the fee payer is the only signer and the authority
of the transfer, so they are not a client payment sponsored by the fee payer, and S3 fails on them. Plus one payment
made for this work on mainnet on 2026-10-24 (slot 460849863, extra.memo set): chain_verified.

## 8. SPEC 0.6 (draft, 2026-10-25, local) — report tools (apc_report.py), offline, standard library only
These read apc_verify's report (or a bundle) and change no verdict.
- Canonical report: RFC 8785 (JCS) for the values a report holds (objects with ASCII member names, strings, integers
  below 2^53 in magnitude, booleans, null): members sorted, no whitespace, UTF-8. Anything else (a float, a non-ASCII
  name, an integer at or above 2^53, which JCS would write as an IEEE 754 double) is refused, not written another way.
- Signed report: `{"apc_signed_report": 1, "report", "public_key": 64 lowercase hex, "key_id": the first 16 hex digits
  of SHA-256(public_key), "signature": 128 lowercase hex}`, closed; the signature is Ed25519 (RFC 8032 5.1.6, checked
  against its 7.1 test vectors 1-3) over "apc-report-v1\n" followed by the canonical report (domain separation: it
  signs nothing else). Verification: `verified`, `failed:key_id_not_the_key`, `failed:signed_by_another_key` (when the
  reader names the expected key), `failed:signature_invalid`. The seed is read from a file and never printed; no key
  validity window is defined (open).
- SARIF 2.1.0 log of a set of bundles: one result per failed check (level error) and per not evaluated check (level
  warning), absent artifacts are not results; a refused bundle is one `bundle` error. Rule ids are the check names.
- Merkle root of a set of reports: RFC 6962 2.1 (leaf SHA-256(0x00 ‖ canonical report), node SHA-256(0x01 ‖ left ‖
  right), split at the largest power of two below n), checked against certificate-transparency's reference roots of
  1 to 8 leaves. Publishing or anchoring a root is an outward action, not done by the tool.
- Policy (reader's rules, closed grammar): `{"apc_policy": 1, "networks"?, "assets"?, "pay_to"?: [distinct strings],
  "max_amount"?: {asset: decimal}, "hosts"?: [host names]}`. P1 network listed, P2 asset listed, P3 amount at most the
  asset's cap (`failed:asset_without_a_cap` when the asset has none), P4 payTo listed, P5 the resource URL's host listed
  (case ignored) — each `verified`, `failed:<reason>` or `not_evaluated:absent:no_rule`. EVM addresses compare with
  case ignored, base58 exactly. Report members `policy` and `policy_verdict` (`policy_met` / `policy_failed`); the
  verdict of the bundle is unchanged.
- Provenance (G6; apc-0.3 and apc-0.5 bundles): optional member `provenance: {"chain_tx"?, "settlement"?: {"source":
  1..256 characters, "fetched": "YYYY-MM-DDTHH:MM:SSZ"}}`, closed, naming only members the bundle carries: who supplied
  the chain data and the settlement reply, and when. DECLARED: echoed in the report member `provenance` with a note,
  no check reads it, no verdict changes.
- MCP (apc_mcp.py): a local tool server, JSON-RPC 2.0 over stdio (MCP revisions 2025-06-18, 2025-03-26, 2024-11-05),
  read-only: `verify_bundle {bundle_json, l1_checkpoint?}` returns apc_verify's report, `apply_policy {policy_json,
  bundle_json}` the report with P1-P5. The bundle is JSON text read by the strict parser; arguments of the wrong shape
  are protocol errors (-32602), a refused bundle is a report with isError true, and an unexpected error is -32603 (the
server keeps reading). Lines are read as bytes: a line that is not UTF-8 or not JSON is a parse error (-32700),
whatever the locale.
Tests: tests/test_report.py, tests/test_provenance.py, tests/test_mcp.py (the server on its real stdio transport),
on the real bundles of bundles/real_v03, real_v04_l1state and the Solana payment of this work.

## 9. SPEC 0.7 (draft, 2026-10-25, local) — AP2 Payment Mandate bound to the x402 payment (M1; census G1)
apc_ap2.py is an independent offline evaluator of the Pulse AP2-x402 conformance profile (shibutatsu/pulse-ap2-x402-
conformance, fixture format ap2-x402-conformance/0.3, read at e06a6cbf, Apache-2.0): written in Python from the
profile's documents and TypeScript sources read at that commit; their code is not run. It checks the one-hop AP2 Open ->
closed Payment Mandate chain (SD-JWT disclosures resolved and each used once, ES256 signatures under the supplied
P-256 keys, the terminal kb+sd-jwt with sd_hash, audience, nonce and times), the signed AP2 Payment Receipt, the
profile's closed schema, RFC 8785 claims hashes, every signed constraint, and the binding of the AP2 x402 instrument
extension to the x402 requirements, the EIP-3009 authorization (nonce = the 32 bytes of base64url(SHA-256(leaf JWT)),
low-s signature with v 27/28 recovering `from`, validity inside the timeout, the 6-second buffer and the mandates'
expiry) and the settlement reply. Failure codes and their order are the profile's. A date-time is the profile's
(zod 4.4.3 `z.string().datetime({ offset: true })`: calendar dates, hour 00-23, seconds optional, any number of
fraction digits) and is read as `Date.parse` reads it, in milliseconds (the fraction cut after 3 digits), without
datetime.fromisoformat; measured 2026-10-26 against zod 4.4.3 and Date.parse of node 22.23.2 on 31 040 strings: the same
decision and value on all but the 21 whose fraction has 10 or more digits starting with 0, which that Date.parse reads
otherwise (.0566272289 as 566 ms). ES256 is ECDSA P-256 written here
(FIPS 186-5), checked against RFC 6979 A.2.5. Measured: on the 80 cases of fixtures/v0.3 (SHA-256 8f40be1b…4ee0; the
corpus is not redistributed: APC_PULSE_CASES names it), the computed decision and failure codes equal the recorded
expectation in 80 of 80, without reading it (tests/test_ap2.py also inverts the expectation and gets the same result).
What the profile itself does not claim stays unclaimed: the AP2 keys are the ones the case supplies (not production
trust anchors), and the receipt's transaction id equals the settlement's by field agreement, not by a chain proof (an
apc bundle gives that with C/B/O).
M1 in a bundle (every bundle version): `mandate: {"profile": "pulse-ap2-x402/0.3", "case": <a Pulse 0.3 case>}`,
closed. M1 `verified` when the case is consistent and its x402 payload equals the bundle's `payment_payload` (RFC 8785
equality); `failed:ap2_<first failure code>` when the case is not consistent; `failed:mandate_binds_another_payment`
when it binds another payload; a case outside the profile's grammar is refused. Another `mandate` object keeps
`not_evaluated:ap2_has_no_x402_binding`. Measured on the 20 consistent cases: M1 verified and, independently, apc's own
L2.sig verified on each payload.

## 10. SPEC 0.8 (draft, 2026-10-25, local) — the HTTP exchange that carried the payment (X1-X7; census G2, G10)
Sources (copies and sha256 in sources/http_20261025): x402 `specs/transports-v2/http.md` at 0aee759 (the
PAYMENT-REQUIRED, PAYMENT-SIGNATURE and PAYMENT-RESPONSE headers, each base64-encoded JSON; "Success | 200", failures
402, 400 or 500), RFC 9421 (HTTP Message Signatures), RFC 9530 (Digest Fields), RFC 9651 (Structured Field Values).
Code: apc_http.py, standard library only. The x402 header examples of http.md and the RFC 9421 Appendix B.2.4 and
B.2.6 signatures and RFC 9530 digests are test oracles.

An apc-0.3 or apc-0.5 bundle may carry `exchange`, the HTTP request that carried the payment and the response to it,
as a client or a server recorded them:
```
exchange: { "request":  { "method": token, "target_uri": "http://..." | "https://...",
                          "fields": [1..256 [name, value]], "body"?: base64 },
            "response"?: { "status": 100..599, "fields": [0..256 [name, value]], "body"?: base64 } }
```
Closed at every level. `name` is an HTTP field name (RFC 9110 token), `value` a field value of visible ASCII, space
and tab without leading or trailing whitespace (RFC 9110 5.5; no obs-fold, no CR or LF); one array entry per field
line, in message order. `body` is standard base64 with padding (RFC 4648 4), at most 8 MiB decoded: the message
content as transferred, after any content coding (RFC 9530 digests cover these bytes). `target_uri` has no fragment
and no user information. Anything else is refused with its path.

DECLARED: the exchange is a recording. X1-X6 show that the recording agrees with the payment the bundle verifies;
they do not show that the exchange happened. Only X7, an RFC 9421 signature under a key the reader trusts, binds
the covered parts of a message to that key.

Field values are read by name with case ignored; a field that occurs on several lines is combined with ", " (RFC
9421 2.1). Checks (each `verified`, `failed:<reason>` or `not_evaluated:<reason>`):
- X1 the request carries the payment: exactly one PAYMENT-SIGNATURE field line, whose value is standard base64 of
  UTF-8 strict JSON equal (RFC 8785) to the bundle's `payment_payload`. `failed:request_without_payment_signature`,
  `failed:payment_signature_repeated`, `failed:payment_signature_not_base64`, `failed:payment_signature_not_json`,
  `failed:request_carries_another_payment`.
- X2 the request is for the paid resource: `target_uri` equals `payment_payload.resource.url`, else
  `payment_required.resource.url` (exact string, as K4); `not_evaluated:absent:no_resource_url` when neither is
  carried. `failed:request_not_for_the_resource`.
- X3 the response carries the settlement: with `response`, exactly one PAYMENT-RESPONSE field line, standard base64
  of strict JSON equal (RFC 8785) to the bundle's `settlement`. `failed:response_without_payment_response` when the
  bundle has a settlement and the response no PAYMENT-RESPONSE; `failed:settlement_not_in_bundle` when the response
  has one and the bundle no settlement; `failed:payment_response_repeated`, `failed:payment_response_not_base64`,
  `failed:payment_response_not_json`, `failed:response_carries_another_settlement`; `not_evaluated:absent:no_response`,
  `not_evaluated:absent:no_payment_response` (neither carries one).
- X4 the status agrees with the settlement: settlement `success` true and status 2xx, or `success` false and a status
  outside 2xx (http.md maps success to 200 and the failures to 402, 400, 500; 2xx is required, not 200, and the
  status is reported). `failed:status_contradicts_settlement`; `not_evaluated:absent:no_settlement` without one.
- X5q / X5r the request / response content agrees with its Content-Digest (RFC 9530 2): the field is a Structured
  Field Dictionary (RFC 9651) whose `sha-256` and `sha-512` members, Byte Sequences, equal the digest of `body`
  (`body` absent = zero bytes only when the message says Content-Length: 0, otherwise `not_evaluated:absent:no_body`).
  Other algorithms are ignored with a note (RFC 9530 2: "A recipient MAY ignore any or all digests"); none of the two
  = `not_evaluated:no_supported_digest`. `failed:content_digest_mismatch`, `failed:content_digest_malformed`;
  `not_evaluated:absent:no_content_digest`. The SHA-256 of every carried body is reported (`request_body_sha256`,
  `response_body_sha256`) whether or not a digest field is present.
- X6 (G10) the response has the declared media type: the response Content-Type, compared on type and subtype with
  case ignored and parameters left out (RFC 9110 8.3.1), equals `resource.mimeType` of the payment payload, else of
  `payment_required`. `failed:content_type_not_the_declared_mime_type`; `not_evaluated:absent:no_mime_type`,
  `not_evaluated:absent:no_content_type`, `not_evaluated:absent:no_response`. The mimeType is the server's
  declaration (the EIP-3009 signature does not cover it): X6 says the response is what the 402 announced, not that
  its content is right.
- X7 RFC 9421 signatures, for each label of a Signature-Input field of the request or the response, only when the
  reader supplies keys (`http_keys`, below; otherwise `not_evaluated:absent:no_http_keys` for each): the label has one
  Signature member (RFC 9421 3.2 step 1.2), the signature base is rebuilt (2.5) and verified under the key named by
  `keyid` with the key's algorithm (3.2 step 6; an `alg` parameter naming another algorithm fails). Algorithms:
  `ed25519` (3.3.6) and `ecdsa-p256-sha256` (3.3.4); others `not_evaluated:algorithm_not_supported`. Components: the
  derived @method, @target-uri, @authority, @scheme, @request-target, @path, @query, @status, and fields without
  parameters; the `req` parameter on a response signature reads the request of the exchange. Other parameters (sf,
  key, bs, tr) and @query-param: `not_evaluated:component_not_supported:<identifier>`. `failed:signature_invalid`,
  `failed:unknown_keyid`, `failed:alg_not_the_key_algorithm`, `failed:signature_input_malformed`,
  `failed:signature_missing`, `failed:component_not_in_message:<identifier>`; a label of a Signature field with no
  Signature-Input is an entry of its own, `failed:signature_without_input` (3.2 step 1.2). Reported per label: where (request or
  response), keyid, algorithm, the covered components, created and expires (not compared with any clock), and the
  result. No coverage is required; the report shows what each signature covers. X7 itself: the first `failed` of
  the labels (request labels first, then response, each in field order), else the first `not_evaluated`, else
  `verified`; `not_evaluated:absent:no_signature` when neither message has a Signature-Input or a Signature field.

`http_keys` (the reader's trust, like --l1-checkpoint; never read from the bundle):
`{"apc_http_keys": 1, "keys": {keyid: {"alg": "ed25519" | "ecdsa-p256-sha256", "public_key": hex}}}`, closed; an
Ed25519 key is 32 bytes, a P-256 key 65 bytes (0x04 || x || y) on the curve.

Report member `exchange` of an apc-0.3 or apc-0.5 bundle: null without one (as `provenance`), else {status,
request_body_sha256, response_body_sha256, signatures}. X1-X7 enter `failed` / `not_evaluated` like every check; an
absent exchange adds none of them (the null member says it is absent).

## 11. SPEC 0.9.1 (draft, 2026-10-26, local) — register of checks on an external device (apc_registry.py, apc-reg-0.2)
An append-only register, kept on a device the user names (a USB drive, an SD card), of the checks apc_verify made:
the report, when (UTC first), where (from a GPS), in which zone, state or province and on which local day, with
summer or standard time. Code: apc_registry.py, Python 3.9+ standard library (zoneinfo; Ed25519 of apc_solana.py);
the `openssl` binary only for the opt-in RFC 3161 token. Owner's decisions of 2026-10-24: the place is always recorded
from the GPS of a connected device; the zone, the UTC offset, summer or standard time and the version of the tz
database are recorded; the same instant is shown in other zones.
0.9.1 replaces 0.9 (format apc-reg-0.1, used only by the tests of the day it was written): an apc-reg-0.1 entry is
refused (`not apc-reg-0.2`). Added in 0.9.1: gpsd JSON input, apc_verify run by the register on the bundle, the
admin-1 region, the opt-in RFC 3161 `timestamp` entry.

### 11.1 Personal data and consent; what leaves the machine
The place of a check is personal data of the person who checks (GDPR art. 4(1): location data). Nothing is recorded
by default: `init REGISTER` opens a register with an `open` entry whose `consent` is "place_recorded_as_personal_data",
and `record` refuses (exit 3) a path where no register was opened. apc_verify never records by itself. The register
stays on the user's device. Nothing leaves the machine unless the user gives `--tsa URL`: then the SHA-256 of the
check entry, and nothing else, is sent to that time-stamping authority (an RFC 3161 request carries the digest, a
nonce and certReq). The gpsd socket is read on 127.0.0.1 only.

### 11.2 Entry (closed at every level: any other member, a missing member or a wrong type is damage)
Each line is the canonical form (section 8) of one entry followed by "\n":
```
{"apc_register": "apc-reg-0.2", "seq": n (0, 1, 2 ... in order), "prev": hash of entry n-1 ("0"*64 for n = 0),
 "kind": "open" | "check" | "timestamp" | "torn_tail" | "seal", "body": ...,
 "hash": SHA-256 of the canonical entry without hash}
open      (seq 0 and only there): {"created_clock_utc": T, "consent": "place_recorded_as_personal_data", "tool": str}
torn_tail {"dropped_bytes": 1..2^22, "dropped_sha256": hex64, "found_clock_utc": T}
seal      {"from_seq", "to_seq", "head", "public_key": hex64, "key_id": hex16, "signature": hex128}
timestamp (right after a check and only there; 11.6)
          {"of_seq": the check's seq, "of_hash": the check's hash, "tsa_url": http(s) URL, "token_b64": the
           TimeStampResp DER in canonical base64, "gen_time_utc": T (the token's genTime), "trust": "freetsa_pinned" |
           "user_ca" | "system_store", "ca_sha256": hex64 of the CA file used, "openssl": `openssl version`}
check     {"tool": str,
           "proven":   {"report": apc_verify's report (carried), "report_sha256": SHA-256 of its canonical form,
                        "verdict": the report's verdict, "bundle_sha256": hex64 | null,
                        "rerun": null | {"verifier": the report's verifier, "options": {"l1_checkpoint": 0x hex64 |
                                 null, "http_keys_sha256": hex64 | null}, "report_sha256", "verdict"},
                        "block_time": null | {"utc": T, "block_bound": the report's block_bound is true}},
           "declared": {"clock_utc": T, "device_zone": zone | null, "gps": GPS, "place": PLACE, "region": REGION,
                        "local": LOCAL | null},
           "tz":       {"tzdata_version": "2026e"-like | "unknown", "zone_file_sha256": hex64 | null,
                        "boundaries": null | DATASET}}
GPS   = {"status": "no_source"}
      | {"status": "no_fix", "format", "source", "source_sha256", "counts", "reason": str}
      | {"status": "fix", "format", "source", "source_sha256", "counts", "fix_record", "aux_record": str | null,
         "lat", "lon": degrees, decimal strings with 7 decimals, "time_utc": T, "fix_mode", "fix_quality",
         "satellites": 0..99 | null, "hdop": "d[.ddd]" | null, "clock_minus_gps_seconds": int}
  format "nmea0183": source "file" | "serial"; fix_record the RMC sentence, aux_record the GGA one;
                     fix_mode A|D|P|R|F|null (RMC mode); fix_quality 1..5|null (GGA quality);
                     counts {"lines", "rmc", "gga", "bad_checksum", "unusable", "other"}
  format "gpsd_json": source "file" | "socket"; fix_record the TPV object (a JSON text of class TPV), aux_record the
                     SKY one; fix_mode "2"|"3" (TPV mode); fix_quality "1"|"2"|"3"|"4"|"6"|"9"|null (TPV status);
                     counts {"lines", "tpv", "sky", "unusable", "other"}
PLACE = {"status": "not_established", "reason": str}                        (exactly when GPS is not a fix)
      | {"status": "established" | "at_sea" | "ambiguous" | "no_zone_in_file" | "no_boundary_file", "zone",
         "zone_basis": "boundary" (established) | "ocean_polygon" (at_sea) | "longitude_derived" (the others),
         "candidates": [zones] (two or more exactly when ambiguous), "country": ISO 3166 alpha-2 | null,
         "country_basis": "zone.tab" | null}
REGION = {"status": "not_established", "reason": str}                       (exactly when GPS is not a fix)
       | {"status": "no_admin_file"}
       | {"status": "established" (1 area) | "none" (0) | "ambiguous" (2..8), "areas": [AREA] in adm1_code order,
          "dataset": DATASET}
AREA  = {"adm1_code": Natural Earth's code, "iso_3166_2": "CC-XXX" | null, "name": str | null, "region": str | null,
         "country": ISO 3166 alpha-2 | null}      (text: 1..128 characters, no control characters)
DATASET = {"release", "source_sha256", "file_sha256", "pinned": release, source and file are the pinned ones}
LOCAL = {"zone": the place's zone, "at_clock": VIEW, "at_gps": VIEW}
VIEW  = {"local_time": "YYYY-MM-DDTHH:MM:SS+HH:MM", "local_day": its date, "utc_offset": its offset,
         "dst_seconds": zoneinfo dst(), "time_kind": "summer_time" (dst > 0) | "standard_time" (0) |
         "negative_dst" (< 0), "abbreviation"}
T = "YYYY-MM-DDTHH:MM:SS[.ffffff]Z" (no fraction or exactly 6 digits)
```
Consistency read with the grammar: report_sha256 and verdict are the report's; rerun exactly with a bundle, and its
report_sha256, verdict and verifier are the recorded report's; block_time needs a bundle; local exactly when the place
is not `not_established`; tz.boundaries exactly when a boundary file was read; a VIEW's day and offset are those of
its local_time and its time_kind the one its dst_seconds names; a timestamp's token parses (11.6), is granted, stamps
of_hash with SHA-256 and says gen_time_utc; trust freetsa_pinned only with the pinned root's ca_sha256.
`negative_dst`: tzdata writes Europe/Dublin (winter, GMT) and Africa/Casablanca (Ramadan) with a negative DST
(measured with zoneinfo and tzdata 2026e: Dublin 2026-01-15 dst -1 h): there the law calls the summer offset
standard time, so a "dst != 0 means summer time" rule would be wrong; the record keeps the number and names the case.

### 11.3 Register file
Append-only. A write is one line, then flush and fsync (and the directory is fsynced when the register is created);
`init` never writes over an existing file; a writer takes an exclusive POSIX lock (where the system has none, one
writer at a time is the user's duty). A record writes its entries (torn_tail, check, timestamp, seal) only after all
of them are built and checked: a refusal at any step, the time-stamping authority included, writes nothing.
Reading (verify, show, and record before it writes):
- every complete line must be the canonical form of an entry of 11.2, in chain (seq, prev, hash), else damage;
- a last piece without its "\n" is a torn line (a write a stop interrupted; "\n" is the commit of a line): verify
  reports it (exit 2), and record truncates it and appends a `torn_tail` entry with its length and SHA-256 before the
  check, so the drop is itself in the chain. Any other damage is a refusal (exit 1) and record writes nothing;
- a seal covers the entries from the one after the previous seal (or 0) to the one before it: head is the hash of
  the entry before it; the signature is Ed25519 (RFC 8032) over "apc-register-seal-v1\n" followed by the canonical
  {"from_seq", "to_seq", "head", "public_key"}; key_id the first 16 hex digits of SHA-256(public key). `verify
  --public-key HEX` also requires every seal to be by that key. record seals when it is given a seed file (--key).
Limit (open): removing whole lines at the end leaves a shorter valid register; only a head kept elsewhere (the
`head` that record, verify and show print), a later seal by a key the reader trusts, or a later RFC 3161 token
shows it.

### 11.4 GPS input
NMEA 0183, from a file (--nmea) or a serial device (--gps, raw mode at 9600 baud unless --baud, up to --seconds).
Read: `$GPRMC`/`$GNRMC` (11, 12 or 13 fields: NMEA 2.0, 2.3 mode, 4.1 navigation status) and `$GPGGA`/`$GNGGA` (14
fields), each with its checksum checked (XOR of the characters between "$" and "*", two upper-case hex digits); a
sentence with a wrong checksum is counted and not read. Other lines are counted (`other`). The fix is the LAST RMC
with status A and a mode, when present, of A, D, P, R or F (E estimated, M manual, S simulator and N are not a
measured fix); if a GGA with the same time field exists, its quality must be 1..5 and its place the RMC's, else no fix.
Coordinates: ddmm.mmmm / dddmm.mmmm with N/S/E/W, converted exactly to degrees with 7 decimals (half-even).
Time: RMC time and date (yy < 80 is 20yy, else 19yy).
gpsd JSON (gpsd_json(5), page of 2026-10-23), from a file (--gpsd-json; one object per line, other lines counted) or
from the gpsd daemon on 127.0.0.1:PORT (--gpsd, `?WATCH={"enable":true,"json":true}`, up to --seconds). Read: objects
of class TPV and SKY. The fix is the LAST TPV with mode 2 or 3 (0 unknown and 1 no fix are not), a status, when
present, of 1, 2, 3, 4, 6 or 9 (5 dead reckoning, 7 time only and 8 simulated are not a measured fix; status is an
integer 0..9, mode 0..3, else the object is unusable), a time "YYYY-MM-DDTHH:MM:SS[.f]Z" and lat and lon numbers in
range, converted to 7 decimals (half-even, from the number's shortest decimal form). The SKY is the one whose time is
the TPV's, else the last one before it; satellites = its uSat, else the count of its satellites with used true; hdop
its hdop. gpsd_json(5) gives no rule for members it does not list (it says the POLL inventory "should not" be assumed
fixed): only the members named here are read; the TPV and SKY lines are carried whole in fix_record and aux_record.
Both formats: a leap second (second 60) is unusable: UTC is taken without leap seconds. No fix = `gps.status` no_fix
with the reason and `place` and `region` not_established: never a default place. A GPS time is a second clock,
independent of the device clock; `clock_minus_gps_seconds` shows how far the two are (for a capture file it is the
age of the capture). The GPS time is DECLARED: gpsd's regression output of the neo-m8n capture says 2034-11-01 where
its RMC says 2015-03-18 (sources/gpsd_json_20261026), the date depending on the decoder.

### 11.5 Zone, country, region, tz database
The zone from the coordinates needs a boundary map (zoneinfo has the rules, not the boundaries). The map is
timezone-boundary-builder (evansiroky), release 2026e (2026-10-11), asset `timezones-with-oceans.geojson.zip`,
56,087,412 bytes, SHA-256 8eefcbc3df102dc3c174983b784bde82fec00fb4a596a1ed63e8f53a92043885 (the digest GitHub
publishes), ODbL-1.0: it is not put in this repository. tools/fetch_tz_boundaries.py downloads it, checks that
digest and converts it, deterministically, to a line file (184,521,818 bytes, SHA-256
3cfc18cd8a81027591c3a6175f3b6eaec17cdc3deed2d378eaaa09ffcd12e029, the same on two conversions on 2026-10-26):
a canonical header, then per zone "min_lon min_lat max_lon max_lat TAB tzid TAB polygons", coordinates unchanged.
The registry reads that file from the path the user gives (--tzdb), hashes it, and parses polygons only where the
bounding box holds the point; `pinned` says whether release, source and file are the pinned ones.
Point in polygon: even-odd rule on the outer ring minus its holes. One zone = established (an `Etc/` zone of the
ocean polygons = at_sea); none = no_zone_in_file; two or more = ambiguous with the candidates; without --tzdb =
no_boundary_file. In the last three the zone is derived from the longitude (Etc/GMT band of 15 degrees, Etc/GMT-N
is UTC+N), marked longitude_derived: it is not a civil zone.
Country: the zone's country code in zone.tab of the tzdata zoneinfo reads, only for a zone from a boundary: it is the
country of the zone, not a political boundary (Europe/Rome also covers SM and VA in zone1970.tab).
Region (state, province; --admin): Natural Earth 1:10m admin-1 states and provinces, release v5.1.2 (tag commit
f1890d9f152c896d250a77557a5751a93d494776 of nvkelso/natural-earth-vector), `geojson/ne_10m_admin_1_states_provinces.
geojson`, 40,726,851 bytes, SHA-256 22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5 (its git blob
id 4a8438f98ac7dfec7dc1739b1eaf91398ad33f22 is the one GitHub lists for that path at that tag), public domain, not
put in this repository. tools/fetch_admin_boundaries.py converts it to a line file (29,536,654 bytes, SHA-256
3a4a329d5d023d3e86f463e4bdc590148929ef63ec4da0e3ab5406a91653a629, the same on two conversions): a canonical header,
then per area "bbox TAB adm1_code TAB {iso_3166_2, name, region, country, polygons}". iso_3166_2 is kept only in the
ISO 3166-2 form (Natural Earth also writes its own placeholders such as "SY-X01~", and 60 codes appear more than
once); its admin-1 level is the one Natural Earth chose per country (for Italy the provinces, with the region
named in `region`). Natural Earth is cartographic: de facto boundaries from its own point of view, not a legal source.
tzdata_version: the "# version" line of tzdata.zi in the TZPATH directory holding the zone's file (else the tzdata
package's IANA_VERSION, else "unknown"), with the SHA-256 of the zone file read: the rules change by law and an old
tzdata is wrong without saying so. A zone the boundary file names but this tzdata lacks is a refusal (update tzdata).

### 11.6 PROVEN and DECLARED
PROVEN (anyone can check it again):
- the report: with --bundle the register runs apc_verify itself on the bundle (with the --l1-checkpoint and
  --http-keys given, as `apc_verify.py BUNDLE` prints it: a refused or unsupported bundle gives that report) and
  records that report, with `rerun` naming the verifier and the options; a --report given as well must be the same
  canonical report, else nothing is recorded. Without --bundle the report is only the file given (rerun null);
- the block time, the bundle's inclusion.block_header.timestamp, proven when the report's block_bound is true;
- the hash chain, a seal's signature (the device's key);
- the time of the check, with `--tsa URL` only (opt-in, off by default): an RFC 3161 token on the check entry's hash
  (`openssl ts -query -sha256 -cert`, posted as application/timestamp-query). Before anything is written the reply
  must parse as a TimeStampResp (status granted or grantedWithMods; SignedData with a TSTInfo; SHA-256 imprint equal
  to the entry hash; genTime) and `openssl ts -verify -digest HASH -CAfile CA -attime genTime` must say OK, where CA
  is, for freetsa.org, the FreeTSA root given by --tsa-ca and pinned by the SHA-256 of its PEM file
  2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438 (https://freetsa.org/files/cacert.pem,
  2026-10-26), else --tsa-ca (user_ca) or the system trust store (system_store). It proves the check entry existed at
  genTime: the check was made NOT AFTER gen_time_utc (show prints it as check_time_proven_not_after). `verify` checks
  every token by the grammar (stdlib) and runs openssl again on those it can (the CA file of --tsa-ca when its SHA-256
  is the recorded one; the system store for system_store tokens); a token that fails is damage.
DECLARED (the device says so; nothing in the register proves it): the clock, the device zone, the GPS input (a GPS
can be spoofed, a file can be any capture), and what is derived from it: place, zone, region, local day, summer or
standard time.

### 11.7 Commands and exit codes
`init REGISTER` (0 opened, 3 refused); `record REGISTER (--bundle B [--l1-checkpoint H] [--http-keys K] [--report R]
| --report R) [--nmea F | --gps DEV [--baud N] [--seconds S] | --gpsd-json F | --gpsd PORT [--seconds S]] [--tzdb F]
[--admin F] [--key SEED] [--tsa URL [--tsa-ca CA]]` (0 recorded, 1 register damaged, 3 input refused, the
time-stamping authority's failure included; nothing written on 1 or 3); `verify REGISTER [--public-key HEX] [--tsa-ca
CA]` (0 intact, 1 damaged, 2 torn last line not yet recorded, 3 not readable); `show REGISTER [--zones Z1,Z2,... |
all]` (0; the checks with the proven not-after time when stamped and, for the GPS instant when there is a fix, else
the clock, the time in each zone by the tzdata of the reader now; default Europe/Rome, America/New_York,
America/Sao_Paulo, Africa/Lagos, Asia/Shanghai, Asia/Kolkata, Australia/Sydney, Pacific/Auckland). 64 usage. A refusal
is one JSON line {"error": reason}; an unforeseen error is a refusal naming its type, never a traceback.
Tests: tests/test_registry.py, on the real captures of sources/nmea_20261026 and sources/gpsd_json_20261026, the real
bundles, a local openssl TSA on 127.0.0.1 (no real authority is called), and generated cases.

## 12. SPEC 0.10 (draft, 2026-10-26, local) — x402 `exact` on EVM by Permit2 or ERC-7710, bundle `apc-0.10`
Sources (copies and sha256 in sources/x402_4241d56_permit2_20261026, sources/permit2_cc56ad0_20261026,
sources/ercs_7710_7579_20261026): x402-foundation/x402 @ 4241d56 `specs/schemes/exact/scheme_exact_evm.md` (sections 2
Permit2 and 3 ERC-7710; byte-identical to the c2a8924 copy of 22/10), `specs/extensions/eip2612_gas_sponsoring.md`,
`contracts/evm/src/x402ExactPermit2Proxy.sol` and `x402BasePermit2Proxy.sol`; Uniswap/permit2 @ cc56ad0 `EIP712.sol`,
`SignatureTransfer.sol`, `libraries/PermitHash.sol`, `libraries/SignatureVerification.sol`; ethereum/ERCs @ 4891ba3
`erc-7710.md` (Draft) and `erc-7579.md` (Draft). Measured on Base 2026-10-26 (oracle/permit2_base_20261026): the proxy
at 0x402085c248eea27d92e8b30b2c58ed07f9e20001 returns PERMIT2() = 0x000000000022d473030f116ddee9f6b43ac78ba3 and
WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter)"); Permit2's DOMAIN_SEPARATOR() on chain 8453
equals the one computed below.

### 12.1 Grammar (closed at every level, as section 1)
```
{ "bundle_version": "apc-0.10",
  "payment_payload":  <x402 v2 PaymentPayload, below>,      required
  "payment_required": <as section 1>,                        optional
  "settlement":       <as section 1>,                        optional
  "chain_tx":         {"network", "tx", "log_transfer", "log_settled"}  permit2; {"network", "tx", "log_transfer"}
                      erc7710; every member required,        optional
  "mandate":          <as section 9>, "exchange": <as section 10>, "provenance": <as section 8 G6>   optional
  "payer_code": <12.5>, "erc1271_call": <12.6> (permit2 only), "inclusion", "canonical", "acceptance": <12.7>  optional }
accepted: {scheme "exact", network eip155, amount, asset, payTo, maxTimeoutSeconds, extra}; extra is required and its
  assetTransferMethod is "permit2" or "erc7710" (absent or "eip3009": refused, such a payment is an apc-0.1..0.3
  bundle; any other value: unsupported); name and version, when present, non-empty strings; other members of extra
  are noted, not interpreted (extra is scheme-specific, as in section 1).
payload, permit2:  {signature, permit2Authorization: {permitted: {token, amount}, from, spender, nonce, deadline,
                    witness: {to, validAfter}}}    (scheme_exact_evm.md 2, Phase 2)
payload, erc7710:  {delegationManager, permissionContext, delegator}   (scheme_exact_evm.md 3, Phase 2)
```
Addresses and amounts as section 4; nonce, deadline and validAfter are decimal uint256 under the same rule (digits
bounded before any conversion); signature and permissionContext are non-empty even-length hex. The logs carry string
address, topics (each 32 bytes of hex), data, transactionHash, blockHash, blockNumber, logIndex; `chain_tx.tx` carries
string to, input, hash, blockHash, blockNumber. Anything else refused with its path. In apc-0.1 to apc-0.3 bundles a
`payment_required.accepts` entry with assetTransferMethod permit2 or erc7710 is now read by this grammar (until 0.10 it
made the bundle unsupported, so an EIP-3009 payment offered both methods could not be verified).

### 12.2 Permit2 checks
- L2.sig (S). The digest Permit2 checks in permitWitnessTransferFrom, rebuilt from constants of the sources, never
  from the input: domain keccak256(keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)") ||
  keccak256("Permit2") || chainId of accepted.network || Permit2 0x000000000022d473030f116ddee9f6b43ac78ba3) (3
  members, no version: EIP712.sol); type hash keccak256(STUB || WITNESS_TYPE_STRING), STUB =
  "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline," (PermitHash.sol),
  WITNESS_TYPE_STRING = "Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256
  validAfter)" (x402ExactPermit2Proxy.sol); struct hash over (TokenPermissions hash of token and amount, spender,
  nonce, deadline, keccak256(WITNESS_TYPEHASH, to, validAfter)). Signature as SignatureVerification.sol for a payer
  without code: 65 bytes r||s||v with v 27 or 28 (other v: `failed:v_not_27_or_28`, ecrecover returns zero), or 64
  bytes EIP-2098 r||vs; no low-s rule (ecrecover; an upper-half s is noted, not refused); the recovered address
  must be `from` (`failed:recovers_<address>_not_from`). Any other length: `not_evaluated:unsupported_signature_length_<n>`
  (Permit2 then asks the payer by ERC-1271: 12.5, 12.6); an ERC-6492 suffix:
  `not_evaluated:erc6492_counterfactual_signature`. As for EIP-3009, a 65-byte check assumes the payer had no code;
  when it had (an EIP-7702 delegation), Permit2 asked the delegated code, and the recovery shows the address's own
  key signed.
- K1 (S–D) witness.to == accepted.payTo; K2 (S–D) permitted.amount == accepted.amount (exact: the proxy transfers
  permitted.amount, x402ExactPermit2Proxy.settle; scheme_exact.md line 39); K3 (S–D) permitted.token == accepted.asset
  (`failed:permitted_token_not_asset`) and the chainId by L2.sig; K5 (S) validAfter <= deadline, else
  `failed:empty_validity_window` (the proxy requires block.timestamp >= validAfter, Permit2 block.timestamp <=
  deadline; the length is reported against maxTimeoutSeconds); K6 permitted.amount > 0 (the proxy reverts
  InvalidAmount); K7 (S) spender == the canonical x402ExactPermit2Proxy 0x402085c248eea27d92e8b30b2c58ed07f9e20001
  (`failed:spender_not_x402_exact_permit2_proxy`): the spender is msg.sender in the signed hash, and the proxy is what
  enforces witness.to (scheme_exact_evm.md "Important Logic"). K4, T1, T2 as section 4 (T2: payer == from).
- C1 (S–chain) `tx.to` is the proxy and its input is `settle` (selector of
  settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)) or `settleWithPermit` (the
  EIP-2612 permit tuple first), strict ABI: address words zero-padded, v word < 256, signature offset canonical (0x100;
  0x1a0), length and zero padding; the calldata tail as section 4; the arguments equal the payload
  (`failed:tx_arguments_differ_from_authorization`) and the signature bytes equal payload.signature. Other selector:
  `failed:tx_not_settle`. The EIP-2612 permit of settleWithPermit is the approval only (eip2612_gas_sponsoring.md); it
  is reported, its signature not checked. `tx.to` not the proxy: `not_applicable:indirect_call`, and the verdict then
  needs C3 verified.
- C2 the transaction hash recomputed, equal to settlement.transaction, chainId, sender (as section 4); `log_settled`
  from the proxy, one topic Settled() for settle or SettledWithPermit() for settleWithPermit (either for an indirect
  call), empty data, same transactionHash, blockHash, blockNumber as the transaction; `removed` as 0.3.1. Permit2
  emits no event of its own for a signature transfer (SignatureTransfer.sol), so this proxy event and the token's
  Transfer are the chain evidence.
- C3 `log_transfer` from the asset, Transfer(from, witness.to, permitted.amount), same transaction and block; its
  logIndex is log_settled's minus one (the proxy emits after Permit2's transferFrom), else
  `not_evaluated:log_transfer_not_next`. Measured on the 231 real settlements: 231 of 231.
Verdict: `chain_verified` only if L2.sig, K1, K2, K3, K7 are verified, C3 too on an indirect call, nothing failed and
nothing present not evaluated (section 5). A settlement reported failed or pending while C1-C3 show the transfer:
T1 as Amendment 0.3.2.

### 12.3 ERC-7710 checks
x402 defines the payload (delegationManager, permissionContext, delegator) and the settlement call
`redeemDelegations([permissionContext], [mode], [executionCallData])`, executionCallData an ERC-20 `transfer(payTo,
amount)`, mode "typically 0x00..." (ERC-7579 single call). It also says the permissionContext is opaque and that
verification "is performed entirely through simulation", with no trusted list of Delegation Managers. So:
- L2.sig, K1, K2, K3 `not_evaluated:erc7710_permission_context_opaque`: nothing in the payload is a signature this
  verifier can check offline, and an apc-0.10 erc7710 bundle is at best `chain_incomplete`. K6 accepted.amount > 0.
- C1 `tx.to` == delegationManager and the input is redeemDelegations(bytes[],bytes32[],bytes[]) in the canonical ABI
  encoding (re-encoded and compared byte for byte: `failed:tx_calldata_not_canonical_abi`; unreadable:
  `failed:tx_not_redeemDelegations_abi`), one delegation (`failed:tx_not_one_delegation_redeemed`), the
  permissionContext equal to the payload's; mode callType 0x00 (else `not_evaluated:erc7579_call_type_<xx>_not_single`),
  execType 0x00 or 0x01 and the other 30 bytes zero (else `not_evaluated:erc7579_mode_not_default`); executionCallData
  = ERC-7579 single call abi.encodePacked(target, value, callData) of exactly 120 bytes: target == asset, value 0,
  callData = transfer(payTo, amount) (`failed:execution_not_a_transfer_call`, `_target_not_asset`,
  `_sends_native_value`, `_address_word_not_padded`, `_to_not_payTo`, `_amount_not_amount`). Indirect call as 12.2.
- C2 the transaction alone, as 12.2 without log_settled. C3 `log_transfer` from the asset, Transfer(delegator, payTo,
  amount), same transaction and block (no position rule: the Delegation Manager's own events are not defined by x402).
  T2 payer == delegator.
What C1-C3 show for erc7710: the asset moved amount from the delegator to payTo in a transaction redeeming this
permissionContext at that manager; not that the delegator authorized it (that is the manager's and the account's
logic, not evaluated). Measured 2026-10-26: no x402 reference implementation of erc7710 in x402 @ 4241d56 (no code
file names it); on Base, 200 of the 14218 transactions that emitted logs of the MetaMask DelegationManager
0xdb9b1e94b5b69df7e401ddbede43491141047db3 in blocks 52902222-53102221 sampled: 0 of the 188 direct calls to the manager has
the x402 shape (one delegation, single call, transfer), so the erc7710 vectors are built here.

### 12.5 Payers with code (Permit2; apc_verify 0.10.0)
Permit2 asks a payer that has code by ERC-1271 (SignatureVerification.sol), and an account with an EIP-7702 delegation
has code: 0xef0100 || the delegate's address. One optional bundle member says what that code is, in one of two forms:
```
payer_code: {"rpc":   {"code": <rpc eth_getCode [from, B]>, "storage"?: <rpc eth_getStorageAt [from, KERNEL_SLOT, B]>}}
          | {"proof": {"code": hex, "parent_header": <header, as section 6>,
                       "at_parent": {"payer": {"accountProof": [hex], "storageProof"?: [hex]}, "delegate"?: {"accountProof": [hex]}},
                       "at_block":  <the same>}}
```
Closed; exactly one form; permit2 only (refused next to an erc7710 payload). `rpc`: B is the transaction's block when
chain_tx is carried (`failed:payer_code_block_not_tx_block`); the method and params of each reply are checked before
its result is read (as payer_wallet, section 3); DECLARED chain state. `proof`: needs `inclusion` with B1 verified
(else `not_evaluated:payer_code_proof_needs_inclusion` / `_block_not_bound`); `parent_header` hashes to its `hash`,
which is `inclusion.block_header.parentHash`, and its number is one less (`failed:payer_state_parent_header_not_parent`);
under the stateRoot of each of the two headers, the payer's account (apc_l1proof.account, the eth_getProof path of
section 6 L1A) has codeHash = keccak256(code) (`failed:payer_state_code_not_proven`), the listed delegate's account has
the pinned code hash (`failed:payer_state_delegate_code_not_pinned`), and the slot word (L1S) is the same at both ends
(`failed:payer_state_slot_changed_in_block`); a proof that does not verify: `failed:payer_state_proof:<reason>`. What
the proof shows: the code and the slot at the end of block N-1 and at the end of block N; a transaction earlier in block
N could change them and change them back, which is not excluded (that would need executing the block).

L2.sig with the code known. Code empty: a 64- or 65-byte signature as 12.2, any other length
`failed:signature_length_<n>_for_a_payer_without_code` (Permit2 InvalidSignatureLength). Code = a delegation to an
address of the CLOSED LIST below: that delegate's isValidSignature, reduced to the check it makes; anything else
`not_evaluated:payer_code_not_known`. The list (code of an existing account cannot change since EIP-6780; code hashes
measured on Base 2026-10-26; sources from Sourcify, copies in sources/kernel_7702_d6cedde8_20261026 and
sources/metamask_7702_63c0c19a_20261026):
- 0xd6cedde84be40893d153be9d467cd6ad37875b28, ZeroDev Kernel 0.3.3 (Sourcify "match"), runtime code keccak256
  e5b56d82…e3b4fb. ValidationManager._verifySignature: first byte 0x00 = root mode (other first bytes:
  `not_evaluated:kernel_validation_mode_<xx>_not_evaluated`); with no root validator installed (the low 21 bytes of
  the word at KERNEL_SLOT = 0x7bcaa2ce…f84f, keccak256("kernel.v3.validation") - 1, are zero; else
  `not_evaluated:kernel_root_validator_installed`; the slot is required, else the bundle is refused) the type is
  VALIDATION_TYPE_7702 and the check is solady ECDSA.recover (65 bytes r||s||v, v 27 or 28, or 64 bytes r||vs; no s
  rule) of _toWrappedHash(h) = EIP-712 {name "Kernel", version "0.3.3", chainId, verifyingContract = the payer} of
  Kernel(bytes32 hash) with hash = the Permit2 digest of 12.2, equal to the payer; after the first byte, a 32-byte
  prefix keccak256("kernel.replayable.signature") selects chainId 0. `verified (ERC-1271 Kernel 0.3.3 by EIP-7702)`,
  `failed:kernel_signature_recovers_<address>`, `failed:kernel_signature_invalid`, `failed:kernel_signature_length_<n>`.
- 0x63c0c19a282a1b52b07dd5a65b58948a07dae32b, MetaMask EIP7702StatelessDeleGator (Sourcify "exact_match"), runtime
  code keccak256 6af675ac…97ba. _isValidSignature: OpenZeppelin ECDSA.recover (65 bytes, v 27 or 28, low s) of the
  hash itself equal to the payer. `verified (ERC-1271 EIP7702StatelessDeleGator by EIP-7702)`,
  `failed:delegate_signature_not_65_bytes`, `failed:high_s_refused_by_delegate`, `failed:recovers_<address>_not_from`.
Report member `payer_state`: null, "declared_rpc" or "proven_at_parent_and_block". Measured on the real set: the 19
66-byte signatures are 0x00 || r||s||v from payers delegated to the Kernel, slot zero at their blocks; 19 of 19 recover
the payer under the Kernel rule, in both forms (chain_verified with inclusion B1-B4 verified); the 65-byte payer
delegated to the DeleGator (p205): verified in both forms.

### 12.6 A declared ERC-1271 call (any payer with code)
```
erc1271_call: {"call": <rpc eth_call [{"to": from, "data": 0x1626ba7e || abi.encode(bytes32 digest, bytes signature)}, B]>,
               "block_hash": hash32, "endpoint": string of at most 256 characters}
```
Closed; permit2 only. The verifier builds the call data itself from its own Permit2 digest (12.2) and
payload.signature, in the canonical ABI layout, and the reply must be for exactly that call (else
`failed:call_params_<i>`). With chain_tx, B is the transaction's block or its parent
(`failed:erc1271_call_block_not_tx_block_or_parent`); with inclusion, block_hash is the header's hash or its parentHash
(`failed:erc1271_call_block_hash_not_header`). A result of 0x1626ba7e and 28 zero bytes: L2.sig
`not_evaluated:erc1271_declared_valid` — DECLARED, never verified; any other result `failed:erc1271_declared_invalid`.
When 12.2 or 12.5 decided L2.sig offline, that result stays, except that a declared invalid next to an offline
verified is `failed:erc1271_declared_contradicts_offline_check`. Report member `erc1271`: {declared: true, block,
block_hash, endpoint, returned}. A state proof for a general ERC-1271 payer is not offered: what isValidSignature reads
is decided by arbitrary code, so the set of accounts and slots to prove is known only by executing it, and this
verifier has no EVM. The proof path of section 6 (apc_l1proof: account, storage, code) proves values, not an
execution; 12.5 uses it only for delegates whose check is reduced above to the values it reads.

### 12.7 inclusion, canonical, acceptance in apc-0.10
The members of section 6 and section 4, same grammar, same code (apc_verify.check_inclusion, check_canonical,
check_acceptance), with the apc-0.10 terms:
- inclusion: B1-B3 with the anchor log `log_transfer` (the payment's own Transfer) in place of AuthorizationUsed and, for
  permit2, `log_settled` as the log that must follow it in the receipt; B3 failure codes `failed:transfer_log_not_in_receipt`
  and `failed:settled_log_not_next_in_receipt` (the others as section 6); E1 leaves the payment's own Transfer out.
  B4 permit2: witness.validAfter <= block timestamp <= deadline (the proxy and Permit2, 12.2); erc7710:
  `not_applicable:erc7710_no_signed_window`. The logs stay required (no reverted-transaction form of Amendment 0.3.3).
- canonical: O1-O4 and L1 of section 6 and 0.4 unchanged (they read only inclusion.block_header and the network).
- acceptance: A1-A2 of section 4 with payer = from (delegator), pay_to = witness.to (payTo), amount =
  permitted.amount (accepted.amount); permit2 nonce: OUR mapping, the uint256 as 0x and 64 hex digits (the profile
  names a 32-byte nonce, Permit2's is a uint256 unique per owner); erc7710 has no nonce:
  `not_evaluated:erc7710_payment_has_no_nonce` when the other members agree.
- report members block_bound (B1-B3 verified, B4 verified or not_applicable), canonical and l1_state as section 6.

Set check (apc_batch.py): a permit2 bundle's key is (network, Permit2, from, nonce) (Permit2's unordered nonces are per
owner across tokens); an erc7710 bundle is kept out of D1-D4 and listed with the reason (a delegation may be
multi-use: scheme_exact_evm.md summary table).
## 13. SPEC 0.11 (draft, 2026-10-26, local) — x402 signed offers and receipts (OR1-OR3; extension `offer-receipt`)
Source (merged x402 extension): x402-foundation/x402 @ 4241d56 `specs/extensions/extension-offer-and-receipt.md`
(extension version 0.6 of 2026-02-04, sha256 51151bd2…6ae9) and its reference implementation
`typescript/packages/extensions/src/offer-receipt/` (signing.ts, did.ts), copies and sha256 in
sources/x402_offer_receipt_20261026; cited as OR §n. Code: apc_offer.py, standard library only. Read in every bundle
version that can carry the extension: apc-0.1 to apc-0.3, apc-0.5, apc-0.12 and, since 0.16.1 (section 27), apc-0.10,
apc-0.15, apc-0.16 (an apc-0.13 bundle cannot carry it: the x402 v1 objects of section 21 have no `extensions`; from
0.21.5 an `extensions` member of its payment_required is ignored, named in notes and not read, SPEC 32.14); until
0.8 these objects were carried in `extensions` and not interpreted, so a forged offer or receipt left the verdict
unchanged.

Where (OR §4.1, §5.1): `payment_required.extensions["offer-receipt"]` = `{"info": {"offers": [1..64 offer]},
"schema"?: object}`; `settlement.extensions["offer-receipt"]` = `{"info": {"receipt": receipt}, "schema"?: object}`.
Closed, as OR §2 asks ("SHOULD treat unknown extension-specific fields as unsupported rather than attempting
best-effort interpretation"): a member of the extension, of `info`, of an artifact or of a payload that this section does
not name makes its check `not_evaluated:<artifact>_member_not_supported(<where>)` (so the bundle is at best
chain_incomplete, and the member is named), never ignored; a missing member or a value of the wrong type is outside the
grammar and refused with its path; `schema` (a descriptive JSON Schema) is carried, not interpreted.
An `offer-receipt` member of `payment_payload.extensions` is carried with a note (the extension does not place one there).
Artifact (OR §3.1): `{"format", "signature": string, "payload"?, "acceptIndex"?: integer >= 0 (offers only)}`.
`format` "eip712" requires `payload`, "jws" forbids it (else refused); another format string is
`not_evaluated:<artifact>_format_not_supported` (OR §2: unknown is unsupported, not interpreted).
Payloads, closed (OR §4.2, §5.2): offer `{version, resourceUrl, scheme, network, asset, payTo, amount, validUntil?}`,
receipt `{version, network, resourceUrl, payer, issuedAt, transaction?}`; version, validUntil, issuedAt JSON integers
in [0, 2^53); the rest strings. `version` other than 1: `not_evaluated:<artifact>_version_not_supported`. `network`
must be CAIP-2 (OR §4.2 note, §5.2 note: v1 names converted by the server), else `failed:<artifact>_network_not_caip2`.

Signature (the expected algorithm is fixed by the format and by the key, never by the artifact alone):
- eip712 (OR §3.2, §4.3, §5.3): domain {name "x402 offer" | "x402 receipt", version "1", chainId 1}, the normative
  types (validUntil absent = 0, transaction absent = ""; a present 0 / "" is read as absent, OR §4.3, §5.3); `network`
  must be `eip155:<id>` and an offer's `payTo` an EVM address (OR §3.1.1), else `failed:<artifact>_eip712_needs_evm`;
  `signature` 65 bytes hex, v 27/28 (0/1 read as 27/28 with a note, as the reference's viem); secp256k1 recovery
  gives the signer address (`failed:<artifact>_no_recovery`).
- jws (OR §3.3; RFC 7515 compact): three base64url parts without padding; header a JSON object with `alg` and `kid`
  strings; a `crit` member is `failed:<artifact>_jws_crit_not_understood` (RFC 7515 4.1.11); other header members are
  ignored with a note (RFC 7515 4); the payload bytes must be the RFC 8785 form of the payload
  (`failed:<artifact>_jws_payload_not_jcs`, OR §10). Key from `kid`, offline: `did:key` (multibase z, multicodec
  ed25519-pub 0xed, secp256k1-pub 0xe7, p256-pub 0x1200, compressed points decoded) and `did:jwk` (OKP Ed25519, EC
  secp256k1, EC P-256; a private `d` is refused); any other `kid` only from the reader's `signer_trust` document
  (below), else `not_evaluated:<artifact>_key_not_resolvable_offline`. The key type sets the algorithm: Ed25519 →
  EdDSA (RFC 8032), secp256k1 → ES256K (RFC 8812), P-256 → ES256 (RFC 7518 3.4); a header `alg` naming another is
  `failed:<artifact>_alg_not_the_key_algorithm`. `failed:<artifact>_signature_invalid` otherwise.
- A JWS whose payload bytes hold a member of the wrong type or miss one is `failed:<artifact>_jws_payload_outside_grammar(...)`
  (the signed bytes are the artifact; an eip712 `payload` with such a member is refused like any member of the bundle);
  an unknown member in either is unsupported as above. A `kid` longer than 4096 characters (a did:key identifier
  longer than 128) is failed before any decoding.
- Checks:
  - OR1 offers: every offer's signature holds (the first failure, `failed:offer_<i>_<reason>`); an `acceptIndex` is
    in range and names an accepts entry with the same scheme, network, asset, payTo, amount
    (`failed:offer_accept_index_out_of_range`, `failed:offer_accept_index_mismatch`: the field is unsigned, OR §4.1.1,
    but the bundle then carries a false statement); and one offer's payload equals the paid terms: resourceUrl the
    bundle's resource URL (payment_payload, else payment_required, exact string), scheme, network, amount exact,
    asset and payTo as addresses (EVM: case ignored; base58: exact) — else `not_evaluated:no_signed_offer_for_accepted`
    (a server may sign only some options). A non-zero validUntil before the settlement's block time (EVM: the
    `inclusion` header timestamp; Solana: chain_tx.blockTime, declared) is a note: the server MAY reject (OR §4.6).
  - OR2 receipt (only "on success", OR §5): a receipt in a settlement whose `success` is not true is
    `failed:receipt_on_unsuccessful_settlement`; the signature holds; network equal to `accepted.network`;
    resourceUrl to the bundle's resource URL (`not_evaluated:no_resource_url` without one); payer to the payer
    (EVM `authorization.from`, case ignored; Solana the authority of the matching transfer); a non-empty
    transaction to `settlement.transaction` (EVM case ignored) — each `failed:receipt_<what>_mismatch`. issuedAt is
    reported; before the settlement's block time it is a note (no source says it is an inconsistency, section "Open").
  - OR3 signer authorization (OR §4.5.1: a valid signature is not authorization), for each artifact that OR1/OR2
    verified: `verified` when the signer is the payTo (eip712: the recovered address equals payTo, for a receipt the
    bundle's `accepted.payTo`; jws: the address the key names on the payment's network equals it: EVM the secp256k1
    key's address, Solana the Ed25519 key in base58, Stellar the Ed25519 key as a G StrKey, XRPL the classic address
    of RIPEMD-160(SHA-256(0xED ‖ Ed25519 key, or the compressed secp256k1 key)) — the last two since 0.16.1; OR §4.5.1
    first approach), or when the reader's `signer_trust` lists the signer for the origin of resourceUrl;
    `failed:signer_not_authorized` when a `signer_trust` is given and lists neither; `not_evaluated:absent:no_signer_trust`
    otherwise (listed, non-blocking, like the reader's keys of X7). DNS TXT and did:web documents are not fetched.
- `signer_trust` (the reader's, like --http-keys; never read from the bundle), closed:
  `{"apc_signer_trust": 1, "keys"?: {kid: {"alg": "EdDSA"|"ES256K"|"ES256", "public_key": hex}},
    "authorized": [{"origin": "https://host[:port]", "signers": [EVM address or kid, 1..64]}]}` (Ed25519 32 bytes,
  secp256k1 and P-256 65 bytes 0x04||x||y on the curve). Authorization is evaluated as the reader states it; OR §5.5
  asks for authorization at issuedAt, which a mutable source cannot show.
Report member `offer_receipt`, present only with the extension: {offers: [{index, format, alg, kid, signer, matches}],
receipt: {format, alg, kid, signer, issued_at, transaction} or null}. An absent extension adds no OR check.
Tests: tests/test_offer_receipt.py — vectors made and checked by the reference implementation itself (x402 4241d56
typescript/packages/extensions, run locally from that commit, viem and jose as its lockfile pins) on the real bundles
of the corpus; positive control: the forged offer and receipt are chain_verified under apc_verify 0.8.0.

## 14. Amendment 0.11.1 (2026-10-26, every bundle version; apc_verify 0.11.0; read version by version as section 27 lists) — x402 builder-code attribution (BC1)
Source (merged x402 extension): x402 @ 4241d56 `specs/extensions/builder_code.md` (sha256 f7d62e04…2866; settlement
metadata `m` merged in #3666, 2026-10-06), cited BC. Code: apc_builder.py. Until 0.8 a Schema 2 suffix of the direct
call's calldata was reported as CBOR hex, "not interpreted", and the builder-code declarations were carried unread.
- The CBOR of the suffix is read closed: definite lengths, shortest-form arguments, text strings in UTF-8, unsigned
  integers, arrays, maps with text keys, nesting at most 16 (BC `m` rules: no negative integers, floats, tags, byte
  strings, indefinite lengths); top-level keys a, w, s, m only and in that order (BC "Top-level order is a, w, s, m");
  inside `m` keys sorted bytewise (RFC 8949 4.2.1, BC); a and w codes and each s code `^[a-z0-9_]{1,32}$`; m keys start
  with "x402". BC says both "Encoding MUST be deterministic (RFC 8949 section 4.2.1) ... map keys sorted bytewise" and
  "Top-level order is a, w, s, m"; the two disagree when both w and s are present ("s" sorts before "w"). Measured on
  the 1099 real Schema 2 suffixes of the oracle corpus (oracle/*.json, Base, 1829 distinct transactions): 839 {w},
  220 {a, w}, 29 {w, s}, 11 {a, w, s}; w = "cdp_facil1" in 1098, "bc_vfsiic9b" in one (a reverted transaction of
  oracle/reverted_base_53101000_2000.json); the 40 with s write w before s. The top-level order rule is the one read.
  Anything else: the report gives `{"malformed": <reason>, "cbor": hex}`; C1 is unchanged (the ERC-8021 framing holds).
- Declarations, closed (refused otherwise): `payment_required.extensions["builder-code"]` = {info: {a?, s?}, schema?},
  `payment_payload.extensions["builder-code"]` = {a?, s?}; codes as above, s a code or a non-empty list.
- BC1, only when the bundle carries a declaration: `failed:builder_code_app_not_declared` when the payload echoes an
  `a` that the carried PaymentRequired does not declare (BC: the client MUST NOT set it); `failed:
  builder_code_app_echo_mismatch` when the echoed `a` is not the declared one (BC App Code Echo Validation: the resource
  server MUST reject, `extension_echo_mismatch`); `failed:builder_code_calldata_app_mismatch` when the settlement
  calldata suffix does not carry the echoed `a` (BC Facilitator Behavior steps 1 and 5: a facilitator that writes the
  suffix reads `a` from the payload and encodes it); `not_evaluated:builder_code_calldata_malformed`; `not_evaluated:absent:no_builder_code_calldata` without a
  decoded suffix (an indirect call's calldata is the caller's and is not read, as in section 4); on Solana, Stellar
  and XRPL (no ERC-8021 calldata) `not_applicable:no_erc8021_calldata_off_evm` in its place (0.16.1); else `verified`.
  `s` and `w` are reported, not compared (BC: s is self-reported, w is the facilitator's own).
- Report member `builder_code` {declared_app, echoed, calldata}, present only with a suffix or a declaration.
What it does not show: a builder code is self-declared attribution that no contract validates (BC: "`m` is public,
facilitator-reported data that no contract validates"); w names a facilitator by its own code, not by a key (F2 does
that from the transaction signer). Tests: tests/test_builder_code.py.

## 15. Amendment 0.11.2 (2026-10-26, every bundle version; apc_verify 0.11.0, apc_batch.py; read version by version as section 27 lists) — x402 payment-identifier (PI1, D4)
Source (merged x402 extension): x402 @ 4241d56 `specs/extensions/payment_identifier.md` (sha256 a48b79d0…d2d3), cited
PI. Code: apc_payid.py. Until 0.8 the extension was carried in `extensions` and not read.
- Grammar, closed (refused otherwise): `payment_required.extensions["payment-identifier"]` and
  `payment_payload.extensions["payment-identifier"]` = {info: {required: boolean, id?: string}, schema?: object}.
- PI1, only when either carries the extension: `failed:payment_identifier_malformed` when the payload's id is not 16-128
  characters of A-Z, a-z, 0-9, "-", "_" (PI "id Format"); `failed:payment_identifier_required_but_absent` when the
  carried PaymentRequired says `required: true` and the payload has no id (PI: the server answers 400, so a payment
  settled on it went past that rule); `not_evaluated:absent:no_payment_identifier` when the payload has none; else
  `verified`, with a note naming the id.
- D4 (apc_batch.py), across a set, ids scoped by merchant (network, payTo, origin of the resource URL; PI "Servers should
  avoid using id alone ... Scope the key"): one id with two request fingerprints (scheme, asset, amount, resource URL; PI
  "Request Binding") is `failed:payment_identifier_reused` (PI: 409 Conflict); one id and one fingerprint with two
  different authorizations whose settlement replies (T1 verified) name transactions is
  `failed:payment_identifier_two_settled_payments`: the operation the id makes idempotent was paid twice (a retry
  that the server or facilitator did not deduplicate). The set verdict is `set_failed` with either.
What it does not show: the id is chosen by the client and signed by no one (it is not in the EIP-3009 authorization);
D4 sees only the bundles it is given. Tests: tests/test_payid.py.

## 16. Amendment 0.11.3 (2026-10-26, apc-0.3, apc-0.5 and apc-0.12; apc_verify 0.11.0) — the payment over MCP or A2A (XM1-XM4, XA1-XA4)
Sources (merged x402 transports): x402 @ 4241d56 `specs/transports-v2/mcp.md` (sha256 4f1e0bb5…d879, MCP-T) and
`specs/transports-v2/a2a.md` (sha256 bbf07836…d977, A2A-T; the A2A extension is google-agentic-commerce/a2a-x402,
spec v0.2 at 125db55); copies in sources/x402_transports_20261026. Code: apc_transport.py. Section 10 covers HTTP only.
Members, as `exchange` (declared recordings; the reader's trust is not involved):
`exchange_mcp: {"request": JSON-RPC request, "response"?: JSON-RPC response}`, `exchange_a2a` the same. A request is
exactly {jsonrpc "2.0", id, method, params (object)} (JSON-RPC 2.0 section 4); a response {jsonrpc "2.0", id, and
exactly one of result (object) or error}; an id is a string or an integer (null and fractions, which JSON-RPC
discourages, are refused). Inside `params` and `result` only the members below are read; the rest (MCP `arguments`,
content, A2A parts and artifacts) is carried. MCP `_meta` and A2A `metadata` must be objects; an
`x402.payment.status` outside the six of A2A-T "Payment Status Lifecycle" is refused.
- XM1 `method` "tools/call" and `params._meta["x402/payment"]` RFC 8785-equal to `payment_payload`
  (`failed:mcp_request_not_tools_call`, `failed:mcp_request_without_payment`, `failed:mcp_request_carries_another_payment`).
- XM2 the response id equals the request id, same JSON type (`failed:mcp_response_id_mismatch`).
- XM3 `result._meta["x402/payment-response"]` equal to `settlement` (`failed:mcp_response_carries_another_settlement`,
  `failed:settlement_not_in_bundle`, `failed:mcp_response_without_payment_response` when the bundle's settlement
  succeeded); a JSON-RPC error: `not_evaluated:mcp_response_is_a_jsonrpc_error`.
- XM4 `result.isError` (a boolean, default false) is true exactly when the settlement did not succeed
  (`failed:mcp_status_contradicts_settlement`); with isError, MCP-T "Server Requirements" (MUST): the PaymentRequired
  is both `structuredContent` and the JSON text of `content[0].text`, equal as JSON values
  (`failed:mcp_payment_required_not_in_both_forms`, `failed:mcp_payment_required_text_differs`).
- XA1 `method` "message/send", `params.message.metadata` with `x402.payment.status` "payment-submitted",
  `x402.payment.payload` equal to `payment_payload`, and a string `taskId` (`failed:a2a_request_not_message_send`,
  `failed:a2a_request_without_payment`, `failed:a2a_request_status_not_payment_submitted`,
  `failed:a2a_request_without_task_id`, `failed:a2a_request_carries_another_payment`).
- XA2 response id equal to the request id; `result.kind` "task" and `result.id` the request's taskId
  (`failed:a2a_response_id_mismatch`, `failed:a2a_task_id_mismatch`).
- XA3 `result.status.message.metadata["x402.payment.receipts"]` (an array) holds the bundle's settlement
  (`failed:a2a_receipts_without_the_settlement`, `failed:a2a_response_without_receipts`, `failed:settlement_not_in_bundle`).
- XA4 the lifecycle agrees with the settlement (A2A-T tables): success true with `x402.payment.status`
  "payment-completed" and task state "completed"; success false with "payment-failed" and "failed"; otherwise
  `failed:a2a_status_contradicts_settlement`.
Report members `exchange_mcp` / `exchange_a2a` (tool or task, whether a response was recorded) only when carried.
Measured on the specification's own examples (tests/test_transport.py): the MCP-T "Payment Required" example's
content[0].text equals its structuredContent as JSON; its "Settlement Failure" example abbreviates the text with
`[...]`, which is not JSON, so XM4 fails on it verbatim (an example, not a rule).

## 17. Draft profiles (2026-10-26; apc_verify 0.11.0 `--drafts`, apc_drafts.py) — proposed x402 rules, kept apart
Proposals are built too (the author, 26/10), but never mixed into the merged-spec checks: each is a profile named by its
pull request and head commit, run only with `--drafts`, reported in the member `drafts` = {profile: {source, checks,
verdict}}, verdict `draft_met` (all verified), `draft_failed` (one failed), `draft_incomplete` or
`draft_not_applicable`. `checks`, `verdict` and the exit code are those of the merged rules alone, with or without
`--drafts`. A profile of apc_drafts.py that cannot read the bundle (Refusal or Unsupported) reports the check `bundle` =
`not_evaluated:not_read_by_the_profile(<reason>)` (0.18.3; until 0.18.2 the 6 real apc-0.10 bundles of
bundles/real_permit2 ended `unsupported`, exit 3, with `--drafts`: the PR 3925 profile read them by the apc-0.1 parser;
found by tools/fuzz_bundles.py seed n27 case 452, independent review 2026-10-27); one past the drafts' Keccak-256 budget reports
`budget` = `not_evaluated:keccak_budget` (0.18.4, section 29.2). When a proposal moves, only its profile changes. Status measured 2026-10-26: open, no review by a
maintainer on any of the three (gh api reviews and comments).
- `x402-pr3910@2e9e6aa` (x402 PR 3910, "self-payment prohibition"): DS1 `failed:invalid_self_payment` when the payer
  equals payTo (case ignored for EVM; on Solana the authority of the matching transfer), else `verified`. Merged rules
  report it only (`payer_is_payee`, Amendment 0.3.3 part 2). Real case: v004 of bundles/real_v03.
- `x402-pr3925@8d08156` (x402 PR 3925, scheme_exact_evm.md "Facilitator Verification Rules (MUST)"), EVM only: DV1
  low-s for every token (`failed:high_s`; the merged reading, Amendment 0.3.2, fails it only for the measured tokens);
  DV2 signer binding = L2.sig apart from the high-s outcome; DV3 the window, which the PR evaluates "at verification
  time": the bundle has no verification time, so the block time of B4 when evaluated, else
  `not_evaluated:verification_time_not_in_bundle`; DV4 = K2; DV5 replay is stateful: `not_evaluated:set_check_apc_batch_D2_D3`.
- `x402-pr3827@fe777a4` (x402 PR 3827, offer-receipt receipt payload version 2 with a salted
  `authorizationCommitment`, §5.6; vectors at babyblueviper1/preaction-governance-conformance 0a818e7, CC0, copies and
  sha256 in sources/x402_pr3827_20261026). DR1 the receipt under the PR's grammar (version 1 or 2, the v2 EIP-712 type
  with authorizationMethod and authorizationCommitment, `info.authorizationSalt` allowed) with the OR2 bindings of
  section 13; DR2 the link of §5.6.4 done offline: commitment = SHA-256("x402-receipt-authorization/0" ‖ 0x00 ‖ method ‖
  0x00 ‖ asset ‖ authorizer ‖ nonce ‖ salt), authorizer the receipt's signed payer, asset the accepted one, the
  candidate the bundle's own authorization when C2 shows it consumed. `verified` (linked), `failed:inconsistent`
  (linked and the receipt's transaction names another one), `failed:malformed:<what>` (one of method and commitment
  only, or an input not of its size: the PR's error codes), `not_evaluated:not_attempted:<why>` (no commitment, another
  method, no salt), `not_evaluated:incomplete:<why>` (the bundle holds one candidate, not the authorizer's whole set, so a
  miss is not the PR's `no_match`; or the authorization is not shown consumed). Under the merged rules the same receipt
  is OR2 `not_evaluated:receipt_version_not_supported` or `..._member_not_supported(info.authorizationSalt)`.
Tests: tests/test_drafts.py (the PR 3827 commit and link vectors; the real self-payment bundle; drafts never change
the verdict).

## 18. Amendment 0.11.4 (2026-10-26; apc_verify 0.11.0, apc_report.py, apc_batch.py) — hosts and URLs outside ASCII
A resource URL may be an IRI (x402 `resource.url` is a string; servers in Japan, China, the Arab world publish IDN hosts
and non-ASCII paths), while an HTTP request target is a URI. Until 0.10 the comparisons were by exact string or by
ASCII lower case, so `https://例え.テスト/データ` never equalled its own request target and a policy host in
Unicode never matched the A-label in a URL. Code: apc_intl.py (standard library only).
- Host form: each label lower-cased if ASCII, else RFC 3490 ToASCII (Nameprep, RFC 3491; Punycode, RFC 3492) with
  Python's `idna` codec; every label must then be LDH; an `xn--` label must decode and re-encode to itself. IDNA 2003
  (the codec) and IDNA 2008 / UTS 46 (browsers, WHATWG URL) map the four UTS 46 "deviation" characters U+00DF, U+03C2,
  U+200C, U+200D differently, so a host holding one is not compared (`host_not_comparable(idna_deviation_character)`),
  never mapped one way silently. IP literals are compared as written.
- X2 (section 10): when the exact comparison fails and the resource URL is not ASCII, the IRI is mapped to a URI (RFC
  3987 3.1: host to A-labels, every other non-ASCII character as %-escaped UTF-8, upper-case hex) and compared again;
  `verified` with a note giving the mapped form.
- P5 (section 8): hosts compared in A-label form; a policy host that has none is refused when the policy is read; a
  resource host that has none is `failed:resource_host_not_comparable(<reason>)`.
- OR3 (section 13) and D4 (section 15): origins compared in A-label form; a `signer_trust` origin may be written as an
  IDN.
- Amounts stay ASCII decimal (section 4: `[0-9]`, not Unicode digits; full-width and Arabic-Indic digits are refused,
  tests/test_apc03.py).
Tests: tests/test_intl.py — RFC 3492 7.1 sample strings (E) Chinese, (I) Hebrew, (K) Japanese as hosts; the %-escapes
against urllib.parse.quote; positive controls on apc_verify / apc_report 0.8.0 (5cbe7c7).

## 19. Amendment 0.11.5 (2026-10-26, every EVM bundle version; apc_verify 0.11.0, apc_assets.py; read version by version as section 27 lists) — stablecoins measured for the world
Until 0.10 the high-s rule of Amendment 0.3.2 knew two tokens (USDC on Base and Base Sepolia); every other asset was
`not_evaluated:high_s_token_rule_not_measured`, and the report did not say what an atomic amount is in units. Measured
2026-10-26 from public RPC (read only; every reply saved in oracle/world_20261026, sha256 in its SHA256SUMS):
- real EIP-3009 executions (AuthorizationUsed logs of the token, the emitting transaction kept when it calls the
  token directly), rebuilt as bundles by tools/world_bundles.py (envelope reconstructed as tools/make_real_bundles.py)
  in bundles/real_world_20261026: USDC on Ethereum 15, Arbitrum 4, Avalanche 8, Optimism 5, Monad 15, Celo 1; EURC on
  Base 2; JPYC on Polygon (0xe7c3d8c9…3c29) 14; Tether USD on Celo 11; Tether America USD (USAT) on Celo 15 — 90 bundles,
  L2.sig verified on 90; 89 chain_verified, 1 chain_incomplete (EURC on Base, block 53089326, tx 0xc7db6d5e…f007: its calldata ends with
  the same ERC-8021 Schema 0 suffix "bc_pn814bq5" twice, which section 4 does not classify: C1
  `not_evaluated:unrecognized_trailing_calldata`, reported, not read as a failure);
- for JPYC and the two Tether tokens on Celo the token has no public `version()` (JPYC has no callable
  `DOMAIN_SEPARATOR()` either): the EIP-712 domain version is the one, of "1", "2", "3", under which every executed
  signature recovers its `from` (exactly one did: "1" for the three; the x402 SDK table defaultAssets.ts @4241d56 gives
  "1" for the two Celo Tether tokens, independently);
- `decimals()` and `symbol()` of each token (USDC, EURC, USD₮ and USAT 6; JPYC 18);
- the high-s probe of Amendment 0.3.2 (tools/probe_lows_usdc.py; for JPYC the domain check is the low-s call itself)
  on the ten tokens: the low-s call returns, the same signature with s' = n − s and v flipped reverts "ECRecover:
  invalid signature 's' value" on all ten (oracle/world_20261026/probe_*.txt).
Rule: apc_assets.ASSETS lists (network, asset) → symbol, decimals, EIP-712 name and version, high-s refused; the high-s
list of 0.3.2 is the set of its entries marked refused (twelve). Report member `asset` {symbol, decimals, amount (the
atomic amount written in units, integer arithmetic, no float), eip712} for a listed asset only; when
`accepted.extra` names another domain a note says so (L2.sig still decides). Not in the table (no direct transferWithAuthorization in the blocks read, retried 2026-10-26 with smaller ranges and
other public RPCs): EURC on Ethereum (5000 blocks) and Avalanche (200000), JPYCv2 (0x431d5dff…7bdb), Sei, XDC, Flare
USD₮0, Stable USDT0, Unichain (2 logs, both indirect calls), World Chain (5000 blocks): they stay outside the table, `not_evaluated:high_s_token_rule_not_measured` as before.
Tests: tests/test_world.py; positive control: under apc_verify 0.8.0 (5cbe7c7) a high-s signature on any of the ten
new tokens is `not_evaluated:high_s_token_rule_not_measured`.

External oracle (2026-10-26, no rule changed): the ten EIP-3009 vectors of iamonuwa/kanon @3d49240 (Apache-2.0,
reason-code registry 2.0.0; copies and sha256 in sources/kanon_3d49240), each `input` read as the payment_payload of an
apc-0.1 bundle: the seven whose reason needs only the evidence (VALID, SIG_MALLEABLE, three SIGNER_MISMATCH,
AMOUNT_INSUFFICIENT, NETWORK_MISMATCH with their target network carried as settlement.network) agree with L2.sig, K2
and T2 (tests/test_kanon.py); NOT_YET_VALID, EXPIRED and NONCE_REPLAY need the verifier's clock and nonce state of
their `context`, which a bundle does not carry (B4 judges the window at the block time, D2/D3 replay across bundles).

## 20. SPEC 0.12 (draft, 2026-10-26, local) — Stellar: the x402 `exact` scheme on Soroban tokens, bundle `apc-0.12`
Sources (merged): x402 @ 4241d56 `specs/schemes/exact/scheme_exact_stellar.md` (XLM §), the facilitator code
`typescript/packages/mechanisms/stellar/src/exact/facilitator/scheme.ts`, `constants.ts` (copies in
sources/x402_stellar_20261026, with the default `maxTimeoutSeconds` 300 of `core/src/server/x402ResourceServer.ts` 826);
XDR stellar/stellar-xdr @4f524bb (sources/stellar_xdr_4f524bb). Code: apc_stellar.py (strict XDR reader, StrKey
SEP-23, network id, transaction hash, Soroban authorization preimage, Stellar Asset Contract id) and apc_xlm.py.
Checked against the x402 constants: the SAC id computed from the classic USDC asset equals `USDC_PUBNET_ADDRESS` and
`USDC_TESTNET_ADDRESS`.
Bundle (closed at every level, as section 7):
```
{ "bundle_version": "apc-0.12",
  "payment_payload": { "x402Version": 2, "accepted": REQ, "payload": {"transaction": BASE64 XDR}, "resource"?, "extensions"? },
  "payment_required"?, "settlement"?, "facilitator"? (as Amendment 0.3.3 part 3, signers G accounts),
  "chain_tx"?: { "ledger", "status": "SUCCESS"|"FAILED", "envelopeXdr", "resultXdr", "contractEventsXdr": [[BASE64 XDR]] },
  "provenance"?, "exchange"?, "exchange_mcp"?, "exchange_a2a"? }
REQ = { "scheme": "exact", "network": "stellar:pubnet" | "stellar:testnet", "amount": decimal i128 >= 0,
        "asset": C StrKey, "payTo": G or C StrKey, "maxTimeoutSeconds": int > 0, "extra": {"areFeesSponsored": bool} }
```
The XDR read: TransactionEnvelope types TX and TX_FEE_BUMP, one or more operations of which only invokeHostFunction /
invokeContract is read (any other operation type: G1 failed in the payload, refused in chain_tx), SCVal types 0-18,
20, 21, SCAddress types 0-5, credentials types 0-2 (type 3, with delegates, refused), every length bounded, padding
zero, booleans 0 or 1, no trailing bytes. `chain_tx` is the RPC's getTransaction reply (declared).
- G1 (XLM §2) one operation, invokeHostFunction, contract = asset, function "transfer" with 3 arguments: from an
  account or contract address, to = payTo, amount = `accepted.amount` as i128.
- G2 (XLM §3) at least one authorization entry; address credentials (legacy or V2, CAP-71 preimage with the address),
  never source-account credentials; every entry's root invocation is the transfer itself and has no sub-invocations;
  every entry names `from`. A G-account payer: the signature vector holds exactly one {public_key, signature} map whose
  key is the payer's own, and Ed25519 verifies over SHA-256(HashIDPreimage ENVELOPE_TYPE_SOROBAN_AUTHORIZATION) →
  `verified`; another signer set needs the account's signers and thresholds (ledger state):
  `not_evaluated:account_signers_need_ledger_state`; a contract payer (smart wallet) is authorized by its own
  `__check_auth`: `not_evaluated:contract_account_check_auth`.
- G3 (XLM §3) each signature expiration ledger is at least the settlement ledger and at most it plus
  ceil(maxTimeoutSeconds / 5) (5 s: XLM's fallback ledger time; the verify-time ledger is not in the bundle, and it
  is at most the settlement ledger, so this is the bound that evidence can show).
- G4 (XLM §4) from is not a settled source (transaction source, fee-bump source, operation source of chain_tx:
  `failed:facilitator_is_payer`), no settled source appears in an authorization entry (`failed:facilitator_in_auth`),
  and the payload's own transaction and operation sources are not settled sources (`failed:unsafe_tx_or_op_source`).
- T1 settlement reply (x402 v2 5.3.2; XLM Phase 3: `transaction` is 64 hex characters); K4 as section 4; K6 as
  section 6 (our rule: a zero amount pays nothing).
- C1 chain_tx carries the payload's operation and its authorization entries byte for byte (XLM Settlement Phase 1:
  "preserving all operations and auth entries"); C2 the transaction id recomputed (SHA-256 of the
  TransactionSignaturePayload) equals `settlement.transaction`, status SUCCESS and result code txSUCCESS or
  txFEE_BUMP_INNER_SUCCESS with an inner txSUCCESS (else `failed:transaction_failed`, and a success reply fails T1);
  C3 the operation's contract events hold exactly one `transfer` event, from the asset, from → payTo, amount equal
  (an i128 or CAP-67's {amount, to_muxed_id} map), and no other transfer event (XLM §4 "NO OTHER BALANCE CHANGES").
- F2 the settled sources are in the declared facilitator signer list. block_bound is false (no ledger header proof).
- Set checks D1-D3 (apc_batch.py): one authorization is (network, asset, payer, the Soroban nonces of its address
  entries), which the host consumes once.
Real data (bundles/xlm_real_20261026 — outside the bundles/real* pattern the EVM tests read —, tests/test_xlm.py): the x402.org facilitator's /supported (2026-10-26, sha256
ff310d04…5d3e) names two Stellar signers; their 50 latest testnet transactions (Horizon), read by Stellar RPC
getTransaction, give 25 successful x402 settlements (oracle/stellar_20261026/x402org_testnet.json). Rebuilt as bundles
(the operation, the payer's signed authorization entries and the settled transaction are real; the payload
transaction around them and the envelope are reconstructed, tools/make_bundles_xlm.py): 7 with an account payer are
chain_verified (G2 verified on the real Ed25519 signatures); 18 with a smart-wallet payer are chain_incomplete
(G2 `contract_account_check_auth`). Pubnet: 316 transactions with a USDC transfer event in 3000 ledgers
(oracle/stellar_20261026/usdc_pubnet.json) held no sponsored invokeHostFunction transfer; the mainnet facilitators
(OpenZeppelin Channels, AgentSmith) need an API key for /supported, so no pubnet x402 settlement is in the corpus.

## 21. SPEC 0.13 (draft, 2026-10-26, local) — x402 version 1, bundle `apc-0.13` (EVM `exact`, EIP-3009)
Source: x402 @ 4241d56 `specs/x402-specification-v1.md` (V1 §; copy and sha256 in sources/x402_schemes_20261026) and,
for the network names, the v1 SDK table `typescript/packages/legacy/x402/src/types/shared/network.ts`
`EvmNetworkToChainId` (15 names; `legacy_network.ts` there). SDKs still serve v1 (x402 issues #3928, #3930 of 24/10).
Code: apc_v1.py.
Bundle, closed: `{bundle_version "apc-0.13", payment_payload: V1 PaymentPayload {x402Version 1, scheme, network,
payload}, payment_required: V1 PaymentRequirementsResponse {x402Version 1, error, accepts} (required: a v1 payload names
no requirement, V1 5.2), settlement?: V1 SettlementResponse {success, transaction, network, payer[, errorReason]},
chain_tx?, inclusion?, canonical?, payer_wallet?, facilitator?, provenance?, acceptance?, mandate?}`; requirements
{scheme, network, maxAmountRequired, asset, payTo, resource, description, maxTimeoutSeconds[, mimeType, outputSchema
(object or null), extra]}. A network outside the table (e.g. "ethereum", which the table lacks; solana) is
unsupported. `exchange` is not read for v1 (its header is X-PAYMENT, not section 10's PAYMENT-SIGNATURE).
Reading: the requirement paid is the one exact requirement on the payload's network; with several there, the one
whose payTo is the authorization's recipient, else refused (V1 names no field that says which). The bundle is then
verified as the apc-0.3 bundle its objects map to (network names to CAIP-2, maxAmountRequired to amount, the
requirement's resource to `resource`), with two v1 rules: K2 is `verified (v1: ...)` when the value exceeds
maxAmountRequired ("meets or exceeds", V1 6.1.2 step 3; v2 requires equality), and K4 holds by construction. The
report carries `x402_version: 1`. Set checks read the mapped bundle.
Tests: tests/test_v1.py — the V1 5.1.1 / 5.2.1 / 5.3.1 examples (the example signature is a real EIP-712 signature by
its `from` under the Base Sepolia USDC domain: L2.sig verified); every real bundle of bundles/real_v03 written in its v1
form gives the same verdict and the same L2, C, B and O results; positive control on 0.8.0.

## 22. SPEC 0.14 (draft, 2026-10-26, local; apc_report.py) — key validity window of the signed report (census G5)
Section 8's signed report had no time, so a key's validity window could not be checked (predgeAI/x402-receipts
@23b2382 checks one: its vectors `neg-key-not-valid-before-validFrom`, `neg-key-not-valid-expired`). Version 2:
`{"apc_signed_report": 2, "report", "signed_at": "YYYY-MM-DDTHH:MM:SSZ", "public_key", "key_id", "signature"}`, closed;
the Ed25519 signature is over "apc-report-v2\n" followed by the RFC 8785 form of {"report", "signed_at"} (so the time
is signed; version 1 is unchanged and still verifies). The reader's keys (never read from the document):
`{"apc_report_keys": 1, "keys": [{"public_key": 32-byte hex, "valid_from": UTC, "valid_to": UTC or null}]}`, closed, one
entry per key, valid_to not before valid_from. With keys: `failed:signed_by_another_key` (not listed),
`failed:key_not_valid_before_valid_from`, `failed:key_not_valid_after_valid_to` (both ends inclusive),
`not_evaluated:v1_has_no_signed_at` for a version 1 document. `signed_at` is the signer's statement: the window shows
the key was valid at the time it states, not that it signed then (no timestamp authority here). CLI: `sign ...
--signed-at T`, `verify ... --keys KEYS.json`. Tests: tests/test_report_keys.py (RFC 8032 7.1 test 1 key; positive
control: apc_report 0.8.0 refuses a version 2 document).

## 23. Draft profiles, second set (2026-10-26; `--drafts`, apc_drafts2.py)
As section 17: profile id = proposal and head commit, report member `drafts`, merged checks and verdict unchanged.
Two carriers are added. `draft_artifacts: [1..64 {"profile": string, "artifact": any}]` is a member of every bundle
version for artifacts a proposal defines outside the x402 messages; the merged rules do not read it (the report notes
its presence) and only the named profile does. A resource member that a proposal adds (PR 3741 `method`) is taken out
of the bundle before the merged rules read it, only with `--drafts`; without it the merged grammar refuses the
bundle as before. Status 2026-10-26: all open, none reviewed by a maintainer.
- `x402-pr3604@4726ab0` Buyer Delivery Claim (in `draft_artifacts`). DC1 the claim's members (PR 3604 4: the ten
  required, measured/externalRefs/priorClaimId optional, another member not read: `not_evaluated`; enums assetType and
  delivered; evidenceHash 64 lower-case hex; timestamp with milliseconds and Z); DC2 claimId = "0x" + SHA-256 of the
  RFC 8785 form of the content with both addresses lower-cased (PR 3604 5: "MUST be lowercased before
  serialization"); DC3 the EIP-191 personal_sign over the ASCII claimId recovers buyerAddress; DC4 buyerAddress is the
  bundle's payer (PR 3604 6, a MUST), DC5 sellerAddress its payTo, DC6 settlementRef its settlement transaction.
  Real data: the four live EAS attestations the PR lists (Base 2, Optimism 1, Ethereum 1; eth_call getAttestation,
  sources/x402_prs_20261026/real_chain_reads.json): DC1-DC3 verified on all four; two carry EIP-55 addresses and
  their claimId is over the lower-case form, which is why DC2 lower-cases.
- `verify402-seller-payout@2b0faea` seller payout manifest (in `draft_artifacts`; one implementer's format,
  a32116150-ctrl/verify402 src/preflight.mjs 985-1230). VM1 its members; VM2 EIP-191 over canonicalStable of {spec,
  seller, chainId, payTo[], issuedAt, expiresAt, signer} (recovery.mjs 159-164: sorted keys, JSON.stringify values)
  recovers `signer`; VM3 chainId is the bundle's chain; VM4 payTo is listed; VM5 expiresAt after the settlement block
  time (from `inclusion`).
- `erc8004-feedback@4891ba3` ERC-8004 (Draft) off-chain feedback file (in `draft_artifacts`): FB1 the MUST fields
  and proofOfPayment {fromAddress, toAddress, chainId, txHash}; FB2-FB5 those equal the bundle's payer, payTo, chain
  id and settlement transaction; FB6 clientAddress names the payer. The file is unsigned (declared): FB binds it to
  the payment, not to its author.
- `x402-pr3741@1f5a05a` resource.method: RM1 an upper-case RFC 9110 token; RM2 the recorded request (section 10
  `exchange`) used the method the server declared (its own rendering is authoritative, PR 3741); RM3 a 2xx HEAD
  settlement for a resource with a mimeType (RFC 9110 9.3.2: a HEAD response carries no content); RM4 equal to
  extensions.bazaar.info.input.method when both are present.
- `x402-pr3186@3dcef3c` offer-receipt receipt version 2 with responseHash, responseHashAlg "sha256",
  responseHashEncoding "raw" | "jcs": DP1 the receipt under that grammar (OR2 bindings), DP3 its signer (OR3), DP2 the
  hash equals SHA-256 of the recorded response body (raw; a content coding other than identity is not removed here)
  or of the RFC 8785 form of the body's JSON (jcs). PR 3186 and PR 3827 both define receipt payload version 2, with
  different members: a version 2 receipt is read under the profile the reader names, never guessed.
- `x402-pr2666@76b8ccc` settlement record (in `draft_artifacts`): SR1 its members (PR 2666 3.1, 3.4), SR2 actionRef =
  "sha256:" + SHA-256(RFC 8785 of {agentId, actionType, scope, timestampMs, seq, terminal}), SR3-SR7 txDigest, payTo,
  asset, amount, network equal the bundle's, SR8 decimals equal the measured ones (section 19) when listed;
  SR9 the vaara.receipt/v1 receipt is not read (`not_evaluated`). Real data: the PR's three records recompute (SR1,
  SR2); its two Polygon legs equal JPYC Transfer logs of the real transaction 0xa9e6c6a9…3249 (receipt read
  2026-10-26).
- `x402-pr3830@f2cf798` svm-memo authorization commitment (receipt version 2 of PR 3827 on Solana): DM1/DM3 as DR1/DR3;
  DM2 commitment = SHA-256("x402-receipt-authorization/0" ‖ 0x00 ‖ "svm-memo" ‖ 0x00 ‖ mint ‖ payer ‖ SHA-256(memo) ‖
  salt) opened with the Memo instruction data of the bundle's payload transaction. The PR's worked example
  (commitment 0xffb8966e…5c59) is reproduced; the link is checked on the real Solana payment of section 7.
Tests: tests/test_drafts2.py; PR 3186 receipts made and verified by that PR's own signing.ts, verify402 manifests
signed as its tests do (tools/drafts2_oracle.ts, tests/data/drafts2_ref_vectors.json; kept with the real corpus, not in the public tree: README).

## 24. Draft profiles, third set (2026-10-26; `--drafts`, apc_drafts3.py)
As sections 17 and 23. Status 2026-10-26: open, no maintainer review.
- `x402-pr3304@7f7489b` response-provenance (in the recorded response body's `extensions`, section 10 `exchange`):
  RP1 the claim's shape (responseHash "sha256:" + hex, fixedPointVersion GVP-FixedPoint/1 or /2, method, dataVintage
  — the /2 grammar YYYY[-MM[-DD]] —, resultCarriage "member" or "body"); RP2 responseHash = SHA-256 of the RFC 8785
  form of {endpoint (the request path), inputs (the JSON request body, else the query under the PR's urlencoded
  mapping with its two tightenings), result, method, dataVintage}. The PR's four outcomes map to verified,
  `failed:contradicted`, `not_evaluated:unverifiable:<why>` and no_claim (profile not applicable). The PR's worked
  vector and its seven query examples are reproduced.
- `x402-pr3682@23b5c21` execution-evidence x402ev/1 (in `settlement.extensions`): EE1 evidenceRef = "x402ev/1:sha256:"
  + SHA-256(RFC 8785 of info without evidenceRef, signer.signature, transparency); EE2 the Ed25519 signature over the
  same bytes; EE3 payer ≠ payee; EE4a-f payer, payee, amount, asset, network, txHash equal the bundle's; EE5
  delivery.contentDigest is the SHA-256 of the recorded response body; EE6 the key is the reader's (signer_trust keys;
  the PR requires an explicit external trust input). The PR's own example is a real signed vector: EE1 and EE2 verify.
- `x402-pr3681@4acdd1f` refund (request and response pairs in `draft_artifacts`): RF1 the request's members and
  reason code; RF2 it names the bundle's settlement transaction; RF3 amount at most the settled amount; RF4 refundTo is
  the payer when given; RF5 `not_evaluated:proposal_defines_no_signed_bytes` (the PR asks for a payer signature "over
  the canonical request bytes" without defining the bytes or EIP-712 types: no verifier can check it); RF6 the
  response status; RF7 the executed refunds, one per idempotencyKey, do not exceed the settled amount; RF8 one key
  with two different refunds fails ("never a second transfer").
- `x402-pr2853@30a6be4` compliance-fields (record and attestation in `settlement.extensions`): CF1 the record (version
  1, canonicalizationVersion 1, JSON numbers only in the declared integer members); CF2 the EIP-712 attestation
  {version, recordDigest, receiptDigest, issuedAt} carries recordDigest = keccak256(RFC 8785 of the record) and the
  record's own receiptDigest and issuedAt; CF3 receiptDigest = keccak256(RFC 8785 of the offer-receipt receipt);
  CF4 the signer recovered from domain {name "compliance-fields", version "1", chainId 1}; CF5 the signer is the payTo
  (else the reader's trust); CF6 settlement.txHash is the bundle's. The PR's three recordDigest vectors are reproduced.
- `x402-pr3783@737243d` delivery-receipt v0.2.1, session path only (apc_dr3783.py): the settlement extension's inline
  receipt or reference, with the epoch's key directory (and, for a reference, the receipt document) in
  `draft_artifacts`; the governance key is pinned through the reader's signer_trust keys. DR1-DR5 are the PR's levels
  integrity, authentic (ed25519 over "x402-delivery-receipt/1\n" + receiptId), trusted (directory root over RFC 8785
  with sorted keys, governance signature, epoch in force, key lifecycle at issuedAt, issuer origin = resource origin),
  settlement (against the bundle's settlement, accepted terms and recorded request), delivery (body SHA-256, or the
  sse stream digest of section 5.6 with the terminal event); DR6 the archival path needs ML-DSA-65 (FIPS 204), not
  implemented here: `not_evaluated:ml_dsa_65_not_implemented`. The PR's eight session-path expected verdicts are
  reproduced level for level and reason for reason, and its stream digest vector.
- `x402-pr3220@72c3704` authority mandates x402-mandate/1, single payment only (PR 3220 sections 3-7; the mandate
  envelope and paymentId in `draft_artifacts`): AU1 the mandate's validation rules (closed object, base64url keys,
  integer strings, perPayment ≤ cap, recipient scope never empty and "*" only alone, Model B recipients as keys,
  strict RFC 3339 notAfter with a real calendar date, well-formed UTF-16); AU2 Ed25519 over "x402-mandate/1\n" + RFC
  8785; AU3 the EIP-3009 nonce of the bundle's authorization is the binding B = SHA-256("x402-mandate-binding/1\n" ‖
  mandateDigest ‖ "\n" ‖ paymentId) (section 7: the settled slot, never a presented field); AU4 the tuple taken from the
  settled artifact (payer = subject, payTo in scope, asset, amount ≤ perPayment and ≤ cap: the PR's security fix);
  AU5 notAfter after the settlement block time (the PR asks for the verifier's clock; the evidence carries the block
  time); AU6 the spend log, committed heads, Model B and delegation are not read. The PR's model A digest,
  signature and the three binding encodings, and its model B digest, are reproduced.
- `x402-pr3868@aeb0389` correctness and dispute, the hash/signature part only (records in `draft_artifacts`, as its
  reference kit publishes them: preimage, receipt_hash, signature, notary_fp): BV1 SHA-256 of the verbatim preimage;
  BV2 Ed25519 over the hash text under the reader's key for that fingerprint; BV3 the record names this bundle's
  settlement transaction (the PR's rule 5). The bond, the adjudicator's endpoint and verdict correctness are outside
  evidence (live data). Real data: the kit's 12 receipts (stillmarcus24/notary-x402-reference-kit @e6e17a2, MIT,
  sources/notary_x402_kit_e6e17a2) verify; their fingerprint is the first 16 hex of SHA-256 over the .pub file text.
Tests: tests/test_drafts3.py.

## 25. SPEC 0.15 (draft, 2026-10-26, local; apc_authcap.py) — scheme `auth-capture` on EVM, the client's collect payload (EIP-3009), bundle `apc-0.15`

Sources (local copies with SHA256SUMS): x402-foundation/x402 main 2ff672c `specs/schemes/auth-capture/
scheme_auth_capture.md` and `scheme_auth_capture_evm.md` (v1.1, 2026-08-26; sources/x402_schemes_20261026, PIN_MAIN.txt);
base/commerce-payments v1.1.0 6b0a5ef and v1.0.0 d33b5d5 (`AuthCaptureEscrow.sol`, `TokenCollector.sol`,
`ERC3009PaymentCollector.sol`; sources/commerce_payments_v110_6b0a5ef and _v100_d33b5d5).

Bundle members: `bundle_version`, `payment_payload` (x402 v2, `accepted.scheme` = `auth-capture`, `eip155` network,
`extra` with the members the binding requires), optional `payment_required`, `settlement`, `chain_tx` = {`tx`,
`receipt`} as the RPC returns them, `provenance`, `exchange`. Every member set is closed except `accepted.extra`: the
binding's own rule is "Clients MUST ignore unrecognized extra keys", so an unknown key there is reported in the notes,
not refused. Checks (the binding's verification steps that need neither chain state nor the facilitator's clock):

- AC1 extra (step 4): the escrow is one of the two canonical deployments (absent = v1.1), `paymentFlow` is `escrow`
  or `authorization`, `autoCapture: true` refused, `captureMode` only under `escrow`, `minFeeBps` ≤ `maxFeeBps` ≤
  10000, a zero `feeRecipient` only with no fee.
- AC2 operator (step 5, offline part): `operatorType` `delegated` (default) or `custom` (`policy` is reserved:
  refused), `policy` zero, a `charge` needs a non-zero `receiverAuthorizer`. Whether the operator is admitted is the
  facilitator's state (note).
- AC3 shape (step 1): `saltNonce` present iff the bind is on; no server fields on `authorize`; a completed `charge`
  carries `amount`, the deployment's fee field (`feeAmount` v1.1, `feeBps` v1.0), `feeReceiver`,
  `authorizerSignature`.
- AC4 deadlines (step 7, static part): `refundDeadline` ≥ `captureDeadline` ≥ `validBefore`, `validBefore` a uint48,
  `validAfter` = 0 (the collector hardcodes it). The checks against "now" need the facilitator's clock (note).
- AC5 collector and amount (steps 9, 12): `authorization.to` = the deployment's ERC-3009 collector, `value` = amount.
- AC6 nonce (step 13): PaymentInfo rebuilt field by field, `signatureNonce` = getHash with payer = 0
  (keccak256(abi.encode(chainId, escrow, keccak256(abi.encode(PAYMENT_INFO_TYPEHASH, info))))) = the authorization's
  nonce; when bound, `salt` = keccak256(abi.encode(SALT_BINDING_TYPEHASH, receiverAuthorizer, policy, saltNonce)).
- AC7 client signature (step 11): ECDSA over ReceiveWithAuthorization under the token's domain recovers `from`;
  ERC-1271 and ERC-6492 forms are `not_evaluated` (chain state); high-s as Amendment 0.3.2.
- AC8 (`authorization` flow only) the charge: 0 < amount ≤ maximum, the fee inside the client-signed bounds (v1.1
  amount × bps / 10000 with the escrow's integer division; v1.0 bps), the fee receiver rule, and the `Charge`
  EIP-712 signature (domain "x402 Auth Capture Operator", "1", chainId, captureAuthorizer) recovers
  `receiverAuthorizer`.
- K4 accepted offered in `payment_required` and the same resource URL; T1 the settlement reply (success, network,
  payer, amount).
- C1 the EIP-1559 hash recomputed = the transaction's and the receipt's, and the settlement's; C2 status 1; C3 exactly
  one escrow event (`PaymentAuthorized`, or `PaymentCharged` with the deployment's fee type) with topic getHash(info)
  and data = the encoded PaymentInfo, amount and collector; C4 exactly one `AuthorizationUsed(payer, nonce)` of the
  token. No block header binds the receipt (`block_bound` false); the call path to the escrow is not decoded.
- C1, block (0.18.2, 2026-10-27, the author's decision; apc_authcap._block, tests/test_authcap_block.py): `chain_tx.tx`,
  `chain_tx.receipt` and every log of the receipt carry `blockHash` (32 bytes of hex, either case) and `blockNumber` (a
  JSON-RPC quantity as in section 6 (apc_verify._q): `0x0` or lower-case hex without leading zeros, at most 256 bits); a member missing
  or outside that grammar is a refusal with its path, whatever C1 is. The receipt's and every log's (hash, number) must
  be the transaction's (hash compared without case, number as an integer), else C1 `failed:log_block_not_tx_block`; a
  C1 not verified (failed or not_evaluated) keeps its reason. This binds the logs to the block the transaction claims,
  not that block to a header (`block_bound` stays false). Measured on the 38 real auth-capture bundles: all carry both
  members in the grammar on the three places and bind (C1 verified, verdicts unchanged in tools/regress.py); mutants
  BB01-BB08 (tools/mutants03.py).

The Permit2 collect path is section 25.1 (0.16.1). Not here: the `upto` EVM binding (Permit2 too, at the same three
places, AC5-AC7); lifecycle payloads (`capture`, `void`, `refund`) need `AuthCaptureEscrow.paymentState`, and step 15
is a simulation: both are live.

Real data (tools/fetch_authcapture.py, base-rpc.publicnode.com, read 2026-10-26; oracle/authcapture_20261026):
escrow v1.0 0xBdEA…: 503 `PaymentAuthorized` logs in blocks 52906744-53106744, the first 20 transactions saved;
escrow v1.1 0xf968…: 0 logs in 53056744-53106744, 22 logs in 51806744-52566743 (76 windows of 10000 blocks; the scan stops at 20
transactions). tools/make_bundles_authcap.py rebuilds the payment payload from the `authorize` call found in each
transaction input (all are ERC-4337 `handleOps` of EntryPoint 0x5FF137…), as the binding's facilitator derives it;
2 v1.1 transactions carry no direct `authorize` call and are left out; `maxTimeoutSeconds` is not on chain (written
0, not checked). Bundles: bundles/authcap_real_20261026 (20, v1.0) and authcap_real_v11_20261026 (18, v1.1), all
`chain_verified`: the chain is the oracle (the escrow emitted getHash of the rebuilt PaymentInfo, the token consumed
the rebuilt nonce and accepted the signature). These are commerce-payments payments, not known to be x402 ones.
Tests: tests/test_authcap.py (real bundles, breaks, a synthetic `charge` with anvil keys, generative members and
leaf types). Mutants AK01-AK24, all killed on a green bench (2026-10-26).

### 25.1 Amendment 0.16.1 (2026-10-26; apc_verify 0.16.1, apc_authcap.py, apc_batch.py) — the Permit2 collect path

Sources: scheme_auth_capture_evm.md of section 25 ("Client payment payload / Permit2", "Commerce-payments
deployments", verification steps 1-14); base/commerce-payments `src/collectors/Permit2PaymentCollector.sol` at the
same two commits (added to sources/commerce_payments_v110_6b0a5ef, MIT, and sources/commerce_payments_v100_d33b5d5,
whose file header says GPL-3.0; the logic of the two files is identical, only comments and the SPDX line differ);
Uniswap Permit2 @ cc56ad0 `PermitHash.sol`, `SignatureVerification.sol` (section 12). The collector calls
`permit2.permitTransferFrom({permitted: {token: paymentInfo.token, amount: paymentInfo.maxAmount}, nonce:
uint256(payer-agnostic hash), deadline: paymentInfo.preApprovalExpiry}, {to: tokenStore, requestedAmount: amount},
paymentInfo.payer, collectorData after the ERC-6492 handler)`: the signed bytes are defined by the pinned code.
`extra.assetTransferMethod` "permit2" selects it (any value other than "eip3009" and "permit2": refused, as before).
- Payload, closed: `{permit2Authorization: {from, permitted: {token, amount}, spender, nonce, deadline}, signature,
  salt[, saltNonce, amount, feeAmount | feeBps, feeReceiver, authorizerSignature]}` — no `authorization` member, no
  witness ("No witness struct is needed"); amount, nonce, deadline decimal uint256 under the rule of section 4.
  `preApprovalExpiry` = `deadline` (it was `validBefore` on the EIP-3009 path) in PaymentInfo, AC4, AC6.
- AC4 as section 25 with `deadline` in place of `validBefore` (`..._deadlines:deadline_after_capture`,
  `..._deadlines:deadline_not_uint48`); Permit2 has no validAfter, so the validAfter rule does not apply.
- AC5 (steps 9, 10, 12): `spender` = the deployment's PERMIT2_TOKEN_COLLECTOR_ADDRESS (v1.1 0xD69831Ae…446e, v1.0
  0x992476B9…aB26; on Base both have 4049 bytes of code, since block 50832988 (32 blocks after the v1.1 escrow) and
  29931650 (the v1.0 escrow's block), oracle/authcap_permit2_20261026/code_base.json)
  (`failed:invalid_auth_capture_evm_collector_mismatch`), `permitted.token` = asset
  (`failed:invalid_auth_capture_evm_token_mismatch`), `permitted.amount` = amount (`..._amount_mismatch`).
- AC6 (step 13): the uint256 `nonce` equals the signatureNonce of section 25 read as a big-endian integer.
- AC7 (step 11): the digest Permit2 checks, from constants: domain as section 12.2 (name "Permit2", chainId of the
  network, verifyingContract Permit2), type hash keccak256("PermitTransferFrom(TokenPermissions permitted,address
  spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"), struct (TokenPermissions
  hash, spender = the deployment's collector, the msg.sender Permit2 hashes, nonce, deadline); SignatureVerification
  for a payer without code as section 12.2 (65 bytes v 27/28 or 64 bytes EIP-2098, no low-s rule: the token never
  sees this signature, so Amendment 0.3.2 does not apply); recovering another address:
  `failed:signature_does_not_recover_the_payer`; other lengths `not_evaluated:erc1271_needs_chain_state`; the ERC-6492
  suffix `not_evaluated:erc6492_counterfactual_signature`.
- AC8 as section 25 with tokenCollector = the Permit2 collector and collectorDataHash = keccak256 of the payload's
  `signature` bytes. The scheme text says the facilitator sets collectorData to "the ABI-encoded Permit2 signature";
  the collector passes collectorData (after the ERC-6492 handler, which returns it unchanged without the magic suffix)
  to Permit2 as the signature itself, and Permit2 accepts only 64 or 65 bytes from a payer without code, so the bytes
  read here are the raw signature (the contract's reading; the wording is reported as a question, section "Open").
- C3 as section 25 with the Permit2 collector in the event data; C4: Permit2 emits no event for a signature transfer
  (SignatureTransfer.sol), so in place of AuthorizationUsed the token's Transfer(payer, *, amount) of the collected
  amount: `failed:no_transfer_of_the_amount_from_the_payer`; a second Transfer from the payer in the transaction:
  `not_evaluated:more_than_one_transfer_from_the_payer` (measured on the 38 real EIP-3009 receipts of section 25:
  exactly one Transfer from the payer in each); the recipient is the operator's token store, not recomputed here.
- Set check (apc_batch.py): the key is (network, Permit2, payer, nonce as a decimal string), the tuple of an apc-0.10
  Permit2 bundle (section 12.7): Permit2's unordered nonces are per owner across spenders, so one nonce spent by an
  exact payment and by an auth-capture collection is the same slot.
- Report member `asset_transfer_method` ("eip3009" or "permit2").
Real data (tools/fetch_authcap_permit2.py, base-rpc.publicnode.com, read 2026-10-26; oracle/authcap_permit2_20261026):
every PaymentAuthorized and PaymentCharged log of the two escrows in blocks 51010000-53111144 (211 windows of at most
10000 blocks; below block 51000000 the public endpoint answered "Archive requests require a personal token", so the
177044 blocks of the v1.1 escrow and the 21078350 of the v1.0 escrow from their deployment to block 51009999 were not
read): v1.1 74 logs, v1.0 97014 logs, all 97088 with tokenCollector = the deployment's EIP-3009 collector, 0 with the
Permit2 collector. No real
Permit2 collection was found, so section 25.1 is tested on vectors rebuilt from the sources (below), not on chain
data.
Tests: tests/test_integration.py (vectors rebuilt from the sources with anvil keys: an authorize and a charge, both
deployments, signed over the PermitTransferFrom digest of the generic EIP-712 of APC_SIGLIB, not of apc_permit2;
breaks of AC4-AC8, C3, C4; generative members and leaf types; the shared keys of the set check). Mutants GX18-GX41,
GX49-GX52.

## 26. SPEC 0.16 (draft, 2026-10-26, local; apc_xrp.py, apc_xrpl.py) — XRP Ledger: the x402 `exact` scheme, bundle `apc-0.16`

Sources (local copies with SHA256SUMS): x402-foundation/x402 `specs/schemes/exact/scheme_exact_xrpl.md`
(sources/x402_schemes_20261026); the binary codec's field table, XRPLF/xrpl.js f8c5c72
`packages/ripple-binary-codec/src/enums/definitions.json` (sources/xrpl_js_f8c5c72); XRPLF/xrpl-dev-portal 94abc77
`metadata.md` and `partial-payments.md` (sources/xrpl_dev_portal_94abc77).

apc_xrpl.py (standard library only): the binary codec, closed (an unknown field or type, a repeated field, fields out
of canonical order, a non-minimal field id, a trailing byte: refused); single signatures — secp256k1 ECDSA in strict
DER over SHA-512Half("STX\0" ‖ the signing fields) with low s required (fully canonical), Ed25519 over the same
bytes unhashed; multi-signed transactions are `not_evaluated`; the transaction id SHA-512Half("TXN\0" ‖ blob);
classic addresses (RIPEMD-160 of SHA-256 of the key, pure Python, base58 with the XRPL alphabet, round trip
required); the transaction SHAMap root (leaf SHA-512Half("SND\0" ‖ VL(tx) ‖ VL(meta) ‖ id), inner
SHA-512Half("MIN\0" ‖ 16 children), the root always inner) and the ledger header hash SHA-512Half("LWR\0" ‖ header).

Bundle members: `bundle_version`, `payment_payload` (x402 v2; `accepted` with `extra` closed to the five members the
scheme defines, `areFeesSponsored` false; `payload.signedTxBlob`), optional `payment_required`, `settlement`,
`chain_tx` = {`tx_blob`, `meta`, `ledger_index`}, `inclusion` = {`ledger_data`, `transactions`: [{`tx_blob`,
`meta`}]} (the ledger's whole transaction set), `provenance`, `exchange`. The reader's trusted ledger hash is the
same `l1_checkpoint` argument as SPEC 0.4. Checks, by the scheme's rule numbers:

- R3 `TransactionType` Payment; R4 `Destination` = payTo and the `DestinationTag` when required; R5 `NetworkID`
  absent for network ids ≤ 1024, equal above; R6 amounts: XRP drops equal with no `SendMax`, `Paths`, `DeliverMin`;
  issued currency with currency and issuer equal, the value equal in exact integer arithmetic (no float, no Decimal
  context), `SendMax` of the same currency and issuer at least the amount, no `Paths`, `DeliverMin` or
  tfPartialPayment (in the binary form the amount is `Amount`; `DeliverMax` is its API v2 JSON name); R7
  `LastLedgerSequence` present and the `Sequence`/`TicketSequence` shape of the method (the live bounds are noted);
  R8 `InvoiceID` = SHA-256(invoiceId) when required; R9 no `Delegate`, no `Memos` (the fee bound is the
  facilitator's policy, noted); R10 the signature, and its key is the account's master key (a regular key needs
  account state: `not_evaluated`).
- K4 accepted offered and the same resource URL; T1 the settlement reply (id = the recomputed transaction id).
- C1 the settled blob is the payload's blob byte for byte; C2 `TransactionResult` tesSUCCESS; C3 the delivered
  amount: `DeliveredAmount` from the metadata, or, when the binary metadata does not carry it, the `Amount` of a
  successful payment without tfPartialPayment (xrpl-dev-portal metadata.md 269); C4 validated no later than
  `LastLedgerSequence`.
- I1 the transaction and its metadata are a leaf of the set, the set's root is the header's `transaction_hash`, the
  header's index is `chain_tx.ledger_index`; I2 the header hash is the reader's trusted ledger hash (`block_bound`
  true only with both). That a validator quorum validated that ledger is the reader's trust, not checked.

Real data (tools/fetch_xrpl_ledgers.py, xrplcluster.com, read 2026-10-26; oracle/xrpl_20261026): 12 validated
mainnet ledgers, 795 transactions with their metadata. All 12 header hashes equal the server's `ledger_hash`, all 12
SHAMap roots equal its `transaction_hash`, every transaction and metadata decodes and re-encodes byte for byte,
758 single signatures verify and 37 are multi-signed. Their 99 Payments (no MPT amounts among them) are
bundles/xrp_real_20261026 (tools/make_bundles_xrp.py; requirements rebuilt from each payment; the first payment of
each ledger carries the whole set): 21 `chain_verified` (12 of the 99 block bound with the server's ledger hash as
the trusted one), 78 `chain_failed` for what x402 forbids and ordinary payments do: of the 99, 37 carry Memos, 33
have no LastLedgerSequence, 27 are partial payments, 23 fail the issued-currency SendMax policy and 14 put SendMax on
XRP, 9 did not succeed (6 tecPATH_DRY, 3 tecUNFUNDED_PAYMENT); 16 carry an InvoiceID. The binary metadata stores
DeliveredAmount in 19 of the 23 successful partial payments and in none of the 67 successful full ones; for the other
4 successful partial payments C3 reports `no_delivered_amount` (the delivered amount is then only in AffectedNodes,
not read). These are XRPL payments, not known to be x402 ones.
Tests: tests/test_xrp.py. Mutants XR01-XR36, all killed on a green bench (2026-10-26).

## 27. Amendment 0.16.1 (2026-10-26; apc_verify 0.16.1) — the every-version amendments, read version by version
The branches that built apc-0.10, apc-0.12, apc-0.13, apc-0.15 and apc-0.16 were built in parallel with sections 13-19,
and at apc_verify 0.16.0 (6b2049d) four bundle versions carried the extensions of sections 13-15 in `extensions` without
reading them, which is what those sections forbid. From 0.16.1 each cell below is what the code does, by the shared code
of apc-0.1 to apc-0.3 (apc_offer.check, apc_verify.builder_code_checks, apc_payid.check, apc_assets.info):

| | 0.1-0.3 | 0.5 Solana | 0.10 Permit2 / ERC-7710 | 0.12 Stellar | 0.13 x402 v1 | 0.15 auth-capture | 0.16 XRPL |
|---|---|---|---|---|---|---|---|
| §13 OR1-OR3 | read | read | read (0.16.1) | read; OR3 payTo as G StrKey (0.16.1) | n/a [a] | read (0.16.1), offer scheme `auth-capture` | read (0.16.1) [b] |
| §14 BC1 declarations | read | read (0.16.1) | read (0.16.1) | read (0.16.1) | n/a [a] | read (0.16.1) | read (0.16.1) |
| §14 BC1 calldata | direct call | n/a [c] | settle calldata decoded (0.16.1) | n/a [c] | as 0.3 (mapped) | absent [d] | n/a [c] |
| §15 PI1 | read | read | read (0.16.1) | read | n/a [a] | read (0.16.1) | read (0.16.1) |
| §15 D4 | read | read | Permit2 read; ERC-7710 kept out [h] | read | n/a [a] | read | read |
| §18 X2 | read | read | read | read | n/a [e] | read | read |
| §18 OR3, D4 origins | read | read | read (0.16.1) | read | n/a [a] | read (0.16.1) | read (0.16.1) |
| §18 P5 (apc_report) | read | read | read | read | read (mapped) | read | read |
| §19 `asset` member | read | n/a [f] | read (0.16.1) | n/a [f] | read (mapped) | read (0.16.1) | n/a [f] |
| §19 high-s rule | read | n/a [f] | n/a [g] | n/a [f] | read (mapped) | read (EIP-3009); n/a on Permit2 [g] | n/a [f] |

[a] the x402 v1 objects of section 21 have no `extensions` member (closed grammar: such a member is refused; from
0.21.5, in payment_required, it is ignored, named in notes and not read, SPEC 32.14), so an apc-0.13 bundle cannot
carry these extensions. [b] the XRPL transaction id is compared without case, as T1 of section
26; amounts and assets as strings. [c] ERC-8021 is EVM calldata: on Solana, Stellar and XRPL there is no suffix to
read, `not_applicable:no_erc8021_calldata_off_evm`. [d] the call path to the escrow is not decoded (section 25 C1-C4),
as an indirect call of section 4: `not_evaluated:absent:no_builder_code_calldata`. [e] section 21: `exchange` is not
read for v1. [f] not EVM: section 19 is for EVM bundle versions. [g] Permit2 verifies the signature by ecrecover with no
s rule and the token never sees it (sections 12.2, 25.1). [h] apc_batch lists an ERC-7710 bundle as kept out of
D1-D4 with its reason (no one-time authorization key, section 12.7). Section 16 (MCP, A2A) is read in apc-0.3, apc-0.5 and
apc-0.12; the other grammars refuse `exchange_mcp` and `exchange_a2a` (not built for them).
Tests: tests/test_integration.py — for every bundle version that can carry them, a bundle with each extension gets its
check (a forged offer is OR1 failed, a mismatched echo BC1 failed, a malformed id PI1 failed) where apc_verify 0.16.0
(6b2049d) left the verdict as without it (positive control: the three on apc-0.10, apc-0.15, apc-0.16, the echo on
apc-0.5 and apc-0.12); a real apc-0.10 settle call whose suffix carries a = bc_8da9xpmp (bundles/real_permit2/p029)
is BC1 verified against that declaration; OR3 by the key that names payTo on Stellar and XRPL (the XRPL rule checked on
the real master keys of bundles/xrp_real_20261026); generative members, leaf types and duplicates inside each
extension on each version. Mutants GX01-GX17, GX42-GX48 (and GX53 for the shared keys below), all killed.

## 28. SPEC 0.17 (draft, 2026-10-26, local; apc_verify 0.17.0, apc_solana.py, apc_xrpl.py, apc_webauthn.py) — the chains' own signature rules, Wycheproof, Coinbase Smart Wallet passkey owners

Every bundle version that the rules below touch is read under them from 0.17 on; no member is added to any grammar.
The principle: a signature check of a chain artifact says `verified` exactly when that chain's own code accepts the
signature, neither stricter nor wider; where our reading is narrower than the chain's code, the narrower case ends
`not_evaluated` (never `failed`), and each rule cites the pinned source it is taken from. Sources, copied with
SHA256SUMS: sources/ed25519_chains_20261026 (PROVENANCE.json names each URL and commit; crate archives checked against
the Cargo.lock checksums), sources/coinbase_smart_wallet_000100ab_libs and sources/coinbase_smart_wallet_00000110
(Sourcify exact matches), sources/wycheproof_d17cc89 (C2SP/wycheproof d17cc89, Apache-2.0, test vectors only).

### 28.1 Ed25519, one rule per chain (apc_solana.ed25519_verify `rule`)
- Solana transaction signatures (apc_svm S1, C1): agave perf/src/sigverify.rs 44-47 calls `Signature::verify`, which
  is solana-sdk signature/src/lib.rs 89-98 and 121-123, `verify_dalek` of solana-ed25519 0.2.4
  (ed_sigs/verification_key.rs 205-227, 391-428). Rule `dalek_strict`: A and R decoded as curve25519-dalek 4.1.3
  decompresses (edwards.rs 194-240: the high bit is the sign of x; field.rs 326-338: y is not required below p, so a
  non-canonical y is accepted; x = 0 with the sign bit set gives x = 0); A of small order refused; R of small order
  refused; S < L; the bytes of [S]B - [k]A encoded must equal the 32 bytes of R; k = SHA-512(R || A || M) over the
  bytes as given. The comment at lib.rs 87-88 and 111-118 says a later change (SIMD-0376) will move `verify` to the
  ZIP-215 rule: when that is in the pinned source, this rule changes with it.
- Stellar (apc_xlm, the Soroban authorization entry): the host verifies with ed25519-dalek 2.1.1 `verify_strict`
  (rs-soroban-env crypto/mod.rs 47-68 and 79-97; account_contract.rs 218-222 for the account's signatures;
  verifying.rs 161-169, 194-238, 402-425; signature.rs 92-97 with S < L since `legacy_compatibility` is not among the
  features of the workspace Cargo.toml line 27; another crate of the build could enable it by feature unification:
  not measured). Same acceptance as `dalek_strict` above.
- XRP Ledger (apc_xrpl R10): rippled PublicKey.cpp 154-170 (S < L) and 272-292 (`ed25519_sign_open` of
  ed25519-donna 2015.03 = floodyberry/ed25519-donna 8757bd4, per conanfile.py line 36 and the XRPLF conan recipe):
  ed25519.c 94-116 and ed25519-donna-impl-base.h 192-239. Rule `donna`: A decoded as above (non-canonical y accepted),
  no order test on A or R, the encoded [S]B - [k]A must equal the bytes of R.
- Every other Ed25519 check of apc (HTTP signatures, signed reports, offers and receipts, drafts, the register) keeps
  rule `rfc8032` (RFC 8032 5.1.7 with canonical encodings, cofactorless equation): those formats are ours or are
  checked against their own specifications, not a chain.

### 28.2 ECDSA rules, unchanged and measured
- EVM secp256k1 (L2.sig, ERC-1271 owners, offers): recovery of the 65-byte r || s || v (Amendment 0.3.2 for an s in
  the upper half). The vectors do not carry v: the bench tries the four recovery ids and compares with the key.
- XRP Ledger secp256k1: rippled verifyDigest with mustBeFullyCanonical true (PublicKey.cpp 224-269, PublicKey.h 240):
  strict DER (PublicKey.cpp 50-73 and 126-136), r and s in [1, n-1], s at most n/2.
- P-256 (AP2 ES256, HTTP ecdsa-p256-sha256, offers, and the WebAuthn check of 28.3): apc_ap2.es256_verify, r || s of
  64 bytes, r and s in [1, n-1], the key on the curve (checked by its callers).

### 28.3 Coinbase Smart Wallet: the second implementation, owner signatures, passkey owners
- Closed list of L2.sig-1271: the implementation 0x00000110dcdedc9581cb5ecb8467282f2926534d is added (Sourcify exact
  match `CoinbaseSmartWallet`; its _isValidSignature, ERC1271.sol, MultiOwnable.sol and libraries have the same text
  and sha256 as 0x000100ab, the difference is in validateUserOp only: sources/coinbase_smart_wallet_00000110).
- Owner an address (CoinbaseSmartWallet.sol 301-313, 322-334 in 0x00000110): the wallet calls solady
  SignatureCheckerLib.isValidSignatureNow (lines 32-112): a 64-byte signature is EIP-2098 compact (r, then v-1 in the
  top bit of the second word, lines 44-63) and a 65-byte one is r || s || v (lines 65-84); ecrecover returns nothing
  for a v other than 27 or 28. From 0.17 the 64-byte form is read (it was `failed:owner_signature_not_65_bytes_v27_28`
  before). What is not read: when the recovery does not give the owner, the library asks the owner's own ERC-1271
  (lines 85-110); an owner with code is not in the bundle, so `failed` there presumes an owner without code (open).
- Owner of 64 bytes, a P-256 key (x, y) (CoinbaseSmartWallet.sol 316-322, 337-343 in 0x00000110): signatureData =
  abi.encode(WebAuthnAuth{authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s}) (WebAuthn.sol 22-37),
  checked by apc_webauthn.verify as WebAuthn.verify(challenge = abi.encode(replaySafeHash), requireUV false):
  s at most n/2 (110-113); the 21 bytes of clientDataJSON at typeIndex are `"type":"webauthn.get"` (115-120, a
  substring: LibString.slice clamps to the length, lines 699-728); the bytes at challengeIndex are `"challenge":"` +
  base64url of the 32-byte challenge without padding (Base64.sol 27-29) + `"` (122-128); authenticatorData has a
  byte 32 (shorter: the contract reverts, which the token reads as an invalid signature) and its UP bit set
  (132-135); UV is not required (139-141 with requireUV false); then ECDSA P-256 over
  sha256(authenticatorData || sha256(clientDataJSON)) (145-162: the RIP-7212 precompile, and FreshCryptoLib when the
  precompile gives no output; both are the FIPS 186-5 verification with r and s in [1, n-1] and the key on the curve,
  FCL_ecdsa.sol 40-61, FCL_elliptic.sol 308-319; that FreshCryptoLib accepts nothing more is read from its source,
  not run). Reasons: `failed:webauthn_<reason>` with the first check that fails in that order. The ABI form of
  WebAuthnAuth is read in the one form abi.encode writes (offsets 0x20 then 0xc0, the second tail right after the
  first, zero padding, nothing after); any other form, which the contract's decoder may accept, is
  `not_evaluated:webauthn_auth_not_canonical_abi` (narrower, so not judged). What the contract does not read is
  reported in notes and never changes the verdict: the UV flag, clientDataJSON read as JSON under the rules of the
  bundle's own JSON (section 1 and 29.1: at most 64 deep, no NaN or Infinity, no unpaired surrogate; from 0.18.1) (not one object with unique
  members, a `type` or `challenge` member other than the substrings, crossOrigin, topOrigin, other members), the
  origin (WebAuthn.sol 62-96 lists what it leaves out). Result `verified (ERC-1271 CoinbaseSmartWallet, passkey)`.

### 28.4 Wycheproof (tests/test_wycheproof.py, tests/test_webauthn.py; measured 2026-10-26 on this tree)
Every vector of five files of C2SP/wycheproof d17cc89 against our code; `valid` must verify and `invalid` must not,
`acceptable` is counted by rule.
- ed25519_test.json, 210: under each of the three rules, 117 of 117 valid verify and 64 of 64 invalid are refused;
  of the 29 acceptable, the 21 mixed-order keys verify under all three, the 8 small-order keys verify under `rfc8032`
  and `donna` and are refused under `dalek_strict`. Defect of 0.16 found and corrected by 28.1: apc_svm and apc_xlm
  verified those 8 (the chains refuse them), and apc_xrpl refused a key that rippled accepts in its non-canonical
  encoding (y = p + 1 of the identity, a case built in the test since Wycheproof has none).
- ecdsa_secp256k1_sha256_bitcoin_test.json, 464, against the rippled rule: 162 of 162 valid verify, 302 of 302
  invalid are refused.
- ecdsa_secp256k1_sha256_test.json, 476, the same rule: of 168 valid, 96 verify and the 72 with s above n/2 are refused
  as not fully canonical (rippled's rule, PublicKey.cpp 235; each one's low-s twin verifies); 308 of 308 invalid are
  refused.
- ecdsa_secp256k1_sha256_p1363_test.json, 252, by recovery (x402-signature-vectors, the four recovery ids tried):
  167 of 167 valid recover the key, 85 of 85 invalid do not.
- ecdsa_secp256r1_sha256_p1363_test.json, 262: apc_ap2.es256_verify, 173 of 173 valid and 89 of 89 invalid; the
  WebAuthn step (apc_webauthn.p256_check): 103 valid verify, the other 70 valid have s above n/2 and are refused by
  WebAuthn.sol 110 (the contract's rule), 89 of 89 invalid refused.
- Also checked: apc_offer's compressed-key decoders on every key of the two r || s files. Copied and not run:
  ecdsa_secp256r1_sha256_test.json (DER), since no apc format carries a P-256 DER signature.

### 28.5 Real data (oracle/passkey_20261026, read-only RPC base-rpc.publicnode.com, 2026-10-26)
- EIP-3009 by a passkey owner: tools/scan_webauthn.py over USDC AuthorizationUsed in blocks 53091619-53093618 (2000
  blocks): 17838 logs, 11537 distinct transactions, 1 whose calldata carries a WebAuthn assertion: tx 0x43b1087a…,
  block 53093490, 15 USDC from the Coinbase Smart Wallet 0x4dfae8f6… (implementation 0x00000110, owner 0 a P-256
  key, origin https://keys.coinbase.com), through 0xa757c942… (a batch call; not in the pinned x402scan list, so an
  EIP-3009 execution not known to be an x402 one). bundles/real_v02_passkey/b001 (tools/make_bundles_v02.py
  --wallets; its validity window is found two words apart, each value the only member of an ABI array):
  `chain_verified`, L2.sig `verified (ERC-1271 CoinbaseSmartWallet, passkey)`; under apc_verify 0.16.0 (6b2049d)
  L2.sig is `not_evaluated:wallet_implementation_not_known`. The 565 wallet replies of oracle/coverage_20261022 all
  have an address owner.
- WebAuthn-layer oracles: EntryPoint v0.6 UserOperationEvent in blocks 53111319-53111618: 677 logs, 662 transactions,
  10 with an assertion in calldata, 10 operations (tools/make_webauthn_oracle.py; userOpHash recomputed = the event
  topic; wallet replies at the block; 9 on implementation 0x00000110, 1 on 0x000100ab): all 10 verify under
  apc_webauthn.verify and each altered s or challenge is refused. These are wallet operations, not payments.
Tests: tests/test_wycheproof.py, tests/test_webauthn.py (with the generative cases of 28.3 on the real bundle re-signed
by a test key). Mutants EW01-EW12, WN01-WN18, CK01-CK08 (tools/mutants03.py): 38 of 38 killed on a green bench of
the touched modules (test_webauthn, test_wycheproof, test_svm, test_xlm, test_xrp, test_apc, test_review070,
test_review071), 2026-10-26; the whole suite is the final run's.

## 29. Amendment 0.18 (2026-10-26; apc_verify 0.18.0; every bundle version) — the bundle as hostile input
A verifier run by a third party reads bundles written by whoever has an interest in deceiving it. A stall, a memory
blow-up or a traceback is a defect, and so is a traceback's exit code 1, which section 5 gives to `chain_failed`.
Section 28 (0.17) was built in parallel and is merged with this section in 0.18.1 (29.7). Every limit below is an input rule: past it the input is
refused with its reason (exit 3), or, inside an artifact that has its own failure codes, that artifact fails.

29.1 JSON nesting. In every JSON text the verifier reads (the bundle, the --http-keys and --signer-trust files, and every
JSON text a bundle carries inside a string and the verifier parses: JWS segments and SD-JWT disclosures of the AP2
mandate and of signed offers and receipts, HTTP bodies, MCP and A2A texts, draft artifacts, the WebAuthn
clientDataJSON of section 28.3 read for its notes) arrays and objects nest at
most 64 deep (apc_verify.MAX_JSON_DEPTH, counted without recursion); deeper, or deeper than the standard library parser
goes, is refused. In the AP2 evaluator (apc_ap2.py) such a text is SIGNATURE_INVALID (a JWS segment) or
DISCLOSURE_INVALID (a disclosure), and the resolution of disclosures that name disclosures stops at the same depth
(DISCLOSURE_INVALID); in the draft profile of x402 PR 3783 (the SSE terminal event and the receipt document) it is a
`VERIFIER_INPUT_*` failure of the profile.
Measured: the deepest of the 1034 corpus bundles nests 8, the deepest of the 80 Pulse AP2 cases 9. Until 0.16.1 a
value 900 deep (an extra member of payment_required, independent review 0.3.1) was read and K4 verified; it is now refused.

29.2 Binary and text bounds.
- RLP (apc_block.rlp_decode: trie nodes of B2, B3 and of the L1 state proofs): lists nested at most 16 deep
  (`rlp_nested_too_deep`), the bound counted on each list, an empty one included (0.18.3; until 0.18.2 it was counted on
  the items, so 17 lists with the innermost empty were read, independent review 2026-10-27); a receipt nests 4. A trie node is read only once its hash matches, but the bundle writes the
  header that holds the root as well, so the bound is needed before any trust.
- XRPL binary codec (apc_xrpl.decode): STObjects nested at most 10 deep, the top one included (an STArray between two
  of them is not counted: 10 objects with 9 arrays between them are read; the 6385 blobs of the corpus: 4 at most;
  rippled's own bound is not checked here); a transaction or metadata blob of more than 918744 bytes (the largest
  length a VL prefix encodes) cannot be a SHAMap leaf and is refused.
- base58 (apc_solana.b58decode): n bytes are at most ceil(n * log 256 / log 58) characters (44 for 32 bytes, 88 for 64);
  without a fixed size n is 1232 (a packet). A longer text is refused (`base58_too_long`) before the conversion, which is
  quadratic in the length (measured on 0bf2063: a 1 MiB string, more than 20 s of CPU).
- MCP (apc_mcp.py): one JSON-RPC message line is at most 2 x 64 MiB + 1 MiB; a longer line is answered with error
  -32600 and the rest of it is read and dropped, never held.
- Keccak-256 (pure Python, about 3 s of CPU per MiB): one verification hashes at most 1 MiB (apc_block.KECCAK_BUDGET,
  counted over every call, the EIP-712 digests of lib.eip712 included); more is refused. Measured: the 1034 corpus
  bundles hash 75765 bytes at most; on 0bf2063 a 6 MiB EIP-712 domain name took 17.7 and 18.4 s of CPU (two runs).
  The draft profiles (`--drafts`, section 17) hash under a budget of their own of the same size, opened after the
  merged rules (0.18.3): a profile past it has the check `budget` = `not_evaluated:keccak_budget`, and the verdict, the
  checks and the exit stay those of the merged rules, as section 17 says. Until 0.18.2 the drafts counted against the
  merged rules' budget: a chain_verified real bundle (bundles/real_v03 v002) carrying a 1 MiB compliance-fields record,
  read only by the PR 2853 profile, was refused, exit 3, with `--drafts` (independent review 2026-10-27; tests/test_hostile.py
  KeccakBudget.test_drafts_have_their_own_budget, also for the PR 3604 profile of apc_drafts2). apc_drafts.run too from
  0.18.4: its PR 3827 profile hashes the version-2 receipt for its EIP-712 signer, which the merged rules do not read;
  until 0.18.3 a receipt `transaction` of 1.2 MB turned a chain_incomplete bundle into refused, exit 3, with `--drafts`
  only (independent review 2 2026-10-27, same test). The profiles of apc_drafts, apc_drafts2 and apc_drafts3 share that one budget,
  in this order.
- RFC 9421 (apc_http.py): at most 64 signature labels in the Signature-Input and in the Signature of one message, with or
  without the reader's keys; more is refused (measured on 0bf2063: 1024 labels, each verified with the key, 3.5 and
  3.8 s of CPU in two runs).

29.3 Internal errors. An exception that no rule of this SPEC names is reported as verdict `error` with the exception's
type in `reason`, exit 3; never 0, 1 or 2. It is a defect of the verifier, not a judgement of the bundle.
A report that cannot be written (standard output closed, full or a closed pipe) is exit 74 with one line on standard
error, never 0 to 3 (0.18.3). Until 0.18.2 such a run ended with a traceback, exit 1 (= chain_failed), when the report
was longer than the output buffer (a refused bundle with a 20000-character member name, written to /dev/full), with
120 when it was shorter, and with the verdict's own exit and nothing written when standard output was closed (independent review
2026-10-27; tests/test_hostile.py InternalError.test_report_not_written_is_74). When standard error cannot be written
either, the line is lost and the exit is still 74 (0.18.4; until 0.18.3 the interpreter's last flush of standard error
made it 120, with standard output full or closed and standard error full: independent review 2 2026-10-27,
InternalError.test_report_and_stderr_not_written_is_74).

29.4 Members read past their grammar (found by the fuzzing of 29.5).
- In the JSON-RPC objects an EVM bundle carries (`chain_tx`, `inclusion`, `canonical`, `payer_wallet`, `payer_code` of
  apc-0.1, 0.2, 0.3, 0.10, 0.13, 0.15) no string begins with "0X": JSON-RPC hex is "0x" followed by hex digits, the
  digits compared with case ignored (the rule of Amendment 0.3.2 for payer_wallet, now for every RPC object). Until
  0.16.1 the members read were lower-cased before comparison: measured on 0bf2063, of 357 member paths (one per bundle
  version and path, list indices merged, on the first chain_verified corpus bundle that carries it) 290 are read (one
  hex digit changed changes the report) and 55 of those, in apc-0.1, 0.2, 0.3, 0.10 and 0.15, took "0X" as "0x".
- apc-0.5: in `chain_tx.meta` pre/postTokenBalances, `owner` and `programId` are canonical base58 of 32 bytes,
  `uiTokenAmount.decimals` an integer 0..255, `uiAmount` a number or null, `uiAmountString` a string; until 0.16.1 they
  were accepted with any value.
- apc-0.15: the escrow's PaymentAuthorized or PaymentCharged log has exactly two topics (one indexed parameter in
  AuthCaptureEscrow.sol, commerce-payments v1.0.0 and v1.1.0); until 0.16.1 a log with more topics was taken (C3).

29.5 Fuzzing (tools/fuzz_bundles.py, standard library). From the real bundles of regress/VERDICTS.json (and, with
`seeds`, bundles the test helpers build for the members no corpus bundle carries), case i of seed S is drawn by
random.Random("S:i") alone and run as the command line runs it in a forked child with RLIMIT_AS, RLIMIT_CPU and an alarm.
Families F01-F14 (new members at every level, wrong types, duplicate members, numbers, long strings, hex forms, unicode
and invalid UTF-8, deep nesting, lists past their bound, binary blobs truncated or with false lengths, inflated proofs,
the declared equivalence of member order and whitespace, deleted members, file level). A case is a defect when the
child crashes, exits outside 0-3 or against its verdict, is `error`, passes 5 s of CPU or 2 GiB, turns a base that is
not chain_verified into chain_verified (unless more of its checks are `not_evaluated:absent:` than the base's: an
artifact taken away, which section 5 lists and does not judge), or changes a verdict under the declared equivalence. Defect cases are written
under --out (default fuzz_found/, not tracked); a case kept as a test is rewritten into tests/fuzz_cases as (base
bundle, path, value, expected verdict), which tests/test_hostile.py rebuilds and runs.
Tests: tests/test_hostile.py — each limit at its value and one past it, the fuzz cases, the members of 29.4; 41 tests
in 0.18.0, 48 in 0.18.4. Run on apc_verify 0.16.1 (0bf2063) with this tree's tools/fuzz_bundles.py and tests/fuzz_cases
added (0bf2063 has neither), 38 of the 48 fail (0.18.0: 31 of 41); the 10 that pass there are the 8 of ExistingLimits
(limits that were already in the code), the harness test and the control that text outside the RPC objects may begin
with "0X". Measured on 2026-10-26: 4600 cases (seeds s7, 600, and s8, 4000), no defect left; the one
s8 flagged (case 2204, chain_tx deleted from a failed Solana bundle) is section 5's `absent`, and the harness now says
so.

29.6 Found by the full test suite on the way (not hostile input). Amendment 0.3.2 (failed-but-executed: the T1 note
says whether the transaction a failed reply names is the one chain_tx carries) is read in apc-0.10 too; until 0.16.1
its note omitted it (tests/test_failed_but_executed.py, the 5 settled bundles of bundles/real_permit2). The tests that
read bundles/real* take them by a closed table of bundle versions (tests/test_apc03.REAL_KINDS): a bundle of a
version not in the table fails the tests, so a new directory of another chain is never read by the EVM tests in silence
(bundles/real_negatives_20261026 had brought apc-0.5 and apc-0.16 bundles into their glob).

29.7 Merge of 0.17 and 0.18 (0.18.1, 2026-10-27, apc_verify 0.18.1). Section 28 and this section were built in parallel from
apc_verify 0.16.0 and merged; the rules of both apply to every bundle version. One defect of the class of 29.1 was in
the 0.17 code: apc_webauthn.notes read clientDataJSON (a text the bundle carries inside the WebAuthnAuth of L2.sig) by
json.loads without the bound. Measured on the merged tree before the correction: a passkey bundle that verifies, with a
member of clientDataJSON nested 100000 deep, ended `error` (exit 3), and one nested 65 deep or holding NaN was read as
a JSON object. From 0.18.1 that text is read as the bundle's own JSON is (section 28.3); past the rules it is the note
"not one JSON object", and the verdict is the contract's, as section 28.3 says. Tests:
tests/test_webauthn.HostileClientDataJSON; mutants WN19, WN20. The bundles of bundles/real_v02_passkey (apc-0.2) are
in the frozen corpus of tools/regress.py from 0.18.1 (1036 bundles); against the corpus frozen under 0.16.1 the merged
verifier differs only by those 2 added bundles.

29.8 Found by the final bench of 0.18.1 (2026-10-27; no rule on bundles and no verdict changes, apc_verify stays
0.18.1). The rule of 29.6 binds every program of this repository that reads the real bundles to measure something,
not only the tests: the real bundles are taken by tests/test_apc03.real_bundles (the closed table REAL_KINDS, sorted),
never by a glob of bundles/real*, and a bundle of a version not in the table stops the program. real_bundles reads
bundles/real*/*.json, one level: 784 of the 1036 bundles of the frozen corpus. The other 252 real bundles
(xrp_real_20261026 99, real_world_20261026/*/ 90, xlm_real_20261026 25, authcap_real_20261026 20,
authcap_real_v11_20261026 18) are outside it and are read by name by their own tests; a bundle of an unknown version
placed there does not stop the programs above (independent review 2026-10-27). Measured on 5211620
before the correction: tools/equiv_x04.py (the X04 equivalence) read bundles/real*/*.json, so also the 562 Solana
(apc-0.5) and XRPL (apc-0.16) bundles that carry settlement and chain_tx (2430 cases, EQ differs 0, PC differs 245;
on the EVM bundles alone 1306 cases, EQ differs 0, PC differs 245); tools/equiv_mutants.py c3 read
bundles/real_v0[23]*/*.json in the file system's order (159 files read, the 98 indirect calls among them taken, one
of them the indirect bundle of bundles/real_v02_passkey, which entered in 0.18.1 without being named); tools/equiv_r02.py read bundles/*/*.json,
every directory, real or not, of every chain (946 bundles; 4180 cases, EQ differs 0, PC differs 2992; on the 222 real
EVM bundles the same 4180 cases and counts); tests/test_self_payment and tests/test_removed read the globs real* and
real_v0*. Each now takes real_bundles; tests/test_equiv_tools.py (the set each tool reads, and a bundle of version
apc-0.99 added in a copy stops each), mutants EQ01, EQ02, EQ03 (tools/mutants03.py).

## 30. Amendment 0.19 (2026-10-27; apc_verify 0.19.0), revised by 0.19.1 (2026-10-27; apc_verify 0.19.1; every bundle version) — the evidence level of a verdict, the facilitator's reply apart

Why. Section 5: a check whose artifact the bundle does not carry is `absent` and does not block. So `chain_verified`
(exit 0) is the verdict both of a bundle that carries only the payment payload with a verified payer signature and of
one that carries the settlement reply, the transaction and its logs, the inclusion proofs and the L1 replies of a final
game; a reader of the exit code alone does not see the difference. Measured on apc_verify 0.18.4 (5cb05bf): the first
bundle of bundles/real_v03_canonical reduced to `bundle_version` and `payment_payload` is `chain_verified`, exit 0,
with 20 checks absent; the whole bundle is `chain_verified`, exit 0, block_bound true, canonical final. Of the 1036
bundles of the frozen corpus (run as tools/regress.py runs them), 405 are `chain_verified` on 5cb05bf: 48 of them
block_bound, 22 canonical final.

What 0.19.1 changes in 0.19.0 (the report member and the option only; no check, verdict or exit without the option):
(a) the settlement reply of the facilitator is DECLARED (section 2) and is no longer a level below the transaction: it
is the report member `facilitator_reply`, apart; the levels take names that do not presume a chain, and the level of
the rail's own record (`settlement_record`) no longer needs the reply; (b) the highest level needs the L1 replies
PROVEN (`l1_state` proven, Amendment 0.4), not only declared; (c) a qualified outcome `verified (…)` counts only when
it is in a closed list, version by version (30.4). The names of 0.19.0 map as: `none` -> `none`, `signature` ->
`signature`, `facilitator_claim` -> (no level: `facilitator_reply` verified), `rpc_data` -> `settlement_record`,
`block_bound` -> `inclusion_proof`, `canonical` -> `finality_proven` only with `l1_state` proven, else
`inclusion_proof`.

30.1 Report members `evidence_level` and `facilitator_reply`. Every report whose verdict is `chain_verified`,
`chain_incomplete` or `chain_failed`, of every bundle version, carries both. A report whose verdict is `refused`,
`unsupported` or `error` carries neither.

`evidence_level` is one of five ordered levels:
`none` < `signature` < `settlement_record` < `inclusion_proof` < `finality_proven`.
A level holds only when every level below it holds; the member is the highest level that holds. With verdict
`chain_failed` it is `none`. A check counts for a level when its outcome is `verified`, or a qualified outcome
`verified (…)` that the closed list of 30.4 names for that bundle version and that check. Any other outcome
(`not_applicable:`, `pending:`, `not_evaluated:` absent or not, `failed:`, a `verified (…)` outside the list), or a
check missing from the report, does not count; a `verified (…)` outside the list adds the note "evidence_level: CHECK
outcome OUTCOME is not in the closed list of SPEC 30.4 for VERSION: it does not count". The names say what kind of
record stands behind the payment, not on which rail: a rail other than a chain (a bank transfer, for example) would
name its own checks in a row of 30.2 under the same levels. In general terms (30.2 gives the checks of each version):
- `signature`: the payer's signature (or authorization) over the payment terms is verified, with the checks that tie
  the signed terms to `accepted` (payee, amount, asset, network).
- `settlement_record`: in addition, the rail's record of the settlement that the bundle carries (for a chain: the
  transaction with its logs or metadata, RPC data DECLARED, section 4) is bound to the authorization the payer
  signed: the chain checks of the version are verified. The facilitator's reply is not needed: a bundle the payer
  puts together from the chain alone, with `chain_tx` and without `settlement`, reaches this level (measured, 30.5).
- `inclusion_proof`: in addition, the report member `block_bound` is true.
- `finality_proven`: in addition, the report member `canonical` is `final` AND the report member `l1_state` is
  `proven` (Amendment 0.4: the eight L1 replies proven from the L1 block hash the reader trusts, `--l1-checkpoint`).
  A report with `canonical` `final` and `l1_state` `not_shown` or `failed` (the L1 replies only declared) stays at
  `inclusion_proof` and carries the note "evidence_level inclusion_proof: canonical final rests on L1 replies the
  bundle carries, declared (l1_state STATE); finality_proven needs l1_state proven (SPEC 30.1)".

`facilitator_reply` is the settlement reply the bundle carries (DECLARED by the facilitator, section 2), read from the
facilitator checks of the version (30.2): T1 and T2, or T1. It is outside the ladder: the level never reads it, it
never changes the verdict, and it is reported whatever the verdict (`chain_failed` too). Its value:
- `absent`: every facilitator check is `not_evaluated:absent:no_settlement` (the bundle carries no settlement);
- `failed`: one of them is `failed:…`;
- `verified`: every one of them counts (as for a level, above);
- `not_evaluated`: any other case (for example `not_evaluated:settlement_pending`,
  `not_evaluated:settlement_pending_executed_on_chain`, a facilitator check missing from the report, a `verified (…)`
  outside the list).
The four cases do not overlap (a `failed:` outcome neither counts nor is absent).

Both members are computed from the report of the merged rules before the draft profiles run: `--drafts` never changes
them (section 17). The level is not a verdict: the checks outside its columns (30.2) decide the verdict as before, and
a `chain_incomplete` report may carry any level from `none` to `finality_proven` (for example a bundle with a mandate,
M1).

30.2 The checks of each level, by bundle version (each cell names the checks of the section cited; "—" says the
version has no artifact for that level, so its highest level is the last one before). The column "without settlement"
says which part of a chain check compares with the facilitator's reply: that part is made only when the bundle
carries `settlement`; every other part of the check is made without it, so no check of the `settlement_record` column
needs the reply (the check rules are those of the sections cited, unchanged by this amendment).

| version | signature | settlement_record | inclusion_proof | finality_proven | facilitator_reply | highest | without settlement |
|---|---|---|---|---|---|---|---|
| apc-0.1 | L2.sig (section 3), K1, K2, K3 (section 4) | C2, and C1 (section 4; an indirect call is C1 failed in 0.1) | — (no `inclusion` in 0.1) | — | T1, T2 (section 4) | settlement_record | C2: the transaction hash equal to settlement.transaction is not compared; C1 (the arguments and signature bytes of the call = the signed authorization) and the rest of C2 are made |
| apc-0.2 | L2.sig (`verified`, or `verified (ERC-1271 …)` under rule L2.sig-1271 of section 3 or rule 32.6 of section 32: the check is reported as L2.sig in every case), K1, K2, K3 | C2, and either C1 or C1 `not_applicable:indirect_call` with C3 (sections 4 and 5) | — (no `inclusion` in 0.2) | — | T1, T2 | settlement_record | as apc-0.1; C3 (the token's Transfer log: from, to, value) is made |
| apc-0.3 | as apc-0.2 | as apc-0.2 | `block_bound` (B1-B4, section 6) | `canonical` final (O1-O4, section 6) and `l1_state` proven (L1, Amendment 0.4) | T1, T2 | finality_proven | as apc-0.2 |
| apc-0.13 | as apc-0.3, on the apc-0.3 bundle the v1 objects map to (section 21) | as apc-0.2 | `block_bound` (section 6) | `canonical` final and `l1_state` proven | T1, T2 | finality_proven | as apc-0.2 |
| apc-0.10 Permit2 | L2.sig (12.2, or its payer-code forms of 12.5), K1, K2, K3, K7 (12.2) | C2, and either C1 or C1 `not_applicable:indirect_call` with C3 (12.2) | `block_bound` (12.7) | `canonical` final and `l1_state` proven (12.7) | T1, T2 | finality_proven | C2: the transaction hash equal to settlement.transaction is not compared; C1, C3 and the rest of C2 are made |
| apc-0.10 ERC-7710 | — (L2.sig, K1, K2, K3 are `not_evaluated:erc7710_permission_context_opaque`, 12.3) | (C1-C3 of 12.3) | (12.7) | (12.7) | T1, T2 | none | as apc-0.10 Permit2 |
| apc-0.5 | S1 (signatures of the required signers), S2 (the transfer: mint, payTo's token account, amount) (section 7) | C1, C2, C3 (section 7) | — (`block_bound` false for every apc-0.5 bundle) | — | T1 | settlement_record | C2: settlement.transaction naming another transaction is not compared; C1 (the confirmed transaction is the payload's), the rest of C2 (meta.err) and C3 (the balance delta) are made |
| apc-0.12 | G1 (the transfer: asset, payTo, amount), G2 (the payer's Ed25519 authorization entry) (section 20) | C1, C2, C3 (section 20) | — (`block_bound` false) | — | T1 | settlement_record | C2: as apc-0.5; C1 (the operation and its auth entries are the payload's), the rest of C2 (status, result) and C3 (the transfer events) are made |
| apc-0.15 | AC5 (collector, amount), AC6 (nonce = the PaymentInfo hash), AC7 (the client's signature) (sections 25, 25.1) | C1, C2, C3, C4 (sections 25, 25.1) | — (`block_bound` false, section 25) | — | T1 | settlement_record | C1: settlement.transaction naming another transaction is not compared; the rest of C1 and C2-C4 are made |
| apc-0.16 | R3, R4, R5, R6 (type, destination, network id, amounts), R10 (the signature by the master key) (section 26) | C1, C2, C3, C4 (section 26) | `block_bound` (I1 and I2, I2 against the reader's trusted ledger hash `--l1-checkpoint`, section 26) | — (no finality rule beyond the reader's trusted hash) | T1 | inclusion_proof | nothing: C1-C4 do not read settlement (the transaction id is compared with settlement.transaction in T1) |

What a level does not say. `settlement_record` rests on RPC data carried by the bundle (section 4 C2: not shown to be
on the canonical chain). `inclusion_proof` binds to a block hash, not to the canonical chain (section 6); in apc-0.16
it rests on the ledger hash the reader trusts. `finality_proven` rests on the L1 block hash the reader trusts
(`--l1-checkpoint`), from which the eight L1 replies are proven. No level says what the facilitator replied:
`facilitator_reply` does.

30.3 Option `--require-level LEVEL` (apc_verify.py), LEVEL one of `signature`, `settlement_record`,
`inclusion_proof`, `finality_proven`. Every report that carries `evidence_level` then carries `evidence_required`:
`{"level": LEVEL, "met": true}` when evidence_level is LEVEL or above, else `{"level": LEVEL, "met": false}`. A
verdict `chain_verified` with `met` false becomes `chain_incomplete` (exit 2), with a note naming both levels; no
other verdict changes (`chain_failed` stays `chain_failed`, `chain_incomplete` stays `chain_incomplete`, `refused`,
`unsupported` and `error` carry neither member). `facilitator_reply` is not a level and no value of the option reads
it. `none`, the names of 0.19.0 that are not names of 0.19.1 (`facilitator_claim`, `rpc_data`, `block_bound`,
`canonical`), any other value or a missing value is a usage error (exit 64). Without the option the report carries no
`evidence_required`, and verdicts, checks and exit codes are those of 0.18.4 (tools/regress.py check, 30.5).

30.4 Closed lists. (i) The cells of 30.2 are apc_verify.EVIDENCE_RULES, keyed by bundle version. A version the
verifier reads without a row there is an internal error of the verifier (verdict `error`, exit 3, section 29.3), never
a level read in silence; tests/test_evidence_level.py checks that the rows are exactly the versions apc_verify
dispatches. (ii) The qualified outcomes that count are apc_verify.EVIDENCE_QUALIFIED, keyed by bundle version and
check, each matched whole:
- apc-0.1: K3 `verified (by L2.sig)`.
- apc-0.2 and apc-0.3: L2.sig `verified (ERC-1271 CoinbaseSmartWallet)` and `verified (ERC-1271 CoinbaseSmartWallet,
  passkey)` (the implementations of section 28.3) and `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)` (section 32,
  from 0.21); K3 `verified (by L2.sig)`.
- apc-0.13: those of apc-0.3, and K2 `verified (v1: value N exceeds maxAmountRequired M)`, N and M decimal (section 21).
- apc-0.10: L2.sig `verified (ERC-1271 Kernel 0.3.3 by EIP-7702)` and `verified (ERC-1271 EIP7702StatelessDeleGator
  by EIP-7702)` (12.5); K3 `verified (token; chainId by L2.sig)` (12.2).
- apc-0.5, apc-0.12, apc-0.15, apc-0.16: none (only `verified` counts).
Qualified outcomes the verifier writes in no column of 30.2, so outside the list: K4 `verified (v1: the requirement is
read from payment_required)` (apc-0.13) and the draft profile check CF4 `verified (signer …)` (section 24, in
`drafts`). tests/test_evidence_level.py checks that every `verified (` form the source of apc_*.py writes is in the
list or among these two, and that every form of the list is written by the source.

30.5 Census (measured 2026-10-27 on this tree, apc_verify 0.19.1; the 1036 bundles of the frozen corpus run as
tools/regress.py runs them, options of its DIRS, so bundles/real_v04_l1state with `--l1-checkpoint`;
evlevel_abc/dumpfull.py (the author's local records, not distributed) and analyse.py). Bundles by version and evidence_level (a refused bundle
carries no level):

| version | none | signature | settlement_record | inclusion_proof | finality_proven | refused | total |
|---|---|---|---|---|---|---|---|
| apc-0.1 | 1 | 1 | 123 | — | — | 10 | 135 |
| apc-0.2 | 0 | 0 | 121 | — | — | 0 | 121 |
| apc-0.3 | 4 | 0 | 0 | 38 | 8 | 0 | 50 |
| apc-0.5 | 68 | 0 | 44 | — | — | 0 | 112 |
| apc-0.10 | 1 | 0 | 3 | 2 | 0 | 0 | 6 |
| apc-0.12 | 18 | 0 | 7 | — | — | 0 | 25 |
| apc-0.13 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| apc-0.15 | 0 | 0 | 38 | — | — | 0 | 38 |
| apc-0.16 | 528 | 0 | 21 | 0 | — | 0 | 549 |

By version and facilitator_reply:

| version | verified | failed | absent | not_evaluated | refused | total |
|---|---|---|---|---|---|---|
| apc-0.1 | 124 | 1 | 0 | 0 | 10 | 135 |
| apc-0.2 | 121 | 0 | 0 | 0 | 0 | 121 |
| apc-0.3 | 46 | 4 | 0 | 0 | 0 | 50 |
| apc-0.5 | 46 | 66 | 0 | 0 | 0 | 112 |
| apc-0.10 | 6 | 0 | 0 | 0 | 0 | 6 |
| apc-0.12 | 25 | 0 | 0 | 0 | 0 | 25 |
| apc-0.13 | 0 | 0 | 0 | 0 | 0 | 0 |
| apc-0.15 | 38 | 0 | 0 | 0 | 0 | 38 |
| apc-0.16 | 90 | 459 | 0 | 0 | 0 | 549 |

By verdict: the 601 `chain_failed` are `none` (reply failed 530, verified 71); the 20 `chain_incomplete` are `none` (19)
or `signature` (1: bundles/real_world_20261026/base_eurc, C1 `not_evaluated:unrecognized_trailing_calldata`), reply
verified in all 20; the 405 `chain_verified` are settlement_record 357, inclusion_proof 40, finality_proven 8, reply
verified in all 405. From 0.19.0 (caf7a0d) to 0.19.1, report by report: rpc_data 357 -> settlement_record,
block_bound 26 -> inclusion_proof, canonical 22 -> finality_proven 8 (bundles/real_v04_l1state, l1_state proven) and
inclusion_proof 14 (bundles/real_v03_canonical, l1_state not_shown, each with the note of 30.1),
facilitator_claim 1 -> signature (base_eurc), none 620 -> none. The qualified outcomes in the columns of 30.2 on the
1036 reports are all in the list of 30.4: K3 `verified (by L2.sig)` (apc-0.1 125, apc-0.2 121, apc-0.3 50), K3
`verified (token; chainId by L2.sig)` (apc-0.10 5), L2.sig `verified (ERC-1271 Kernel 0.3.3 by EIP-7702)` (apc-0.10
2), L2.sig `verified (ERC-1271 CoinbaseSmartWallet)` (apc-0.2 2, apc-0.3 8) and `verified (ERC-1271
CoinbaseSmartWallet, passkey)` (apc-0.2 1); none outside it, so no note of 30.4 in the corpus.
Every corpus bundle carries a settlement and a `chain_tx`, so no corpus bundle has the reply absent. The payer's own
bundle (30.1 a), measured on all 1036: each bundle without `settlement` (and without `provenance` for the 587 whose provenance
names settlement: 38 apc-0.15, 549 apc-0.16; G6 of section 8 lets it name only members the bundle carries) gives facilitator_reply `absent` in the 1026 that
are read, the same verdict and the same evidence_level in 1025, and no check other than T1/T2 differs in any of the
1036; the one change is bundles/real_issue1062 (the reply says failed, the chain executed it, x402 issue 1062):
`chain_failed`/none with the reply, `chain_verified`/settlement_record without it. The 10 refused stay refused
(chain_tx without log_authorization_used, apc-0.1). The apc-0.16 bundles are run without a trusted ledger hash (as
tools/regress.py runs them), so none is inclusion_proof here; with the ledger hash the server gave,
bundles/xrp_real_20261026/0357d4c313ea is (test). No apc-0.13 bundle is in the corpus; the v1 forms of the first
bundles of bundles/real_v03_canonical and bundles/real_v04_l1state are inclusion_proof and (with the reader's L1 hash)
finality_proven (test).
Without the option nothing else changed: tools/regress.py check, 1036 bundles, 0 differences (it compares verdict,
exit, checks and verifier; the two members are not frozen there); the 1036 reports of caf7a0d (0.19.0) and of this
tree differ by `verifier` (1036), `facilitator_reply` (1026, new), `evidence_level` (406: every value but `none`
renamed or moved) and `notes` (14: the note of 30.1 on the canonical final with l1_state not_shown, nothing else); exit,
verdict, checks and every other member equal. `--drafts` on the 1036 bundles gives the same exit, verdict, checks,
evidence_level and facilitator_reply as without. `--require-level` (require_level on the 1036 reports, as main applies
it): `finality_proven` turns 397 chain_verified into chain_incomplete and leaves 8; `inclusion_proof` 357 and 48;
`settlement_record` and `signature` 0 and 405; the 601 chain_failed and 20 chain_incomplete keep their verdict
(`met` false, except `signature` met on base_eurc), the 10 refused carry no member; checks and evidence_level
unchanged in all.

30.6 Tests and mutants (measured 2026-10-27 on this tree). tests/test_evidence_level.py, 28 tests: real bundles of
each (version, verdict, level, reply) the corpus holds; finality (canonical final with l1_state proven, not_shown,
failed, the proofs taken out); the v1 forms; XRPL inclusion_proof with the server's ledger hash; ERC-7710; each
level's artifact taken out of real bundles of every version; the payer's own bundle (settlement out) on a real
bundle of every version, with `--require-level settlement_record`; the reply's four values; the closed list of
qualified outcomes against the `verified (` forms written by the source of apc_*.py (AST), matched whole, and a form
outside the list (no count, the note); the table of 30.2 cell by cell; --require-level on every level ×
requirement, the other verdicts, usage (the names of 0.19.0 included); --drafts; the closed tables; random removal of
artifacts (seed 20261028, 113 steps, 40 refused; 30 of the steps take out settlement between verdicts other than
chain_failed): the level never rises while neither
verdict is chain_failed, taking out settlement never changes it, and the reply is absent once settlement is out.
tests/test_spec30_table.py, 6 tests (first written by a second reviewer, commit 94f5e82 of its clone, revised here): the table
of 30.2 and the list of 30.4 read as text against apc_verify.py read as text. Positive control: on caf7a0d 26 of the
28 and 6 of the 6 fail. Python 3.9.25, 3.11.2, 3.13.15: both files OK. Python 3.11.2, whole suite one file at a
time: 52 files, 807 tests, OK (run 2026-10-27 23:39 on the sources of this tree; the one file changed after it is
tests/test_evidence_level.py, the block_bound cases of the members-read test, and that file is OK on this tree on the
three Pythons; second review 2026-10-28: 11 of the 52 files re-run on this tree, 209 tests OK). Mutants EL01-EL42 (tools/mutants03.py; EL01-EL25 of 0.19.0 retargeted to the 0.19.1
lines, EL26-EL42 on the new ones; control on the unmutated copy passes first): 42 killed; EL15 (block_bound truthy)
lived in the first run and is killed since the test of the members read sets block_bound to 1 and "true".

## 31. SPEC 0.20 (draft, 2026-10-31, local; apc_verify 0.20.0, apc_mandate.py; bundle versions apc-0.1, apc-0.2, apc-0.3, apc-0.13 read as v2, and apc-0.5 by 31.9) — the AP2 mandate as an ap2-evidence-pack, its restrictions, and the payment (MP1-MP7)

**Sources, read 2026-10-31.** AP2 at `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (the head of `main` that day, by the
GitHub API; local clone): `docs/ap2/payment_mandate.md`, `agent_authorization.md`, the schemas
`code/sdk/schemas/ap2/{open_payment_mandate,payment_mandate}.json` and `types/*.json`, the SDK
(`code/sdk/python/ap2/sdk/{mandate,constraints,payment_mandate_chain}.py`). ap2-evidence-pack 1.7.1 (tag `v1.7.1`,
commit `158047d81c1082603312ab381013343bf39e8c95`; `ap2_evidence.py` SHA-256
`d128823a049d522aabfe8ec70806db4db984f7aa93b4487b70bf7905b4bfb39a`, `pqcrypto/sigsuite.py`
`7b9126ad6530777c2fc18333186593a6b71d928e165b93107e4cdbf6ed27792b`), its SPEC §2, §4, §6, §11.

**What AP2 says about x402, and what it does not.** The normative documents and the schemas of AP2 at `e1ea56d` do not
name x402. The only binding of an AP2 Payment Mandate to an x402 payment is in a SAMPLE, not normative:
`code/samples/python/src/roles/x402_credentials_provider_mcp/server.py` (lines 162-215) signs an EIP-3009
`TransferWithAuthorization` whose `nonce` is `keccak256` of the presented mandate chain as text (`Web3.keccak(text=
mandate_chain)`, the `~~`-joined string the shopping agent persisted), whose `value` is meant to be the closed mandate's
`payment_amount.amount` (minor units of USD) times 10 000 (USDC, 6 decimals), and whose `to` is meant to be
`payment_instrument.payee_address`. Measured 2026-10-31 with the SDK's generated models (pydantic 2.12.5):
`payee_address` is not a field of `PaymentInstrument` and is dropped when the sample builds the instrument, so the signed
mandate does not carry it; the sample's credentials provider then reaches its `except AttributeError` branch, which
sets the default merchant address AND `amount_cents = 1250` (lines 147-160). Reproduced 2026-10-31 by running the
sample's own `issue_payment_credential` (isolated venv: web3 7.15.0, fastmcp 3.1.0, mcp 1.26.0, pydantic 2.12.5; no
network): mandates of 999 and 250000 cents with a `payee_address`
0x1111…1111 both gave an authorization of value 12500000 (12.50 USDC) to the default 0x7099…79C8. The same defect
was reported upstream on 2026-07-15 (AP2 issue #299; fixes proposed in pull requests #300, #329 and #333, open on
2026-11-01). This section therefore takes from the sample ONLY the nonce rule,
which the sample applies on every path, and states its own reading for the amount; the payee is bound only where the
signed mandate names an address (MP4).

**Bundle member** (the versions listed above):
```
mandate: {"profile": "ap2-evidence-pack/1.7.1", "pack": <an ap2-evidence-pack/1.0 pack, one JSON object>,
          "chain": <string: the presented AP2 Payment Mandate chain, open hop "~~" closed hop>}
```
closed (a missing or other member is refused with its path). In apc-0.10 (Permit2, ERC-7710: no EIP-3009 nonce) the member keeps the outcome of section 9 for a profile
other than Pulse (`not_evaluated:ap2_has_no_x402_binding`); apc-0.5 (Solana) reads it with the binding of 31.9; apc-0.12,
apc-0.15 and apc-0.16 do not take the member (refused: unknown member). `pack` is serialized by apc with the strict parser it was
read with, RFC 8785 is NOT applied: the verifier of ap2-evidence-pack reads the bytes apc writes from the parsed object
(`ensure_ascii=False`, compact separators), as its own `restriction` command does with its private copy (§11.2 of
that SPEC). `chain` is at most 65 536 characters of ASCII (it is hashed with Keccak-256, inside the
budget of section 29.2). The `pulse-ap2-x402/0.3` profile of section 9 (M1) is unchanged; a
bundle carries one `mandate`, so M1 and MP1-MP7 never both apply: with this profile M1 is
`not_applicable:mandate_profile_ap2-evidence-pack/1.7.1` in apc-0.1, apc-0.2, apc-0.3 and apc-0.13 (apc-0.5 has no M1).

**Implementation.** The pack is verified by ap2-evidence-pack itself (`verify_restrictions`, which runs `verify_evidence`
with the default policy on one snapshot and then evaluates §11), loaded from the directory `APC_AP2EV` names — with the
variable unset, since 0.21.2 (32.11), from `../ap2-evidence-pack` beside the verifier's folder; apc
computes the SHA-256 of `ap2_evidence.py` and `pqcrypto/sigsuite.py` (read as regular files; since 0.21.3 the bytes it
runs, 32.12 (e)) and evaluates MP1-MP7 only when both equal the
values above (otherwise every MP check is `not_evaluated:ap2_evidence_pack_not_1.7.1`, and the hashes are reported);
no directory (`APC_AP2EV` unset and no sibling), a pack that does not import (it needs the `cryptography` package), or a
module `ap2_evidence` (since 0.21.3 also `sigsuite`) already loaded from another place, gives
`not_evaluated:ap2_evidence_pack_unavailable`, and since
0.21.2 the note names the cause in words (32.11); a check ap2-evidence-pack could not run (its exit 74, e.g.
an `--ap2-tsa-cert` that is a FIFO) gives `not_evaluated:ap2_evidence_pack_check_not_run` for every MP check. The
evaluation of AP2 constraints (MP3, MP5) is written in apc from the AP2 text; the SDK is a test oracle (31.8), never run
by the verifier.

### 31.1 MP1 — the pack
`verified` when the receipt has `admission` `admitted` and `valid` true; else `failed:ap2_pack_not_valid` with the
receipt's `admission` and `refusal_class` in a note. A pack that does not verify is evidence of
nothing: MP2-MP7 are then `not_evaluated:ap2_pack_not_valid`. Reported (member `mandate` of the report): `admission`, `valid`,
`time_anchor`, `existed_by` of the §11 receipt, `self_asserted_only` of the `verify_evidence` receipt on the same private
file, the hashes of the two loaded files. MP1
verified says what §6 of ap2-evidence-pack says — every artifact's ES256 signature under its snapshotted key, its
disclosures, its KB-JWT when present, the bindings — and NOT who the keys belong to (`self_asserted_only`, §6 step 7 of
that SPEC).

### 31.2 MP2 — the chain is in the pack and is one delegation
`chain` splits on `~~` into exactly two segments (the SDK's `PaymentMandateChain.parse` takes exactly two payloads), else
`failed:chain_not_two_hops`. The first segment, as written or with the final `~` the join strips put back,
equals the `sd_jwt_compact` of exactly one artifact O of the pack (the SDK's `_canonical_chain_segment` puts it back unless
the last `~`-separated part is a compact JWT, so it reads an SD-JWT without disclosures, `h.p.s~` joined as `h.p.s`, as
a JWT; the pack holds each token as issued: independent review 2026-10-31, on 3df1e7d such a hop was
`failed:chain_hop_not_in_pack`); the second equals that of exactly one artifact C (`failed:chain_hop_not_in_pack`, `failed:chain_hop_in_pack_twice`). Then,
in this order (each `failed:<reason>`):
- O's Mandate Content (the form of §11.1 of ap2-evidence-pack: `delegate_payload` holding exactly one object, else the
  payload) has `vct` `mandate.payment.open.1` (`open_hop_not_an_open_payment_mandate`), and `cnf.jwk` a P-256 JWK
  (`open_hop_without_cnf_jwk`);
- C's Mandate Content has `vct` `mandate.payment.1` (`closed_hop_not_a_payment_mandate`);
- C's snapshotted `key.jwk` equals O's `cnf.jwk` on `kty`, `crv`, `x`, `y` (`closed_hop_not_signed_by_the_delegate`):
  with MP1, C's signature verifies under the key O delegated to;
- C's payload carries `sd_hash` equal to BASE64URL(SHA-256(O's `sd_jwt_compact`)) or `issuer_jwt_hash` equal to
  BASE64URL(SHA-256(O's issuer JWT)) (the SDK's two `hash_mode`s; the Delegate SD-JWT draft `0c1d686` §5.1.4), and not
  both (`closed_hop_not_bound_to_the_open_hop`).
`aud`, `nonce` and `iat` of C are reported, not compared: the bundle names no expected audience or nonce. MP2 verified
says the closed mandate is the delegate's, bound to that open mandate; not that a credentials provider received it.

### 31.3 MP3 — the closed mandate within the open mandate (AP2 "Verification and Processing Rules", agent_authorization.md; the constraint types of payment_mandate.md)
Each pre-set value of O's Mandate Content (`payee`, `payment_amount`, `payment_instrument`, `pisp`, `execution_date`,
`risk_data`) is present in C and canonically equal (RFC 8785), else `failed:preset_changed:<key>` (the AP2 text: "verify
the closed Mandate Content has these values unchanged"). The SDK's `check_preset_payment_claims` compares only `payee` (by
`merchant_matches`), `payment_amount`, `payment_instrument` and `execution_date`: a changed `pisp` or `risk_data` fails
here and passes the SDK (declared; measured in 31.8). Each constraint of O,
in order (the first that fails names MP3; every outcome is listed in the report):
- `payment.amount_range`: C's `payment_amount` is `{"amount": integer, "currency": string}`; same `currency`;
  `min` ≤ `amount` ≤ `max` (`min` absent: no minimum). `failed:amount_out_of_range`, `failed:currency_differs`;
  a negative `amount` is `failed:payment_amount_negative`, before the currency and even without `min` (amendment b, 2026-11-01: AP2 pull
  request #391, open and not merged on 2026-11-01; Mastercard Verifiable Intent requires a non-negative amount; the
  SDK at `e1ea56d` accepts it, declared divergence);
  C's `payment_amount` of another form (here and for `payment.budget`): `failed:payment_amount_malformed`.
- `payment.allowed_payees`: C's `payee` matches an element of `allowed` by the SDK's `merchant_matches` (both `id`
  present: equal `id`; otherwise equal non-empty `name` and equal non-empty `website`) — the AP2 text says "MUST be present
  in the `allowed` array" and names no matching rule; the SDK's is taken and declared. `failed:payee_not_allowed`.
- `payment.allowed_payment_instruments`: an element of `allowed` with C's `payment_instrument.id` (the SDK compares `id`).
  `failed:instrument_not_allowed`.
- `payment.allowed_pisps`: an element with C's `pisp` equal on `domain_name`, `legal_name`, `brand_name`, each a string
  in the element (`types/pisp.json` requires the three; an absent name never matches an absent one, review 2026-10-31).
  `failed:pisp_not_allowed`; C without `pisp`: `failed:pisp_missing`.
- `payment.execution_date`: when C has `execution_date`, `not_before` ≤ it ≤ `not_after`, compared only when both are
  `YYYY-MM-DD` or both `YYYY-MM-DDTHH:MM:SSZ` (the SDK compares the strings; other forms `not_evaluated:date_form`).
  C without it ("When absent indicates immediate execution"): with a block time (MP6) the block's UTC time is compared in
  the constraint's form, else `not_evaluated:no_execution_date_no_block_time` (not an `absent:` outcome: it blocks
  `chain_verified`, since the mandate's window is not shown met). `failed:execution_date_outside`.
- `payment.budget`: the cumulative spend is state outside the bundle ("requires tracking the total amount spent"). Same
  currency, C's amount not negative (`failed:payment_amount_negative`, checked before the currency, as AP2 pull request
  #391 does), and C's amount alone against `max`.
  **Amendment c (2026-11-01; replaces amendment b of the same day): the unit of `max` is contested, so a verdict is
  given only where every reading in play agrees.** AP2's schema types `max` as `number` and its text names no unit;
  the SDK at `e1ea56d` computes `int(max * 100)` for every currency. On 2026-11-01 the open proposals on the AP2
  repository go two ways: MAJOR units converted with the ISO 4217 exponent (pull requests #368 and #377; #340 states
  major units in the schema text only; issue #362, title only, reports the `* 100` for every currency), or an INTEGER in ISO 4217 MINOR units like every
  other amount (issue #389, which also reports that the KYA Bench conformance vectors grade the ambiguous budget
  `indeterminate`). Outside AP2, the amount fields of ACP, Stripe, Mastercard Verifiable Intent (whose `budget.max`
  is an integer in minor units), UCP and Adyen are integers in minor units (the author's notes (not distributed) 
  MERCATO_IMPORTI_BUDGET_20261101.md, sources dated there). The readings of `max` taken here, each only when it is a
  whole number of minor units: MAJOR = `max` × 10^e, e the ISO 4217 exponent (`CcyMnrUnts`) of List One published
  2026-09-17 (six-group.com `list-one.xml`, sha256 33139b43…a1b0ff, downloaded 2026-11-01: 165 codes; a code outside it,
  the 13 listed "N.A." included, is `not_evaluated:budget_currency_exponent_unknown`), and MINOR = `max` itself. An integer
  `max` is exact at any size (Python integers); a finite float (a JSON number written with a fraction or an exponent) is read through its shortest
  decimal text (Python's `repr`) in decimal arithmetic that traps rounding. No reading left (0.295 USD, 5e-324):
  `not_evaluated:budget_unit`. C's amount above every reading: `failed:amount_exceeds_budget`; at or below every
  reading: `not_evaluated:budget_needs_past_spend` (never verified: the spend before C is outside the bundle);
  between them: `not_evaluated:budget_unit_ambiguous`. For JPY both readings coincide. An absent `max`, NaN, an
  infinity, or a value of another Python type (a float subclass or a Decimal included) is
  `failed:constraint_malformed`. Divergences from the SDK at `e1ea56d`, declared: a budget in a currency
  whose ISO 4217 exponent is not 2 (JPY: × 1 here, × 100 there; KWD: × 1000 here); a float whose product the SDK
  truncates (0.29 USD: 29 here, 28 there); an amount between the two readings (the SDK compares with `max` × 100);
  a negative amount. Divergences from pull requests #368/#377, declared: there a code outside ISO 4217 List One
  (XAU, XDR, or any other string) takes exponent 2, a fraction of the minor unit is rounded down, and only the MAJOR
  reading is taken; here the first is not evaluated, the second is not a reading, and an amount between the two
  readings is `not_evaluated:budget_unit_ambiguous`. A pack carries no fraction (§3.1 of ap2-evidence-pack), so a float reaches this rule
  only on Mandate Contents passed directly to `eval_terms`/`evaluate_mp3` (the tests); measured 2026-10-31: the SDK
  writes `Budget(max=10)` as `10.0`, and ap2-evidence-pack 1.7.1 refuses to build a pack from such a token ("float
  '10.0' in the evidence file"), so a budget mandate made by the SDK cannot be carried today (declared).
- `payment.agent_recurrence`: `not_evaluated:recurrence_needs_past_uses` (state outside the bundle). The SDK also requires
  `amount_range` and `budget` beside it: their absence is `failed:recurrence_without_amount_range_or_budget`.
- `payment.reference`: the open checkout mandate is not part of a payment chain; when an artifact of the pack has a
  Mandate Content of `vct` `mandate.checkout.open.1` whose `sd_jwt_compact` hashes (BASE64URL(SHA-256), the `_sd_alg` of O
  being `sha-256` or absent; another `_sd_alg`: `not_evaluated:sd_alg_not_sha256`) to `conditional_transaction_id`:
  verified for this constraint; otherwise `not_evaluated:open_checkout_not_in_pack`.
- a constraint whose `type` is not one of these: `not_evaluated:unknown_constraint` ("Any unknown Constraints MUST be
  treated as failing evaluation" — a relying party applying AP2 refuses; this verifier cannot say the payment is outside
  terms it cannot read, so it does not say `verified`). A constraint of a known type that is malformed (the schema's
  required keys and JSON types, `_constraint_shape` of ap2-evidence-pack, except a `payment.budget` `max` that is a
  finite float: the budget item above) is `failed:constraint_malformed`; a known type
  with a member outside its schema (types and required keys right) is `not_evaluated:constraint_unknown_member` (the
  SDK's models ignore such a member; this verifier cannot say what it narrows; review 2026-10-31). A constraint of type
  `io.github.robertolocatelli81.restricts` in O is a type AP2 does not know (`not_evaluated:unknown_constraint`): it is
  left out only in a restriction record R (31.5).
O's `constraints` not a list: `failed:constraint_malformed`. MP3 `verified` only when every pre-set value and every
constraint is verified; `failed` when one fails (whatever its position); else the first `not_evaluated`.

31.3a (2026-10-31, after a probe of 40 000 damaged open/closed pairs: on 2 309 of the 28 354 that the AP2 SDK refuses,
MP3 said `verified`) The two Mandate Contents meet the AP2 schemas at e1ea56d before their terms count: the closed one
`payment_mandate.json` (`vct` "mandate.payment.1", `transaction_id` string, `payee` a Merchant, `payment_amount` an
Amount, `payment_instrument` a PaymentInstrument required; `pisp`, `execution_date`, `risk_data`, `iat`, `exp` typed when
present), the open one `open_payment_mandate.json` (`vct` "mandate.payment.open.1", `constraints` array, `cnf` object
required; its pre-set values typed as above), with `types/merchant.json` (`id`, `name` strings required, `website`),
`types/amount.json` (`amount` integer, `currency` string), `types/payment_instrument.json` (`id`, `type` strings required,
`description`), `types/pisp.json` (`legal_name`, `brand_name`, `domain_name` strings); and every element of the `allowed`
list of `payment.allowed_payees` / `_payment_instruments` / `_pisps` is of its type, else that constraint is
`failed:constraint_malformed`. A fault is `failed:closed_mandate_schema:<member>` or `failed:open_mandate_schema:<member>`
(the first). JSON types are exact (`type(x) is int`, a boolean is not an integer): the SDK's pydantic models also coerce
"1250" into 1250 and fill a missing `vct` or constraint `type` from their defaults, so a mandate the SDK accepts can fail
here (declared, never the other way). Members outside a schema are left alone, as those models ignore them. Measured on
the same 40 000 pairs (seeds 11-14, the author's local probe, not distributed): SDK refuses 28 354, MP3 verified on 0 of them; SDK accepts and
finds a violation, MP3 verified on 0; no crash.

### 31.4 MP4 — the x402 payment is the one the mandate closed
On the EIP-3009 authorization of the bundle (`payment_payload.payload.authorization`):
- MP4n (the sample's rule): `nonce` equals `keccak256` of the UTF-8 bytes of `chain`. `failed:nonce_not_the_chain_hash`.
  This binds the signed authorization to this exact chain string, its disclosures included.
- MP4a (this specification's reading, declared; the sample's intent "cents * 10,000" for USDC): the asset is in the
  measured table of section 19 (`apc_assets.py`) and its symbol names a currency by this closed list — `USDC`, `USD₮`,
  `USAT` → `USD`; `EURC` → `EUR`; `JPYC` → `JPY` (the issuers' naming; a peg is not checked) —, C's
  `payment_amount.currency` is that currency, and `value` equals `amount` × 10^(d − e), d the token's decimals and e the
  ISO 4217 minor unit (USD 2, EUR 2, JPY 0). `failed:value_not_the_mandate_amount`,
  `failed:currency_not_the_token_currency`, `failed:payment_amount_malformed`; an asset outside the list, or d < e:
  `not_evaluated:asset_currency_unknown`.
- MP4p: when C's raw resolved `payment_instrument` carries `payee_address` (a key outside AP2's schema, as the sample
  writes it), it equals the authorization's `to` (case-insensitive 0x hex, 20 bytes; another form `failed:malformed`;
  another address `failed:payee_address_not_the_authorization_to`);
  else `not_evaluated:mandate_names_no_address` — AP2 names merchants, not chain addresses.
MP4 = the first `failed` of MP4n, MP4a, MP4p, else the first `not_evaluated`, else `verified`; the three are reported.

### 31.5 MP5 — the payment within every restriction record (the terms the issuer later narrowed)
For each entry of the §11 receipt whose `original` is O: an entry not `verified` gives `not_evaluated:restriction_<state>`
(its reasons are reported); a `verified` record R is applied to C exactly as MP3 applies O (R's pre-set values and
constraints, the restriction constraint itself left out; `payment.reference` with R's `_sd_alg`, the token it is in). MP5 `failed:payment_outside_restriction` when C is outside a
verified R; `verified` when C is within every verified R and every entry naming O is verified; `not_evaluated:
absent:no_restriction` when no record names O. Records naming another artifact are reported, not applied.

### 31.6 MP6 — times
Block time t: the `timestamp` of the header that B1 verifies (apc-0.3 only), else none. B1 shows that the header hashes
to the block the bundle names, not that the block is on a chain: t is a chain's time only as far as `canonical` and
`l1_state` show it (section 30: `evidence_level` `finality_proven`), and a header made for the bundle gives MP6 and MP7
the t its maker chose (31.8: the synthetic block, on no chain, has MP6 `verified`). A reader who relies on MP6 or MP7
asks `--require-level finality_proven`. O's `exp` (top level or Mandate
Content, the earlier) ≥ t, else `failed:paid_after_mandate_expiry`; O's `nbf` when present ≤ t, else
`failed:paid_before_mandate_validity`; an `exp` or `nbf` that is not a JSON integer: `failed:malformed`; neither present:
`verified` (no limit to meet). With `exp` or `nbf` and no block time: `not_evaluated:no_block_time` — not an `absent:`
outcome, so it blocks `chain_verified` (a mandate with a time limit is not shown in force; revised 2026-10-31 after
the second review, observation O1: as `absent:` an expired mandate could stand beside `chain_verified` in apc-0.1/0.2).
C's `iat` is the delegate's statement and is reported only. The `exp`/`nbf` of C and of restriction records are not
checked (declared).

### 31.7 MP7 — existence is not knowledge
For each verified R applied in MP5 on which MP5 is `not_evaluated` (C neither shown within R nor outside it, e.g. a
`payment.budget` or an unknown constraint in R): `not_evaluated:payment_within_restriction_not_shown` (review
2026-10-31). For each verified R applied in MP5 on which MP5 failed (C within R gives `verified`: whether R existed before the
payment changes nothing), with the pack's `time_anchor` state `verified` (the TSA certificate is supplied: §3.2 of
ap2-evidence-pack) and a block time t: `existed_by` (an RFC 3161 GeneralizedTime `YYYYMMDDHHMMSS[.f]Z`, read with its
fraction; another shape is `not_evaluated:no_time_anchor`) < t is reported as "R existed, by the TSA's clock, before the
payment's block" — and MP7 is `failed:paid_outside_restriction_that_existed_before` only when MP5 failed on that R. MP7
NEVER says that the agent, the merchant, the credentials provider or the payer RECEIVED or KNEW R: AP2 has no revocation
(§11.5 of ap2-evidence-pack) and the existence of a signed, timestamped narrower term proves its existence only. Without
a verified time anchor: `not_evaluated:no_time_anchor`; without a block time: `not_evaluated:absent:no_block_time`;
`existed_by` ≥ t: `verified` with the note "R is not shown to exist before the payment". The report entry of each
verified R carries `existed_before_payment` (true/false) whenever the anchor is verified and t is known. MP7 is the
first `failed`, else the first `not_evaluated`, else `verified`, over the verified records applied;
`not_evaluated:absent:no_restriction` when no record names O; `not_evaluated:no_verified_restriction` when records name
O and none is verified.

### 31.9 Solana (apc-0.5): this specification's own binding
Neither AP2 nor x402 defines how an x402 `exact` payment on Solana binds an AP2 mandate (no EIP-3009 nonce on SVM). The x402
SVM scheme (`scheme_exact_svm.md` at x402 4241d56, section 3.1; the sentence is the same at 72dde23 of 2026-10-26, the
file's last commit on 2026-10-31, while section 3.1 itself gained the version-1 and split layouts) says a client "MUST
include a Memo instruction containing either the value of `extra.memo` (when present) or a random nonce (at least 16
bytes, hex-encoded for UTF-8 compliance)". This specification puts the binding in that Memo: its data is the lowercase hex
SHA-256 of the UTF-8 bytes of `chain` (32 bytes, 64 hex digits: inside the nonce rule). It is OURS, declared as such, not a
rule of AP2 or x402. apc-0.5 takes the closed member of section 31 (any other profile or member is refused); MP1-MP3 and
MP5 as above; MP4n: exactly one top-level Memo instruction whose data equals that hex string (`failed:memo_count_<n>`,
`failed:memo_not_the_chain_hash`); with `accepted.extra.memo` set by the seller to anything else, the Memo is the seller's
(S5) and MP4n is `not_evaluated:seller_memo`. MP4a with the token table of this section (measured `getTokenSupply`,
2026-10-31, slot 463662928): USDC mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, 6 decimals; another mint
`not_evaluated:asset_currency_unknown`. MP4p: a `payee_address` of base58 form (32-44 characters of the Bitcoin alphabet)
equal to `accepted.payTo`, else `failed:payee_address_not_the_authorization_to`, another form `failed:malformed`. apc does
not prove a Solana block (block_bound false): MP6 and MP7 have no block time (`not_evaluated:no_block_time` when the mandate
has a time limit; MP7 as 31.7).

Real data: bundles/real_svm_mandate/ (2026-10-31), a payment made for this work on Solana mainnet, signature
`4F6f2zy763RQARFBJ7PqbCLUCRnV2A4JPMXDeU3u34RTVQR3WB3cC1jFL23VXGdrCBnwZdn4mfx81i1gd3gxLWWX` (slot 463633849): throwaway
client, merchant and mint, fees and rent paid by the author's test key, token accounts burned and closed after; the Memo carries
the SHA-256 of the chain of the AP2 mandate made for it. S1-S5, MP1-MP3, MP5, MP7 verified; MP4n verified on the
transaction as executed; MP4a not evaluated (a throwaway mint, not USDC); MP6 not evaluated (no proven block time).

### 31.8 Tests and review (measured 2026-10-31 on 3c92d1b; the items dated 2026-11-01 on the tree of the amendment)
- tests/test_mandate.py, 42 tests (32 before the reviews; 40 with the independent review patch, +1 for 31.3a, +1 for the amendment
  of 2026-11-01): every MP outcome; `not_evaluated:budget_unit` on Mandate Contents given directly (a pack carries no
  fraction, so a non-integer `max` is not reachable from a pack); amendment c: `not_evaluated:budget_unit_ambiguous`
  (reachable from a pack: an integer `max` between whose two readings C's amount falls), an integer `max` of 1002
  digits, the ISO 4217 table by its digest, and `failed:payment_amount_negative` before the currency; the closed member and the pack against ap2-evidence-pack's own
  verdict at every path (generative); hop and binding faults (swapped, re-signed, a delegate key with the same x and the
  other y, sd_hash or issuer_jwt_hash of the wrong hop); restriction records within, outside, contradicted, of another
  original; MP6/MP7 with a local RFC 3161 TSA; a synthetic Base block whose header B1 verifies
  (tools/synth_mandate_block.py: a block on no chain, B1-B4 verified, the header altered fails B1); the Solana bundles of
  31.9 and the Memo rules. The tests that compare the TSA's clock with a block time take the real clock at run time and
  pass with the import time moved by -9000, -3000, -1400, -100, +2000 and +9000 seconds.
- tests/fixtures_mandate: 9 bundles made with the AP2 SDK at e1ea56d from keys made for them (tools/gen_mandate_fixtures.py);
  9/9 as expected; positive control: all 9 differ on f5ad071 (the tree before this section).
- MP3 against the SDK's check_payment_constraints (tools/diff_mandate_sdk.py, generated open/closed pairs with the
  amount bounds and their neighbours; seeds 20261031, 7, 99, 5000 pairs each, 15 000 generated): 13 736 compared, of
  which 13 712 agree, 24 declared divergences (a pre-set payee equal by `id` and different otherwise: "unchanged" is RFC
  8785 equality here) and 0 disagree; 1 264 apc not_evaluated and 0 SDK errors outside the comparison (33.14: until
  2026-11-03 this line read "0 disagreements on 13 712 pairs", the agreements counted as the pairs compared); positive
  control: three boundary mutants (`>=` for `>` on max, `<=` for `<` on min, `>=` for `>` on not_after) give 12, 3 and 16
  disagreements on 3000 pairs of seed 20261031 (0 unmutated; re-measured 2026-11-03; until then this line said 12, 3 and 3: 33.14).
- Mutants MD01-MD83 (tools/mutants03.py, apc_mandate.py, apc_svm.py, apc_verify.py; MD61 not listed, equivalent since
  31.3a, reason in the file), final tree, control on the unmutated copy first: 82 killed, 0 survived (journal
  mandate_20261031/mut_final6.journal (the author's local records, not distributed), 2026-10-31 night). Before, on earlier trees, MD13 (sd_hash),
  MD14 (issuer_jwt_hash), MD15 (a key compared on x only), MD41 (the anchor state), MD48 (the GeneralizedTime fraction,
  equivalent for an integer block time, killed by a direct test of the parser) and MD79 (a boolean taken as an integer)
  lived and were killed by the tests added for them.
- Whole suite one file at a time on the final tree: 53 files OK; frozen corpus (tools/regress.py check): 1038 bundles,
  0 differences after the 2 bundles of bundles/real_svm_mandate were added (the other 1036 unchanged).
- More generated inputs (2026-10-31, before 31.3a and the independent review patch): MP3 against the SDK on 4 more seeds (1-4) of
  20 000 pairs: 73 249 compared, of which 73 137 agree, 112 declared divergences on a pre-set payee and 0 disagree; 6 751
  apc not_evaluated, 0 SDK errors (re-measured 2026-11-03 on the tree of 33.14: the same counts; until then this line
  read "0 disagreements on 73 137"); tests/test_mandate.py and tests/test_svm.py on Python 3.9.25 and 3.13.15 (cryptography
  50.0.1): 72 tests OK on each. On the final tree: seed 31, 10 000 pairs, standard 9 145 compared (9 137 agree, 8
  declared on a pre-set payee, 0 disagree; 855 not_evaluated), `presets` 9 545 compared (9 090 agree, 12 declared on a
  pre-set payee, 443 on a pre-set `pisp` or `risk_data`, 0 disagree; 455 not_evaluated; both re-measured 2026-11-03, the
  same); the damaged-pair probe of 31.3a: 0 `verified` on the 7 102 pairs of 10 000 that the SDK refuses.
- Review: a second reviewer (a separate review, on a clone, with these dependencies) found five defects in the first version —
  R1 the restriction type skipped in the OPEN hop (MP3 verified, AP2 treats an unknown type as failing), R2 MP7 verified
  when MP5 was only not_evaluated, R3 two absent PISP names matching as None == None, R4 a member outside a constraint's
  schema read as malformed (now not_evaluated, the author's choice), R5 a reason missing from 31.4 — each shown by a test
  that failed before the fix; a third independent review judged the fixes ACCEPTABLE. Its observation O1
  (a mandate's time limit without a block time listed as `absent:`, which does not block) is fixed in 31.3 and 31.6.
- Independent review (2026-10-31, on a copy of 3df1e7d): the open hop without disclosures (31.2, fixed), the pre-set
  `pisp`/`risk_data` divergence from the SDK (31.3, declared), the block time of a header B1 verifies (31.6, declared),
  the M1 and check_not_run outcomes and apc-0.15 (31, declared); eight tests added (TestIndependentReview, each failing on
  3df1e7d or killing a mutant that lived there: the open hop without disclosures, an open hop with a KB-JWT (MD83), the
  pack written unescaped at ap2-evidence-pack's size limit, the loader's realpath guard, an existed_by of another shape, the exit-74 path, recurrence with one of its two companions,
  the `--ap2-tsa-cert` value); test_reference_with_the_open_checkout_in_the_pack no
  longer fails when the hash ends in `A` (one run in 16). tools/diff_mandate_sdk.py with `presets` (seeds 20261031, 7,
  99; 5000 pairs each): 14 256 compared, of which 13 549 agree, 698 declared divergences on a pre-set `pisp` or
  `risk_data`, 9 on a pre-set payee and 0 disagree; 744 apc not_evaluated and 0 SDK errors outside the comparison (33.14:
  until 2026-11-03 "0 disagreements on 13 549 pairs"). apc-0.10 keeps M1 of section 9; apc-0.12, apc-0.15 and apc-0.16 refuse the member.

## 32. SPEC 0.21 (draft, 2026-11-01, local; apc_verify 0.21.0, 0.21.1 by Amendment 32.10, 0.21.2 by Amendment 32.11, 0.21.3 by Amendment 32.12, 0.21.4 by Amendment 32.13, and 0.21.5 by Amendment 32.14, apc_msca.py, apc_siglib.py; bundle versions apc-0.2 and apc-0.3, apc-0.13 read as v2; 32.2 in every bundle version this file reads) — a 65-byte signature of a payer with code: USDC's (v,r,s) path, and the ERC-1271 of Circle_SingleOwnerMSCA 1.0.0 proven from state

**Sources, read 2026-11-01.** Circle stablecoin-evm fc85788 (sources/circle_stablecoin-evm_fc85788): `EIP3009.sol` 84-104
(`transferWithAuthorization(…, uint8 v, bytes32 r, bytes32 s)` forwards `abi.encodePacked(r, s, v)` to the `bytes` form),
143 and 276-290 (`_requireValidSignature` calls `SignatureChecker.isValidSignatureNow(signer, digest, signature)`),
`SignatureChecker.sol` 38-47 (a `signer` with code is asked by ERC-1271 `isValidSignature`; one without goes through
`ECRecover.recover`, 65 bytes, low s). Circle buidl-wallet-contracts, commit 3c8cd8fbf242c48d9774352bc1087fdebc09988d
(2026-09-14, GitHub raw), copies in sources/circle_msca_v1_3c8cd8fb_20261101 with SHA256SUMS: `SingleOwnerMSCA.sol`
80-83 (NAME `Circle_SingleOwnerMSCA`, `_MESSAGE_TYPEHASH` = keccak256("CircleSingleOwnerMSCAMessage(bytes32 hash)")),
116-139 (`isValidSignature`), 405-419; `BaseERC712CompliantAccount.sol` 24-42 (`getReplaySafeMessageHash`);
`Constants.sol` 41 (`WALLET_VERSION_1` = "1.0.0"); `WalletStorageV1Lib.sol` 32-56 and `Structs.sol` 37-41 (the storage
layout); `WalletStorageInitializable.sol` 46-65 (`initialized`, `initializing`); OpenZeppelin 5.0.0
`SignatureChecker.sol` 22-27 and `ECDSA.sol` 128-140 (from the Sourcify sources of the implementation). The same five
Circle files from Sourcify (chain 42161, `exact_match`, 2026-08-26) have the same sha256 as the GitHub copies.

### 32.1 Why: "65 bytes, so an EOA" is false on USDC's (v,r,s) path
Section 3 reads a 65-byte `payload.signature` as the signature of an account without code: recovery must give
`authorization.from`, else `failed:recovers_<address>_not_from`. That is what USDC does for a payer WITHOUT code. For a
payer WITH code USDC packs `r || s || v` (65 bytes) and asks the payer's `isValidSignature` (sources above): a 65-byte
signature is the ordinary form in which a contract wallet with one owner key pays by `transferWithAuthorization(v, r, s)`,
and section 3 called every such payment `failed`. Measured (2026-11-01, oracle/coverage_20261022 replayed offline on
0.20.0, the author's notes PASSO2_STUDIO_ERC1271_20261101.md (not distributed)): of the 2449 authorizations of the 7 census windows, 28 are direct calls
of one payer, payer-C, whose code is an OpenZeppelin ERC1967Proxy (133 bytes) in
front of Circle's `SingleOwnerMSCA` 1.0.0 (ERC-6900 v0.7, one owner key, no plugin); all 28 executed on chain
(AuthorizationUsed and Transfer logged); the verifier built no bundle for them (`direct_not_decoded`, payer
`code_not_known`) and, on a bundle built by hand for one of them, gave `chain_failed` with L2.sig
`failed:recovers_0xcec58155…_not_from` (bundle_28_senza_payer_wallet.json) and, with a `payer_wallet` member,
`failed:payer_wallet_with_a_65_byte_signature` (bundle_28_con_payer_wallet.json): a false negative on an executed
payment. This section corrects the two rules and adds the state member and the closed list that make these payments
verifiable offline.

### 32.2 A 65-byte signature that does not recover `from` (every bundle version read by this file: apc-0.1, apc-0.2, apc-0.3, apc-0.13 as v2)
Without `payer_state` and without `payer_wallet`, L2.sig of a 65-byte signature is section 3's result, with ONE
exception, the mirror of Amendment 0.3.2 (`high_s_accepted_on_chain`): when the recovery does not give `from` and the
bundle's `chain_tx` shows that the token accepted this very signature for this very authorization — C1 `verified` (the
transaction is a direct call whose arguments are the authorization and whose signature bytes are `payload.signature`)
and C2 `verified` (the transaction hash recomputes and the token logged AuthorizationUsed(from, nonce) in it), and,
with `inclusion`, B3 not failed (a receipt proven reverted, or one that does not hold the carried logs, is not an
execution; the same reading for Amendment 0.3.2, review 2026-11-01) — AND
the digest this verifier computed is the token's: `accepted.asset` on `accepted.network` is in the measured list of
Amendment 0.11.5 and `accepted.extra` names its measured EIP-712 name and version — L2.sig
is `not_evaluated:signature_accepted_on_chain_needs_payer_state`, K3 `not_evaluated:by_L2.sig`, with a note. Why: with
USDC's code, a signature whose recovery is not `from` is accepted only through the payer's `isValidSignature`, so the
payer had code at that block (or the token was not the measured implementation; the same reading as 0.3.2). Without the
domain condition the recovery says nothing about code: `accepted.extra` is unsigned (section 2), and a bundle that
declares another domain name or version for a real EOA payment makes the recovery fail while C1 and C2 hold (the
calldata carries no domain); such a bundle stays `failed:recovers_<address>_not_from` (tests/test_apc.py Mutations
"extra.name USDC", found when this rule was first written without the condition). What the
outcome says: the chain accepted it and the rule that accepted it is code the bundle does not show; `payer_state` (32.3)
shows it. What it does not say: never `verified` — who authorized the payment is decided by that code, not by the
recovery — so the verdict is at most `chain_incomplete`, and the exception never turns a `failed` into a level above
`none` (section 30). What it rests on: `chain_tx` is RPC data carried by the bundle (section 4 C2). On a real chain a
forged signature of an account without code cannot reach C1 and C2 verified (the token reverts and logs nothing), so
it stays `failed:recovers_<address>_not_from`; a bundle whose transaction and log are made up gives, with this
exception, `chain_incomplete` where it gave `chain_failed`, and `chain_verified` for a real signature then as now (a
made-up chain_tx has never been detectable offline: that is what `inclusion` is for, section 6, and in apc-0.3 B1-B3
bind the transaction and its receipt to a block hash — a block hash, not the chain: a made-up block hashes too, and
only `canonical` (O1-O4) with an L1 checkpoint ties it to the chain). Positive controls (tests/test_msca.py): the signature altered
in one byte → C1 `failed:tx_signature_differs_from_payload`, L2.sig stays `failed:recovers_…`; `chain_tx` taken out →
`failed:recovers_…`; a `chain_tx` of another transaction → `failed`; an indirect call (C1 `not_applicable:indirect_call`,
the signature bytes are not bound to the transaction by C1) → `failed:recovers_…`. Until 0.20 such a bundle was
`chain_failed` on the recovery alone, whatever the chain showed (the 28 payments of 32.1). Frozen corpus: 0 of the
1038 bundles carry a 65-byte signature that does not recover `from` (tools/regress.py check, 32.8), so no frozen verdict
changes by this rule.

### 32.3 Dispatch of L2.sig (apc-0.2 and apc-0.3; apc-0.13 as v2)
In this order:
1. ERC-6492 suffix (apc-0.3, section 6): as before, first; a `payer_state` beside it is read for its grammar and
   state (32.4; the report member says what it showed), a `payer_wallet` is not read (as before), and the 6492 outcome
   stands.
2. `payer_state` present (32.4): its rule 32.6 decides L2.sig for a signature of ANY length (the state says whether the
   payer had code; the signature's form follows from the code); its `verified (ERC-1271 …)` is written only when the block
   whose state decides it is anchored, 32.10, else `not_evaluated:payer_state_block_not_anchored`. `payer_state` and
   `payer_wallet` together: refused (one member says what the payer is).
3. `payer_wallet` present (section 3): rule L2.sig-1271 reads the member — grammar, block, method and params of each
   reply, code and implementation against the closed list of section 3 — for a signature of any length. A code or
   implementation outside that list: `not_evaluated:wallet_implementation_not_known` (the member for the list of 32.5 is
   `payer_state`; the report does not name it here). In the list, with a 65-byte signature: `failed:payer_wallet_with_a_65_byte_signature`
   as before (CoinbaseSmartWallet.isValidSignature ABI-decodes a SignatureWrapper, which 65 raw bytes are not; the
   fallback of EIP7702Proxy to the payer's own key over the raw hash, section 3, is not evaluated here: open, no
   corpus case). Until 0.20 a `payer_wallet` beside a 65-byte signature was NOT read: L2.sig was set to
   `failed:payer_wallet_with_a_65_byte_signature` whatever the member held (a member of another payer, an unknown code,
   a malformed member passed unseen; tests/test_apc.py test_payer_wallet_beside_a_65_byte_signature_or_in_v01 is
   revised: a `payer_wallet` of another payer and block is now `failed:payer_wallet_block_not_tx_block`, the block being
   read first).
After points 2 and 3, for a 65-byte signature: when the member gives a `not_evaluated` outcome, the block is NOT
   anchored (32.10: a `payer_state` by `rpc`, a `proof` not evaluated, a `proof` proven under a block that no checkpoint
   vouches for, a `payer_wallet`), the recovery of section 3 fails and the conditions of 32.2 do not hold, L2.sig is
   the `failed` result of section 3, with a note (review 2026-11-01: such a member is declared and unsigned like
   `accepted.extra`; without this, a forged signature of an account without code beside a declared unlisted code went
   from `chain_failed` to `chain_incomplete` with no `chain_tx`. The review wrote "the state is not
   `proven_at_parent_and_block`"; 0.21.1 reads "the block is not anchored": a state proven under a made-up block is the
   state the bundle chooses — measured, the made-up block of 32.10 with a receipt proven reverted gave `not_evaluated`
   where this clause means `failed`; tests/test_msca_anchor.py).
4. Neither: a signature of 65 bytes by section 3 with the exception of 32.2; of another length
   `not_evaluated:contract_wallet_needs_payer_wallet` as before (the note now names `payer_state` too).

### 32.4 Grammar: `payer_state` (optional, apc-0.2 and apc-0.3; refused in apc-0.1; a JSON-RPC member for 29.4)
```
payer_state: {"rpc":   {"code": <rpc eth_getCode [from, B]>,
                        "wallet"?: {"implementation":      <rpc eth_getStorageAt [from, ERC1967_SLOT, B]>,
                                    "owner":               <rpc eth_getStorageAt [from, MSCA_OWNER_SLOT, B]>,
                                    "implementation_code": <rpc eth_getCode [implementation, B]>,
                                    "owner_code":          <rpc eth_getCode [owner, B]>}}}
           | {"proof": {"code": hex, "parent_header": <header, as section 6>,
                        "at_parent": {"payer": {"accountProof": [hex], "storageProof"?: [[hex], [hex]]},
                                      "implementation"?: {"accountProof": [hex]}, "owner"?: {"accountProof": [hex]}},
                        "at_block":  <the same>}}
```
Closed at every level; exactly one form; `<rpc>` as section 1 (method and params checked before the result is read,
`failed:<reply>_params_<i>` as section 3). ERC1967_SLOT = 0x360894a1…2bbc; MSCA_OWNER_SLOT = 0xc6a0cc20…bfc8 + 8
(32.5). The optional members — `wallet` in `rpc`; `storageProof` (two proofs, in the order ERC-1967 slot, owner slot),
`implementation` and `owner` in each end of `proof` — are REQUIRED when `code` hashes to a code of the list of 32.5 and
REFUSED otherwise (an empty or unlisted code: nothing reads them, and a member nothing reads is not carried). The
implementation and owner whose replies or proofs are carried are the addresses the two slot words give (32.6), so
`implementation_code.params[0]` and `owner_code.params[0]` are checked against those words. Lists of proof nodes: 1..64
(an absence proof too; an owner without an account is proven by its absence, apc_l1proof.account).
- `rpc`: B is the transaction's block when `chain_tx` is carried (`failed:payer_state_block_not_tx_block`), one block for
  every reply; DECLARED chain state at the end of that block (as `payer_wallet`, section 3).
- `proof`: needs `inclusion` with B1 verified (`not_evaluated:payer_state_proof_needs_inclusion` without `inclusion`,
  so always in apc-0.2; `not_evaluated:payer_state_proof_block_not_bound` when B1 is not verified); `parent_header`
  hashes to its `hash`, which is `inclusion.block_header.parentHash`, and its number is one less
  (`failed:payer_state_parent_header_not_parent`); under the stateRoot of each of the two headers (apc_l1proof.account,
  storage: the eth_getProof paths of section 6 L1A, L1S), the payer's account has codeHash = keccak256(code)
  (`failed:payer_state_code_not_proven`), the two slot words are the same at both ends
  (`failed:payer_state_slot_changed_in_block`), the implementation's account has the pinned code hash
  (`failed:payer_state_implementation_code_not_pinned`; code of an existing account cannot change since EIP-6780), and
  the owner's account is read for its codeHash; a proof that does not verify: `failed:payer_state_proof:<reason>`. What
  the proof shows: the code and the two words at the end of block N-1 and at the end of block N; a transaction earlier
  in block N could change them and change them back, which is not excluded (as 12.5). The proof is as strong as the
  header it reads: B1 binds the header to the transaction, not to the chain, so a bundle that makes up the two headers,
  the state tries and the transaction gets the owner it chooses and, signing with that key, `verified`, `chain_verified`
  and `inclusion_proof` without any key of the payer (measured, review 2026-11-01, tests/test_review_msca.py); for an
  account without code a made-up block cannot change who signs. The owner is bound to the chain only when the block
  is (`canonical` with an L1 checkpoint, `finality_proven`): 32.10 writes `verified` only then.

### 32.5 Closed list WALLETS_1271 (apc_msca.WALLETS; a wallet enters by measure, not by catalogue: verified source, pinned hashes, real executed payments)
| proxy code keccak256 (bytes) | implementation (ERC-1967 slot) | implementation code keccak256 | owner slot | name |
|---|---|---|---|---|
| d09e34b2e51f09092e73e3ba1d520a42972496bf2a3bfdb22bb50b9729a9fd66 (133) | 0x9c6e09bc32d1e012dcaa2623e66d2cc9860c1aed | 60ecaaadc845f14626e77541b390bd36a7f5c35efdee5c30471f0eb08626019e | 0xc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfd0 | Circle_SingleOwnerMSCA 1.0.0 |
Provenance (measured 2026-11-01, the author's notes PASSO2_STUDIO_ERC1271_20261101.md (not distributed) §2, raw replies in passo2_20261101 (the author's local records, not distributed)):
the proxy code is OpenZeppelin `ERC1967Proxy` (solc 0.8.24 by its CBOR metadata; Basescan "Similar Match" for
the payer, declared), which delegates every call to the address in the ERC-1967 slot, so `isValidSignature` is the
implementation's; the implementation 0x9c6e09bc… is NOT verified on Base (Sourcify `match: null`, Basescan "Verify
and Publish") and IS `exact_match` on Arbitrum One (chain 42161, same address, Sourcify, 2026-08-26, `SingleOwnerMSCA`,
solc 0.8.24, optimizer 200 runs, viaIR, paris); its runtime bytecode on Arbitrum (arb1.arbitrum.io/rpc) equals the one on Base
(eth_getCode) byte for byte, 17844 bytes, keccak256 60ecaaad…; `NAME()` = `Circle_SingleOwnerMSCA`, `VERSION()` =
`1.0.0`, `AUTHOR()` = `Circle Internet Financial` by eth_call on the payer. The owner slot is `WALLET_STORAGE_SLOT` + 8:
`AddressDLL installedPlugins` takes slots +0..+2, five mappings +3..+7, then one word packs `uint8 initialized`
(byte 0), `bool initializing` (byte 1) and `address owner` (bytes 2..21): word = owner << 16 | initializing << 8 |
initialized (Solidity storage layout; measured word 0x…d0437f82…fda0001: owner 0xd0437f82…, initializing 0,
initialized 1). Any other proxy code, or a listed proxy whose slot names another implementation:
`not_evaluated:wallet_implementation_not_known` (an upgraded UUPS implementation, `UpgradableMSCA` with plugins, the
v0.8 modules, multisig and WebAuthn owners of Circle's `docs/Smart_Contract_Signatures_Encoding.md`: not measured on
real payments, not listed). The Coinbase Smart Wallet families stay in section 3 (`payer_wallet`); a Coinbase proxy code
or EIP-7702 delegation in `payer_state` is `not_evaluated:wallet_implementation_not_known` with a note naming
`payer_wallet`.

### 32.6 The rule, reduced from the sources to the values the state gives
With the code known (rpc: `code.result`; proof: `code` proven by the account's codeHash):
- code EMPTY (the payer had no code at the end of that block): L2.sig is section 3 for 65 bytes (recovery must be
  `from`; the high-s rule of 0.3.2; the exception of 32.2 does NOT apply: the state answers the question it leaves
  open); any other length `failed:signature_length_<n>_for_a_payer_without_code` (Circle ECRecover.sol 51-56, as 12.5).
- code in the list of 32.5: the implementation word has 12 zero bytes then the listed address (else
  `not_evaluated:wallet_implementation_not_known`); the implementation's code hash is the pinned one (else
  `failed:payer_state_implementation_code_not_pinned`); the owner word has zero bits above bit 176 (else
  `failed:msca_owner_word_not_canonical`), `initialized` 1 and `initializing` 0 (else `failed:msca_not_initialized`: the
  layout is read as pinned only when its flags read as the measured initialized wallet); owner = 0 →
  `not_evaluated:msca_owner_zero_plugin_path` (SingleOwnerMSCA.sol 118-131: the plugin installed for the selector
  decides, arbitrary code); the owner HAS code (rpc: `owner_code.result` not "0x"; proof: codeHash not keccak256("") at
  EITHER end — 0.21.1: an owner deployed inside block N may have decided; until 0.21.0 the end of block N alone was read):
  OZ SignatureChecker 22-27 runs `ECDSA.tryRecover` FIRST and asks the owner's own ERC-1271 only when the recovery does
  not give the owner, so the check below decides when it ends in `verified`, and every other ending is
  `not_evaluated:msca_owner_has_code` (arbitrary code; review 2026-11-01). The check is OZ 5.0.0 `ECDSA.tryRecover` over
  `rs = keccak256(0x1901 || DS || keccak256(TYPEHASH || h))`, h = the EIP-3009 digest of section 3, TYPEHASH =
  keccak256("CircleSingleOwnerMSCAMessage(bytes32 hash)"), DS = keccak256(keccak256("EIP712Domain(string name,string
  version,uint256 chainId,address verifyingContract)") || keccak256("Circle_SingleOwnerMSCA") || keccak256("1.0.0") ||
  chainId of accepted.network || from) (BaseERC712CompliantAccount.sol 34-42; the digest is built from these constants
  and the payer, never from the input): the signature is 65 bytes `r || s || v` (else `failed:msca_signature_length_<n>`:
  tryRecover returns InvalidSignatureLength, and the owner without code has no ERC-1271 path), `s` at most n/2 (else
  `failed:msca_high_s`, ECDSA.sol 137), `v` 27 or 28 with a recoverable point (else `failed:msca_signature_invalid`,
  ecrecover returns zero), recovery equal to the owner (else `failed:msca_signature_recovers_<address>_not_owner`).
  Result `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)` when the block is anchored, else
  `not_evaluated:payer_state_block_not_anchored` (32.10). The same bytes are what USDC passes on both forms of
  transferWithAuthorization (EIP3009.sol 95-103 for (v,r,s); the `bytes` form as carried).
- code NOT EMPTY and NOT in the list: `not_evaluated:wallet_implementation_not_known`.
K3 follows L2.sig as section 4. Report member `payer_state` (apc-0.2 and apc-0.3 reports): null, "declared_rpc" or
"proven_at_parent_and_block"; the note says which, and that the state proof binds the owner to the block, not the
payment to the chain. Measured on the 28 real payments of 32.1 (tests/test_msca.py, bundles/real_msca_20261101): on 0.21.0, 28 of
28 `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)` in both forms (28 apc-0.2 bundles with `rpc`, 28 apc-0.3 bundles
with `inclusion` B1-B4 verified and `proof` proven at parent and block); on 0.21.1 the same 56 bundles reach the end of
this rule and L2.sig is `not_evaluated:payer_state_block_not_anchored` (32.10: none carries `canonical`); v 27 in 16 and
28 in 12, s low in 28; positive controls (the failed outcomes do not depend on anchoring): the same signature with one hex digit of r altered → `failed:msca_signature_recovers_…_not_owner` (30 of the 56
bundles) or `failed:msca_signature_invalid` (26: no point recovers), never verified; s
replaced by n - s with v flipped → `failed:msca_high_s`, the signature of payment i next to the authorization of
payment j → failed (28 of 28), an owner word with `initialized` 0 (synthetic trie) → `failed:msca_not_initialized`, the
owner with code (synthetic) → the rule's end with the owner's signature (`verified` only anchored, tests/test_msca_anchor.py;
else `not_evaluated:payer_state_block_not_anchored`) and `not_evaluated:msca_owner_has_code` when the state names another
owner with code, owner zero → `not_evaluated:msca_owner_zero_plugin_path`,
another implementation address → `not_evaluated:wallet_implementation_not_known`, the implementation's code hash not
pinned (synthetic) → `failed:payer_state_implementation_code_not_pinned`, a proof node altered or a header with another
stateRoot → `failed:payer_state_proof:…`, parent header not the parent → `failed:payer_state_parent_header_not_parent`,
a slot word that differs between the two ends → `failed:payer_state_slot_changed_in_block`, the same payment with a
`payer_state` that declares an EMPTY code → `failed:recovers_…_not_from` (the rule of section 3, without the exception of
32.2), and with another length → `failed:signature_length_<n>_for_a_payer_without_code`.

### 32.7 Evidence level (section 30)
30.4 (ii): `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)` is added to L2.sig of apc-0.2 and apc-0.3 (apc-0.13
by "those of apc-0.3"). The state proof does not lift the level: `signature` says the payer's rule is verified; whether
the payment is on a chain is 30.2's `settlement_record`, `inclusion_proof`, `finality_proven` as before. Since 0.21.1 the
qualified outcome is written only for an anchored block (32.10), so a report that carries it has every check of
`finality_proven` verified; on a block not anchored L2.sig is `not_evaluated`, the level is `none` (the ladder starts at
`signature`, 30.1) and the verdict `chain_incomplete`. The 30.2 row of
apc-0.2 names section 32 beside section 3.

### 32.8 Census, tests, measures (2026-11-01, this tree)
- tools/coverage_census.py (0.2.0): for a direct call whose decoded authorization names the payer and nonce of the log
  but whose signature does not recover the payer, with the payer's code in the list of 32.5 and the five replies of the
  `rpc` form in the saved files, the bundle is built with `payer_state` and verified; the class
  `direct_not_decoded|token_direct|code_not_known` keeps the payers whose code is not listed or whose replies are not
  saved; `disable` "msca_1271" switches the rule off (positive control); 0.2.1 (0.21.1) writes `l2_sig`, the L2.sig outcome, in each EIP-3009 record built (a bundle built with `payer_state` and one built without it are both `chain_incomplete` since 32.10; the field tells them apart: mutant MS62 lived on the verdict alone). Rerun of the 7 windows of 2026-10-22
  (oracle/msca_20261101/campaign_base_20261022_msca.json, oracle/msca_20261101/coverage_rerun.json, coverage_census 0.2.0
  on apc_verify 0.21.0): observed 2449, built 2289 (2261 on 0.20.0 and on 2026-10-22), every one `chain_verified`,
  chain_verified share 93.5 % (Wilson 95 % 92.4-94.4; before 92.3 %, 91.2-93.3), excluded 160 (before 188); the class
  `direct_not_decoded|token_direct|code_not_known` 28 -> 0, every other class unchanged (router 0x77e4be31 73, EntryPoint
  v0.6 38 + 6 + 1, batch settlement 13, ERC-1967 proxy not read 12, Kernel EIP-7702 direct 2, ...); x402-attributed
  1844 observed, 1844 chain_verified. Rerun on 0.21.1 (oracle/msca_20261101/coverage_rerun_0211.json, the 0.21.0 file
  kept beside it): observed 2449, built 2289 (the same bundles), verdicts chain_verified 2261 and chain_incomplete 28 (the 28 built with `payer_state`, L2.sig `not_evaluated:payer_state_block_not_anchored`: the census builds the `rpc` form, never anchored), chain_verified share 92.3 % (Wilson 95 % 91.2-93.3: the share of 0.20.0 again, with the 28 now BUILT and counted as `chain_incomplete` instead of excluded as `code_not_known`), excluded 160, the class `direct_not_decoded|token_direct|code_not_known` still 0; x402-attributed 1844 observed, 1816 chain_verified (98.5 %; 1844 of 1844 on 0.21.0: the 28 payments are facilitator-attributed).
- Real bundles: bundles/real_msca_20261101 (tools/make_bundles_msca.py from the census replies, the Transfer logs and
  the raw replies of oracle/msca_20261101: blocks, receipts, parent headers, eth_getProof of the payer with its two
  slots, of the implementation and of the owner at N-1 and N, from base.drpc.org; the `rpc` reads from the same
  endpoint): 56 bundles; on 0.21.0: 28 rpc (apc-0.2) `chain_verified`, L2.sig `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)`,
  payer_state declared_rpc, evidence_level settlement_record; 28 proof (apc-0.3) `chain_verified`, the same L2.sig,
  proven_at_parent_and_block, block_bound true, inclusion_proof. On 0.21.1 (32.10, measured 2026-11-01): 56
  `chain_incomplete` (exit 2), L2.sig `not_evaluated:payer_state_block_not_anchored`, K3 `not_evaluated:by_L2.sig`,
  evidence_level `none`, payer_state and block_bound as before: 0 of 56 verified, in either form (no bundle carries
  `canonical`); MANIFEST.json rebuilt offline by the tool (the 56 bundle files byte-identical). Anchored (32.10,
  tools/anchor_msca.py, ANCHORED.json): 28 more bundles m0NN_anchored_*.json = the proof form plus `canonical` and
  `l1_state`, verified with `--l1-checkpoint 0x6e4d8bb5…5895`: 28 `chain_verified`, L2.sig `verified (ERC-1271
  Circle_SingleOwnerMSCA 1.0.0)`, `finality_proven` (tools/regress.py runs the directory with that option; the rpc and
  proof forms ignore it). Raw replies of the anchoring: oracle/msca_20261101/anchor (4 games: facts, L1 proofs and
  replies at block 26321847; 116 L2 headers gzip; plan.json; SHA256SUMS). Raw replies: 392 gzip files, SHA256SUMS, 6.1 MB (6,081,932 bytes; 7.1 MB allocated on disk).
- tests/test_msca.py: 23 tests (Real, SignatureControls, AcceptedOnChain, PayerWalletBeside65, RpcForm, ProofForm with
  synthetic tries, Census), OK on the final tree (revised by the review of 2026-11-01 and by 0.21.1: where the rule's
  `verified` was asserted on an unanchored bundle the assertion now reads `not_evaluated:payer_state_block_not_anchored`). Positive control: every test of the file fails on 295b84d (the tree before this
  section: 316caba plus the 31.3 review fix) with an AssertionError, none with an import error (the file uses
  apc_verify.verify_bundle only).
- Mutants MS01-MSnn (tools/mutants03.py, apc_msca.py and the changed lines of apc_verify.py and tools/coverage_census.py;
  control on the unmutated copy first; HOME isolated, so PYTHONUSERBASE names the user site where `cryptography`
  lives): 49 mutants, 2 shards, journals passo2_20261101/mut_MS3_shard{0,1}.journal (the author's local records, not distributed): 47 killed,
  MS13 (v not checked: the recovery library alone rejects v 29 for a real r, since x = r + n leaves the field) and MS32
  (the payer_wallet note only for the EIP-7702 form) lived; a test each (v 29 with r = 2, the note for both Coinbase forms)
  and both killed (journals mut_MS13.journal, mut_MS32.journal, each after its own passing control). 0.21.1: the review
  patch moved the lines of MS10-MS13, MS23, MS47, MS48 and MS52 (re-targeted; 6492, N19, N20, HZ05, HZ07, HZ08 and MD30,
  stale since earlier commits, re-targeted too: a pattern found 0 times is STALE, never a kill) and adds MS64 (32.2
  executed although B3 says reverted, R2) and MS65-MS73 on the lines of 32.10 and of the owner's code at either end
  (N04). Run on this tree (two shards, journals passo2_r3_20261101/mut_MS_r3_shard{0,1}.journal (the author's local records, not distributed), control passing first in each): 59 mutants MS01-MS73, 58 killed, MS62 (census: payer_state not attached) lived — on the verdict alone a bundle built without the member is `chain_incomplete` too (32.2) — killed after coverage_census 0.2.1 writes `l2_sig` and test_msca.Census reads it (journal mut_MS62.journal, after its own passing control). The seven re-targeted older mutants were not re-run here.
- Whole suite one file at a time (passo2_20261101/suite_1.log (the author's local records, not distributed), Python 3.11.2): 54 files, 872 tests,
  54 OK, 0 failed (0.21.0); on 0.21.1 (passo2_r3_20261101/suite_0211.log (the author's local records, not distributed), Python 3.11.2, this tree): 56 files (tests/test_review_msca.py and tests/test_msca_anchor.py added), 897 tests, 56 OK, 0 failed; tests/test_msca.py, test_review_msca.py and test_msca_anchor.py (48 tests) also OK on Python 3.9.25 and 3.13.15; with the 28 anchored bundles (RealAnchored, 3 more tests): 56 files, 900 tests, OK — 49 files in one run, then tests/test_apc03.real_bundles taught that ANCHORED.json is a manifest, not a bundle (it refused it, closed table: 6 files red for that one reason, test_apc03 included re-run, 7 OK), test_regress run after the refreeze (17 OK); tests/test_msca_anchor.py (15) OK on 3.9.25 and 3.13.15 too; tests/test_high_s.py's `eoa_bundles` now leaves out the bundles that carry `payer_state` (a contract
  wallet's 65-byte signature is not an account's without code: its high-s twin is `failed:msca_high_s`, tested here).
  Frozen corpus: tools/regress.py check on the final tree, 1094 bundles, 0 differences (the 56 added bundles were
  justified by 56 `§32` rows of regress/CHANGES.md, refrozen with `write`, rows removed); on 0.21.1, 224 differences, all
  in bundles/real_msca_20261101 (56 bundles × exit 0 -> 2, verdict chain_verified -> chain_incomplete, K3, L2.sig),
  justified by 224 `§32.10` rows, check exit 0, refrozen with `write`, rows removed; no other bundle of the 1094 changes;
  then the 28 anchored bundles added: 28 `added` differences, justified by 28 `§32.10` rows, check exit 0, refrozen with `write` (1122 bundles, bundles/real_msca_20261101 84: 56 chain_incomplete, 28 chain_verified), rows removed, final check 1122 bundles, 0 differences; tests/test_regress.py 17 OK; before the change, 0 of the
  1038 frozen bundles carried a 65-byte signature that does not recover `from` or a `payer_wallet` beside a 65-byte
  signature, so no frozen verdict moves under 32.2 or 32.3.

### 32.9 Open after 0.21
- The plugin path (owner zero), an owner with code, an upgraded or other Circle implementation (UpgradableMSCA v0.7,
  the v0.8 module/multisig/WebAuthn owners): `not_evaluated` with the reasons of 32.6, until a real payment of each is
  measured. ERC-7739: the listed wallet does not implement it (probe `isValidSignature(0x7739…7739, "")` → 0xffffffff,
  measured 2026-11-01); no payer of the corpus uses it; no rule is written without a datum.
- The two direct calls of the census from payers delegated (EIP-7702) to Kernel 0.3.3 (section 12.5 reduces it for
  Permit2 digests only): the same reduction over the EIP-3009 digest is small and not written here (no bundle built).
- EIP7702Proxy's fallback to the payer's own key with a 65-byte signature beside `payer_wallet` (32.3 point 3).
- ERC-4337 EntryPoint payers (47 of the census): deferred by the author (2026-10-27).

### 32.10 Amendment 0.21.1 (2026-11-01; apc_verify 0.21.1; apc-0.2, apc-0.3, apc-0.13 as v2) — a `verified` read from the payer's state needs the block anchored
Why (review of 19b0ecd, 2026-11-01, R3, measured): a bundle whose two headers, state tries, transaction and receipt are
all made up — owner slot = a key of the forger's, implementation and code hashes the pinned ones, `payTo` and `value`
changed — gave L2.sig `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)`, `chain_verified`, evidence_level
`inclusion_proof`, block_bound true, payer_state `proven_at_parent_and_block`, without any key of the payer
(tests/test_review_msca.py forge, tests/test_msca_anchor.py). For an account without code a made-up block cannot change
who signs: the signer is in the signature. For a payer with code the signer is a DATUM OF THE BLOCK (the owner word of
32.5), and a `verified` read from it is worth what the block is worth. What ties a block to the chain in this verifier:
`rpc` state is DECLARED (section 4: carried RPC data); `block_bound` (section 6, B1-B4) binds the transaction and its
receipt to a block HASH — a made-up block hashes too; `canonical` with the L1 replies declared (section 6, O1-O4) is
carried by the bundle — a forger writes those replies too; only `l1_state` proven (Amendment 0.4, L1) reaches something
OUTSIDE the bundle: the eight L1 replies recomputed from proofs under an L1 header chained to the block hash the reader
gives (`--l1-checkpoint`). That is the predicate 30.1 names `finality_proven`, and it is the one taken here.

Rule. When the outcome of L2.sig is decided by values read from `payer_state` — the `verified (ERC-1271 …)` of 32.6
(owner word, implementation word, code hashes) — it is written only when the block that state belongs to is ANCHORED:
B1-B4, O1-O4 and L1 all `verified` (apc_verify.block_anchored; the report then says block_bound true, canonical `final`,
l1_state `proven`, and the level is `finality_proven`). Otherwise L2.sig is `not_evaluated:payer_state_block_not_anchored`,
K3 `not_evaluated:by_L2.sig`, with a note that says which state (declared by RPC, or proven under the carried header)
and what would anchor it; the verdict is at most `chain_incomplete` and the level `none` (30.1: `signature` does not
hold). The `rpc` form is never anchored, even beside an anchored `inclusion`: its values are declared, not read from
that block (anchored = `block_anchored` and payer_state `proven_at_parent_and_block`); the `proof` form is anchored only with `canonical` and
`l1_state` under the reader's checkpoint. The `failed` outcomes of 32.6 do not depend on anchoring (a forger does not
forge a failure) and stand as before; a plain `verified` of section 3 (the state says the payer had no code and the
recovery gives `from`) is not read from the state and needs no anchoring. The clause of 32.3 (review) reads "not
anchored" where the review wrote "not `proven_at_parent_and_block`". Owner with code: read at either end (32.6).

What it does not say. `not_evaluated` is not `failed`: the 28 real payments of 32.1 are the owner's as far as this
verifier can tell; what is missing is a datum outside the bundle. The checkpoint is the reader's: a reader who trusts a
checkpoint a forger hands over is shown whatever that L1 says (tests/test_msca_anchor.py, the limit test: a made-up block,
state and L1 under the forger's checkpoint give `verified`; the same bundle under no checkpoint or under the real
Ethereum checkpoint of the corpus does not). The rule moves the trust to the checkpoint and no further (30.2).

What it costs (measured 2026-11-01). bundles/real_msca_20261101: 0 of 56 verified (28 rpc, 28 proof), each
`chain_incomplete`, L2.sig `not_evaluated:payer_state_block_not_anchored`, level `none`; on 0.21.0 all 56 were
`chain_verified`. Frozen corpus: 224 differences, all of them (32.8). Census (32.8, rerun on 0.21.1): built 2289 as before, chain_verified 2289 -> 2261 (92.3 %, the share of 0.20.0), the 28 counted `chain_incomplete`; x402-attributed chain_verified 1844 -> 1816 (the census builds the
`rpc` form, which no checkpoint can anchor).

What anchors them (measured 2026-11-01, tools/anchor_msca.py, read-only JSON-RPC at one request per second, no key:
L1 ethereum-rpc.publicnode.com, L2 base.drpc.org; raw replies in oracle/msca_20261101/anchor with SHA256SUMS). Base's
dispute games of type 621 (AggregateVerifier) cover 600 blocks each with 20 intermediate roots, so a root stands every
30 blocks: every payment of this payer is at most 29 blocks before a root, inside the 64-header bound of section 6
(measured: 1 to 29 headers over the 28). The four games holding the 28 blocks (0x44d39acd…, 0xc34e08c2…, 0x68c0cebf…,
0x3a46a62f…; indexes 23768, 24272, 24560, 24704 of the factory) are all resolved DEFENDER_WINS and `isGameClaimValid`
at L1 block 26321847 (0x191a3b7), where the eight replies, the game code and the account and storage proofs of the ten
L1 accounts were read for each game (sources/l1proof_20261024/fetch_l1proof.py, driven by the tool). The 28 anchored
bundles (bundles/real_msca_20261101/m0NN_anchored_*.json, ANCHORED.json; the proof-form bundle plus `canonical` with
`l1_state`) under the one checkpoint 0x6e4d8bb54a650a38a950ccc2530a30314149ca5f316bc9f811f7834c10ce5895 (that L1
header's hash): **28 of 28 `chain_verified`, L2.sig `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)`, evidence_level
`finality_proven`, canonical `final`, l1_state `proven`, O4 `verified`**; the same 28 without the checkpoint:
`chain_incomplete`, L2.sig `not_evaluated:payer_state_block_not_anchored`, canonical `final`, l1_state `not_shown`, level
`none`; under the real Ethereum checkpoint of bundles/real_v04_l1state (another L1 header): the same. The `rpc` form
stays unanchorable by construction (declared, not read from a block). Found on the way: tools/canonical.py's binary search went DOWN when no
game of type 621 was within 64 indexes of the probe (`hi = mid`), which never meets one when the search starts low (the
type-621 games are the newest; the first 611 of the factory's 25511 games are type 0): corrected to go up, in both tools.

Tests (tests/test_msca_anchor.py, 12): the anchored case is built with a MADE-UP L1 — a header whose hash is the
checkpoint the test reader trusts; the game clone (Solady CWIA code with the root claim and the extraData of 20 roots,
our block the last), the AnchorStateRegistry, DisputeGameFactory, SystemConfig and SuperchainConfig proxies and
implementations with the pinned code hashes and the storage words apc_l1proof.replies reads, every one proven under
that header's stateRoot (apc_block.trie_root / trie_proof) — because a real block cannot carry a synthetic state (the
output root of O3 covers the block hash) and no real payment of this payer has a `canonical` member. Positive half: the
real signature under the synthetic state, anchored → `verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)`, `chain_verified`,
`finality_proven`, canonical `final`, l1_state `proven`; the same bundle with no checkpoint, another checkpoint, a game
in progress (O4 pending, canonical `proposed`), a challenger win, a game not respected, or no `canonical` →
`not_evaluated:payer_state_block_not_anchored`; the owner's own signature with the owner having code at the parent end,
the block end or both, anchored → `verified`. Anchoring lifts no failure: an altered signature or another owner in the
anchored state → `failed:msca_signature_…`; a receipt proven reverted in an anchored block (B3 failed, O4 and L1
verified) → `failed:recovers_…_not_from` (32.3, review clause: the state is not anchored and the token executed nothing).
Negative half: the 56 real bundles; the made-up block of the review; the declared `rpc` without `chain_tx` →
`failed:recovers_…`; an `rpc` state that says no code beside a real EOA payment → `verified` (no anchoring needed); the
predicate equals `finality_proven` on bundles/real_v04_l1state (with the checkpoint true, without it false), is false on
real_v03_canonical (L1 replies declared) and on every real_msca bundle, and each of its nine checks counts (any one
`failed:`, `pending:`, `not_evaluated:` or missing → false). Real data (RealAnchored, 3): the 28 anchored bundles under
their checkpoint → `verified`, `finality_proven`, canonical final, l1_state proven, block_bound true, at most 64 headers;
the same without the checkpoint, and under the checkpoint of real_v04_l1state → `not_evaluated:payer_state_block_not_anchored`;
the anchoring altered seven ways (a header of the L2 chain, root_index + 1, the status reply, the claim-valid reply, a
node of an L1 account proof, the L1 header's stateRoot, the replies at another L1 block) → never `verified`
(`not_evaluated` or refused), the checkpoint altered in one digit → `not_evaluated`, the unaltered one → `verified`.
Positive control: on 19b0ecd with the review patch's
tests/test_review_msca.py copied beside it, tests/test_msca_anchor.py 12 tests: 10 fail with an AssertionError, 0 errors;
the 2 that pass are the two whose assertions hold on 0.21.0 too (anchoring lifts no failure; a plain `verified` needs no
anchoring). tests/test_review_msca.py (13, review patch, revised for 32.10): 7 fail on 19b0ecd with an AssertionError,
0 errors (the 6 that pass are the controls and the tests that only kill mutants N02, N05, N07). RealAnchored on 19b0ecd
(anchored bundles copied beside): 3 of 3 fail with an AssertionError, 0 errors (19b0ecd gives `verified` with and without the checkpoint, and after every alteration of the anchoring). Measured 2026-11-01, Python 3.11.2.

Review 2 (2026-11-01, measured). (1) `block_anchored` read the block only: a real anchored bundle with its `proof` state
replaced by the `rpc` state of the same payment (bundles/real_msca_20261101 m001) gave `chain_verified`, L2.sig
`verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)`, `finality_proven`, payer_state `declared_rpc`; and under the reader's
checkpoint a 65-byte signature altered in one digit beside a declared unknown code (`0x6001`) gave
`not_evaluated:wallet_implementation_not_known`, where the same bundle without the checkpoint gave `failed:recovers_…`.
apc_verify now reads anchored as `block_anchored` AND payer_state `proven_at_parent_and_block`: both give
`not_evaluated:payer_state_block_not_anchored` and `failed:recovers_…` (tests/test_msca_anchor.py DeclaredBesideAnchored, 2;
mutant MS74). (2) Tests added for lines that mutants left alive: every `failed:` of section 3 beside a declared member
(v outside 27/28, a high-s twin: tests/test_review_msca.py), and an owner with code under an anchored state with a
signature of 66 bytes, a high s, v 29 or an r with no curve point → `not_evaluated:msca_owner_has_code`
(OwnerCodeAtEitherEnd). (3) The L1 block of the checkpoint is 26321847 (0x191a3b7; the header hash
0x6e4d8bb5…5895 on two L1 nodes), not 26321975 as first written. (4) tools/anchor_msca.py records scheme and host of
each endpoint, never the path or query (a key may sit there).

### 32.11 Amendment 0.21.2 (2026-11-02; apc_verify 0.21.2; every bundle version) — the verifier's environment: the sibling pack, the cause named, exit 64 without the signature library, the mandate suite skipping
Why (review of the public tree built from 95d2c11, 2026-11-02, F1-F4, measured): four sentences of the public README
were true of the test suite and false of the verifier. (F1) With `APC_AP2EV` unset and an ap2-evidence-pack v1.7.1 beside
the folder, `apc_verify.py` gave MP1-MP7 `not_evaluated:ap2_evidence_pack_unavailable`: the sibling default existed in
tests/test_mandate.py alone (its line 26). (F2) With `APC_AP2EV` right and an interpreter without `cryptography`, the same
outcome, and the note blamed `APC_AP2EV` ("APC_AP2EV names an ap2-evidence-pack v1.7.1 tree"). (F3) Without
x402-signature-vectors the verifier ended with a traceback, `ModuleNotFoundError: No module named 'lib'`, exit 1: the exit
section 5 gives to `chain_failed`, which section 29 (0.18) already calls a defect. (F4) With the corpus present and the pack
absent, tests/test_mandate.py raised RuntimeError, exit 1, where the README said "skips". These are conditions of the
reader's machine, not rules on the bundle: no verdict, check or exit code of a bundle read in a working environment
changes (tools/regress.py check, 0 differences besides the verifier string).

Rules.
(a) The pack's directory (section 31, Implementation). `APC_AP2EV` set: that directory and no other, as before (a path
that does not exist or holds other files is `not_evaluated:ap2_evidence_pack_not_1.7.1`, the hashes reported). `APC_AP2EV`
unset: the directory `../ap2-evidence-pack` beside the verifier's folder (apc_mandate.AP2EV_SIBLING, resolved from the file's
own path, not from the working directory); when it does not exist, `not_evaluated:ap2_evidence_pack_unavailable`; when it
exists it is read exactly as a directory the variable names, at the SHA-256 of tag v1.7.1 and no other (a sibling at another
tag is `not_1.7.1`). The variable, when set to a non-empty value, always wins over the sibling (an empty value counts as
unset; since 0.21.3 the note says so, "unset (or empty)": 32.12 (h)). The default is the one the public README and the
test suite state; the test suite's own default (tests/test_mandate.py) is unchanged.
(b) The cause named (section 31, Implementation). When MP1-MP7 are not evaluated, the note `MP1-MP7: <reason> (SPEC 31:
<cause>)` says in words which one of these it was, and what gets the pack: no directory (`APC_AP2EV` unset, no sibling); the
files at the directory are not those of tag v1.7.1; the `cryptography` package is not installed for this interpreter
(`pip install cryptography`, the interpreter's path named: a `ModuleNotFoundError` whose `name` is `cryptography` or a
submodule of it); a module `ap2_evidence` (since 0.21.3 also `sigsuite`, 32.12 (e)) already loaded from another place (that
place named); any other failure of the import (type and message). The outcomes of the checks are the two of section 31, unchanged: the cause is in the note and in
apc_mandate.cause(), never a new check value.
(c) The signature library (section 5, exit codes). apc_verify.py reads lib/eip712.py and lib/secp256k1.py of
x402-signature-vectors at import, from `APC_SIGLIB` or its default. When that import fails with a `ModuleNotFoundError`
whose `name` is `lib`, `lib.eip712` or `lib.secp256k1`, and apc_verify.py is the program run, it writes ONE line on standard
error naming the path tried, the library, and the two ways to have it (`APC_SIGLIB`, or the sibling checkout), writes no
report, and exits 64: there is no verifier, hence no verdict, and 64 is the code of this table for an invocation the reader
has to correct (section 5, `--require-level` out of grammar), the only one of the table that judges neither the bundle
(0-3) nor the writing of a report (74). Imported as a module, the same condition is an ImportError with the same sentence
(a test or a tool reads it as such). A `ModuleNotFoundError` for any other module is not this case and is raised unchanged:
the guard is closed on the three names, a defect of the verifier must not be dressed as a missing library. Since 0.21.3
the library is also bound to the bytes of tag v1.4.0, and standard error closed or full leaves the exit at 64: 32.12 (f), (g).
(d) The mandate suite (tests/test_mandate.py). After `real_corpus.need("real_svm_mandate")` (the corpus first, as before),
when the pack is not usable or openssl is absent the module raises unittest.SkipTest with the reason of (b) and the
dependency's name: `unittest discover` (the CI's command) and tools/run_ordered.py (through tests/__init__.py) count
it as skipped, with the reason, never as passed and never as an error; `python3 -m unittest tests.test_mandate` alone
stops at the SkipTest message, exit 1, as it does for the corpus (tests/real_corpus.py). A skip is shown (`skipped=N`), it
is not a pass; until 0.21.1 the module raised RuntimeError (exit 1, an error under `discover` too).

Tests (tests/test_amend0212.py, none needs the corpus but MandateSuiteSkips; six of the first seven failed on 95d2c11 with an
AssertionError, the seventh, test_another_missing_module_is_raised_as_it_is, being the closure control of the guard, measured
2026-11-02): a copy of the verifier beside a symbolic link to the pack and no variable (MP1 `verified`; without the link,
`unavailable` with "APC_AP2EV is unset" in the note; a sibling with other files, `not_1.7.1`; the variable set to a path
that does not exist beside a good sibling, `not_1.7.1`); a `cryptography` package that raises at import put first on
PYTHONPATH (MP1 `unavailable`, note with `pip install cryptography`, control without the blocker `verified`); `APC_SIGLIB`
at an empty folder (exit 64, standard output empty, one line on standard error without "Traceback", control exit 2;
`import apc_verify` an ImportError naming `APC_SIGLIB`); the mandate suite under `discover` with the pack absent and with
`cryptography` blocked (rc 0, `skipped=1`, the reason). tests/test_mandate.py: the sibling case added to the loader test
(the sibling is patched, never the machine's), and `test_sibling_default_loads_the_pack`. Measured without the
dependencies as well, on the interpreters of the machine without `cryptography` (3.9.25, 3.13.15): the note of (b).
Measured 2026-11-02 on this tree (the author's working tree with the corpus): tools/run_ordered.py on Python 3.11.2, 932
tests, OK (skipped=11), 1692 s; `tools/regress.py check`, 1122 bundles, 0 differences (the verifier string apart), then
refrozen with `write`; tests.test_amend0212, test_mandate and test_hostile OK on 3.9.25 and 3.13.15 with `cryptography`
(skipped=1 each: a corpus set); test_amend0212 on 3.9.25 and 3.13.15 without `cryptography`: 4 OK, 3 skipped, each skip
naming the package and the interpreter. Mutants on the new lines, one at a time: 13 of 13 killed by an AssertionError.

### 32.12 Amendment 0.21.3 (2026-11-02; apc_verify 0.21.3; every bundle version) — the code run is the code hashed: the pack and the signature library; a dependency that cannot load fails the CI
Why (review of 7e4531e, 2026-11-02, measured). (1) The pack: the hashes of 32.11 (a) were taken on the two files, then
`ap2_evidence` was imported BY NAME with the folder first on sys.path, so a package `pqcrypto/sigsuite/` beside the hashed
`sigsuite.py`, a `cryptography/` package in the folder or a cached bytecode file whose header matches the source ran instead,
while the report gave the hashes of v1.7.1: a planted package made MP1 `verified` on a pack whose signature was altered; a
FIFO named `ap2_evidence.py` stalled the verifier. (2) The signature library: `APC_SIGLIB` (or its default) was put first
on sys.path and `lib.eip712`, `lib.secp256k1` were imported by name, bound to no hash at all: any two files of those names
ran as the library (the stand-in of tools/siglib_standin, a copy with one byte changed), and a `lib/__init__.py` or a
cached bytecode file in the folder ran with them, while the README named tag v1.4.0. (3) With the signature library absent
and standard error closed (`2>&-`) or full (`2>/dev/full`) the exit was 1 (a traceback: read as `chain_failed`) or 120 (the
interpreter's last flush), not 64. (4) The CI (.github/workflows/ci.yml of the public tree) checks out the two sibling
repositories at their tags, but every test that needs the pack skips when it is not usable: a tag moved, a checkout step
broken or `cryptography` missing left the CI green with the mandate checks never exercised. The same defect in two
places (1, 2) and a gate that could not fail (4): none is a rule on a bundle; no verdict, check or exit code of a bundle
read in a working environment changes (tools/regress.py check, 0 differences besides the verifier string).

Rules.
(e) The pack: the code run is the code hashed (section 31, Implementation). The two files `ap2_evidence.py` and
`pqcrypto/sigsuite.py` are read as regular files, opened without blocking (a FIFO, a directory or a device is absent:
`not_1.7.1`, hash `null`), hashed, and when both hashes are those of 32.11 (a) THOSE SAME BYTES are compiled and run as the
modules `sigsuite` then `ap2_evidence` (apc_mandate._load): no import by name, no package, extension, cached bytecode or
other file of the folder can stand in for them, and apc never puts the folder on sys.path (the pack's own code does, at
the top of `ap2_evidence.py`; its only import after that, `sigsuite`, is the module already run from the hashed bytes, so
no import resolves through the folder: measured 2026-11-02 with an audit hook on the load), sys.path is restored after, and
sys.modules is left as it was found (the two names present before are present after, absent before, absent after). A module
of either name already loaded from another place is refused as in 32.11 (b). The pack's own imports (`cryptography`,
`tempfile`, ...) resolve on the process's sys.path, and the `openssl` it runs for the TSA and x5c checks is the one on PATH:
that is trust in the interpreter's environment, as for the verifier itself.
(f) The signature library: the code run is the code hashed (section 5, exit codes; apc_siglib.py). `lib/eip712.py` and
`lib/secp256k1.py` of x402-signature-vectors tag v1.4.0 have the SHA-256
8f1ae28568fdeab8713c3595631ab313ec9cc14bddc6772e0dd78946b804e608 and
7e10ceb85840d1049dc2fbdef4c03e14a5af9a29c78eba54d4393695402a1f69 (read 2026-11-02 from `git show v1.4.0:lib/...` of the
public repository, github.com/robertolocatelli81-dev/x402-signature-vectors, commit 985b46d; the same bytes in a fresh
clone of the tag). The verifier (apc_verify.py, and apc_block.py, apc_ap2.py and the tools that need Keccak-256 or the
recovery: every one through apc_siglib.load) reads the two files of the directory `APC_SIGLIB` names (set to a non-empty
value; an empty value counts as unset) or of its default, as regular files opened without blocking, hashes them, and runs
THOSE BYTES as the modules `lib.eip712` and `lib.secp256k1` of a package `lib` that holds nothing else (`import lib.other`
is a `ModuleNotFoundError`); the directory is never put on sys.path. The files absent, not regular, or with any other hash:
no verifier, the one line of 32.11 (c) on standard error (the path tried, the file and the hash found against the one
expected, the two ways to have the library) and exit 64; imported as a module, an ImportError with that sentence
(apc_siglib.SiglibError). The other programs of this folder that need the library, apc_block.py, apc_ap2.py, apc_batch.py,
apc_report.py and apc_mcp.py, do the same (apc_siglib.guard, the program's name at the start of the line): run as the
program, one line and exit 64 (for apc_batch, 1 is a D1, D3 or D4 failure, so a traceback's 1 read as one) and nothing
of a report; imported as a module, a SiglibError with the same sentence; until this amendment the five ended with a
traceback, exit 1 (the ImportError of apc_verify, or the SiglibError of apc_block, raised as it was). The 35 tools under
tools/ that need the library, directly or through apc_verify, apc_block or another tool, at their start or inside a
function (anchor_msca, canonical, census_eip3009, check_eip3009_oracle, count_removed_zero, coverage_census,
fetch_authcap_permit2, fetch_authcapture, fetch_base_eip3009, fetch_payer_wallets, fetch_permit2_state, fuzz_bundles,
gen_mandate_fixtures, inclusion, log_pairs, make_bundle_issue1062, make_bundle_reverted, make_bundles_authcap,
make_bundles_l1state, make_bundles_msca, make_bundles_negatives, make_bundles_permit2, make_bundles_permit2_state,
make_bundles_v02, make_bundles_v03, make_corpus_manifest, make_real_bundles, make_webauthn_oracle, rebuild_corpus,
regress, run_ordered, scan_logs, scan_webauthn, synth_mandate_block, world_bundles), do the same since the second
commit of this amendment (2026-11-02; the version stays 0.21.3: no byte of apc_verify.py changes):
`apc_siglib.guard("tools/<name>", __name__ == "__main__")` right after the root is put on sys.path and before the first
import of this folder's code (the three whose sys.path held only tools/, fetch_authcap_permit2, fetch_authcapture and
make_bundles_v03, put the root first); run as the program, one line `tools/<name>: <sentence>` and exit 64, nothing on
standard output; imported as a module, a SiglibError with the same sentence; with the library, nothing changes (the
load the guard does is the one their imports did, now at the start also for the three that imported inside a function:
fuzz_bundles, gen_mandate_fixtures, regress). Until then each ended with a traceback, exit 1 (7 to 26 lines of
standard error, measured on c0f699c: 32 when run without arguments, `tools/regress.py check` too; fuzz_bundles and
gen_mandate_fixtures only once a run reached the import). The 17 other tools with a `__main__` do not reach a load of
the library (apc_mandate's `_keccak_hex` is reached by check(), not by eval_terms(); apc_xrpl's secp256k1_verify is
not called by make_bundles_xrp) and are not guarded. A module `lib`,
`lib.eip712` or `lib.secp256k1` already loaded from another place (one without
apc_siglib's mark) is refused the same way, the place named. Once loaded in a process the modules stay (every `from lib.x
import` of the verifier and the tests resolves to them); a second load returns them. Consequence, stated: the stand-in of
tools/siglib_standin is no longer accepted as the verifier's library (`APC_SIGLIB=tools/siglib_standin` is exit 64); it
remains what tests/test_standin.py tests by file path, an independent implementation checked on real data. The
`ModuleNotFoundError` guard of 32.11 (c) is replaced by this one (the import by name it guarded no longer exists); any
other failure is raised unchanged.
(g) Standard error closed or full (32.11 (c)). The line is lost and the exit stays 64 (as 74 does, 29.3): never a traceback's
1, never the interpreter's 120.
(h) An empty `APC_AP2EV` counts as unset (as before) and the note says "APC_AP2EV is unset (or empty)".
(i) The CI must fail when a dependency cannot load (.github/workflows/ci.yml, written by the public-tree tool). A step
runs `tests/test_amend0212.py` with `APC_REQUIRE_DEPS=1`: under that variable every test that would skip for the pack
FAILS instead with the skip's reason (the real corpus still skips: it is not distributed, 33), tests/test_mandate.py raises
RuntimeError instead of SkipTest when the pack or openssl is missing (the corpus skip before it unchanged), and the class
DependenciesRequired (skipped without the variable) asserts that the library of (f) is loaded at the two hashes, that the
pack of 32.11 (a) is loaded (apc_mandate.cause() None) and that the fixture `tests/fixtures_mandate/base.json` gives MP1
`verified`. A skip is visible in a log; a failure stops the gate: this is the difference the step buys.

Tests (tests/test_amend0212.py; each failed on 7e4531e with an AssertionError, measured 2026-11-02, but RequireDepsSwitch,
which checks the switch of this test file itself and passes there; those of (e) come from the
review of 7e4531e). (e) PackCodeIsTheHashedBytes (7): a planted `pqcrypto/sigsuite/` package and a planted
`cryptography/` package beside the two files (no marker written, MP1 `verified`), a bytecode file whose header matches
`sigsuite.py`, a module `sigsuite` from elsewhere (`unavailable`, the place named), a FIFO named `ap2_evidence.py`
(`not_1.7.1` within the timeout), an empty `APC_AP2EV` (h), exit 64 with standard error closed and full (g), sys.path and
sys.modules as found after the load. (f) SignatureLibraryIsTheHashedBytes: a `lib/` of other bytes (the stand-in, and the
two files of the tag with one byte appended: exit 64, standard output empty, one line naming the path, the file and
"v1.4.0", control exit 2 on the untouched copy); a planted `lib/__init__.py` and a planted bytecode file whose header
matches `lib/eip712.py` (no marker written, a verdict); a module `lib.eip712` from elsewhere (`import apc_verify` an
ImportError naming the place; as the program, exit 64), and one replaced after the load (a second load refuses
it); a load failed half-way leaves no module of the three names; after `import apc_verify` the directory is not on sys.path, the two
modules carry the hashes of (f), `import lib.other` with `lib/other.py` in the folder is a `ModuleNotFoundError`; an empty
`APC_SIGLIB` with the default present, a verdict (exit 2); OtherProgramsWithoutTheLibrary (2): the five programs with the
library absent and with one byte appended (exit 64, standard output empty, one line without "Traceback" that starts with
the program's name, the control exit of each with the library), with standard error closed and full (64), each imported
as a module (a SiglibError with the same sentence), and a failure of the load that is not a SiglibError raised as it is
(the guard is closed on that one type); ToolsWithoutTheLibrary (3, second commit of 2026-11-02): the list of the 35
tools and, in each, the guard line with its own name before the first import of this folder's code; each tool run as the
program with the library absent and with one byte appended (exit 64, standard output empty, one line without
"Traceback" that starts with `tools/<name>: the signature library`, naming the directory tried and "APC_SIGLIB" or
"v1.4.0"); each imported as a module without the library (exit 1, `apc_siglib.SiglibError: tools/<name>: ...`) and with
it (the control: exit 0 and nothing on standard error, but gen_mandate_fixtures, `KeyError: 'AP2_SDK_PATH'`,
synth_mandate_block without the real corpus, the SkipTest of tests/test_mandate, and in the public tree anchor_msca and
make_bundles_l1state, whose saved RPC replies of sources/l1proof_20261024 are kept with the corpus: a closed list of
four, never the library's sentence; measured in the public tree, where the first run of this control failed on the
last two). (i) DependenciesRequired, and `APC_REQUIRE_DEPS=1` with
`APC_AP2EV` at a folder without the pack: the pack tests of this file FAIL (`failures=`), none skips; tests/test_mandate.py
under `discover` with the corpus present, the pack absent and the variable: `errors=1`, RuntimeError (MandateSuiteSkips).
Measured 2026-11-02 on this tree (the author's working tree with the corpus, Python 3.11.2): this test file on the code of
7e4531e, the tests of (e) 7 of 7 failed with an AssertionError (9 subcases), those of (f) 7 of 7 (9 subcases),
DependenciesRequired and the new test of MandateSuiteSkips (under the variable) too; RequireDepsSwitch passes there (it
tests this file's switch, not the verifier); OtherProgramsWithoutTheLibrary, 2 of 2 failed on bee5c17 (26 subcases: a
traceback's exit 1, or 120 with standard error full); tests.test_amend0212 here, 26 tests, OK (skipped=1: DependenciesRequired
without the variable), and 1 OK with `APC_REQUIRE_DEPS=1`; `APC_SIGLIB=
tools/siglib_standin` on tests.test_apc03: the ImportError of (f) naming both files and their hashes. Mutants on the new
lines (apc_siglib.py 8, apc_verify.py 4, the two test switches 2), one at a time, each file restored and checked by
sha256: 14 of 14 killed by an AssertionError; in review two more lived, the early return of a second load when any one of
the three modules is apc_siglib's (`all` -> `any`) and the restore of sys.modules after a load failed half-way removed,
killed by the two tests added for them (both re-run on the final tree: killed); on the guard of the five other programs (apc_siglib.guard 9, its five calls 15:
`except Exception`, the name dropped, the branch inverted, ImportError for SiglibError, no newline, `except OSError` only,
no dup2, exit 1, None returned; each call with True, with False, with apc_verify's name), 24 of 24 killed by an AssertionError. Second commit (2026-11-02, the 35 tools):
ToolsWithoutTheLibrary on the code of c0f699c (the test file copied into a checkout of it), 3 of 3 failed, 140 subcases,
every one an AssertionError (a traceback's exit 1; the usage of regress on standard output; no guard line); on this tree,
3 of 3 OK in 8 s; tests.test_amend0212, 29 tests, OK (skipped=1), and 29 OK with `APC_REQUIRE_DEPS=1`. Mutants on the
guard lines of the tools, one at a time, each file restored and checked by sha256 (the branch inverted, the folder
dropped from the name, the guard line removed in regress and in run_ordered, `False` and `True` in place of the
`__main__` test, the root not put on sys.path in make_bundles_v03, `load()` in place of the guard, the guard after the
environment-dependent inserts of gen_mandate_fixtures, the name misspelt, exit 64 also with the library, the exit
swallowed): 12 of 12 killed by an AssertionError. On the final tree of this amendment (2026-11-02): tools/run_ordered.py, 951 tests, OK
(skipped=12), 1756 s; `tools/regress.py check` with `APC_AP2EV` at the pack of v1.7.1, 1122 bundles, 0 differences, 0
unjustified, 165 s (the verifier string is unchanged, nothing refrozen; without the pack the 14 MP checks of the two
mandate bundles differ, `not_1.7.1`: the environment, not the code).

### 32.13 Amendment 0.21.4 (2026-11-03; apc_verify 0.21.4; every bundle version) — the x402 ResourceInfo as the specification writes it
Source: x402-foundation/x402 @ 0aee759 (the pin of section 0), `specs/x402-specification-v2.md`, the ResourceInfo table:
`url` string, required; `description` string; `mimeType` string; `serviceName` string, "Printable ASCII, max 32
characters"; `tags` array of strings, "Max 5 entries; each printable ASCII, max 32 characters"; `iconUrl` string,
"Absolute `https`/`http` URL to an icon representing the service. Max 2048 characters." The same commit writes rules
for the last three members a second time, in `specs/extensions/bazaar.md` ("Service Metadata on `resource`",
Validation Rules, which "SDKs and facilitators MUST apply ... during extraction"): `serviceName` and each tag non-empty,
tags deduplicated case-insensitively, `iconUrl` with no userinfo, no IP literal and no `localhost`; a field that fails
its rule is dropped ("Hard rejection only happens at the JSON envelope level"). Its TypeScript schema
(`typescript/packages/core/src/schemas/index.ts`) takes `null` for any optional member as absent and requires
`serviceName` and each tag non-empty.

Until 0.21.3 every reader of a ResourceInfo here (`payment_payload.resource` and `payment_required.resource` of
apc_verify, apc_svm, apc_xlm, apc_xrp, apc_authcap and apc_permit2: twelve places) knew `{url[, description,
mimeType]}` only (apc_authcap's `payment_payload.resource` also `method`) and refused the last three as unknown
members, so a 402 response that a real server sends (agent-payment-chain issue #1, 2026-11-03: `serviceName`, `tags`,
`iconUrl`) was refused, exit 3; and none of them checked the type of `description` or `mimeType` (`"description": 5`
and `"description": null` passed). apc_ap2 knew the three members but took `null` for any optional one, did not check
that `iconUrl` is an absolute http(s) URL, and refused an empty `serviceName` or tag.

From 0.21.4 one rule, in every place (apc_verify.resource_info; apc_ap2 the same rule in its own schema errors):
- closed: a member outside the six is refused with its path, as before; `url` a non-empty string;
- `description` and `mimeType`: strings (`null` or another type refused);
- `serviceName`: a string of 1 to 32 characters, each in U+0020..U+007E;
- `tags`: an array of at most 5 strings, each of 1 to 32 characters in U+0020..U+007E;
- `iconUrl`: a string of 1 to 2048 characters, each in U+0021..U+007E: `http://` or `https://` (the scheme's ASCII
  letters in either case, RFC 3986 3.1), then an optional userinfo ending in `@`, then a host that is not empty and does
  not start with `:` (RFC 9110 4.2.1 and 4.2.2: an http(s) URI with an empty host is invalid), the authority ending at
  the first `/`, `?` or `#`.

Our reading where the texts differ (declared): the upper bounds are those of the ResourceInfo table, and a value out of
them is refused with its path, not dropped (the Bazaar rule is for a catalog's extraction; a verifier that dropped a
member would verify a ResourceInfo the server did not send); `null` is refused, not taken as absent; the empty string is
refused for `serviceName` and a tag: the table sets no lower bound, but the Bazaar rule and the TypeScript schema of the
same commit require one character, and we follow them (the author's decision, 2026-11-03); the Bazaar rules on the
`iconUrl` host (IP literal, `localhost`) and on duplicate tags are not applied.

What a reader of the report does with these three members is not changed: they are read for their form only and decide
no check (K4 compares `url` alone, as before). apc_authcap keeps the member `method` it read in
`payment_payload.resource`.

Measured (2026-11-03): tests.test_amend0213, 12 tests, OK on Python 3.9, 3.11 and 3.13 (in the public tree two skip:
they need bundles/authcap_real_20261026 and the six sets named below) — the table (80 resources, 20 accepted and 60
refused; each outcome read off the table, and where the table is silent, `null`, the empty string, an empty host, off
the reading above) through apc_verify.resource_info, apc_ap2._resource and apc_ap2's x402 payload; 20000 generated
resources (members of the grammar and unknown ones, values of every JSON type and at the borders) on which the two
readers agree, both outcomes over 500 times; a syntax check that no reader of a resource keeps its own list and that
each `X["resource"]` passed to a call goes to resource_info, two places in each of the six readers; on the real corpus
(real, real_svm, xlm_real_20261026, xrp_real_20261026, real_permit2, authcap_real_20261026) each reader refusing six
`tags` in `payment_payload.resource` and in `payment_required.resource` with the path; a synthetic 402 of the shape of
agent-payment-chain issue #1 read with K4 verified, and a refusal naming the path of each member out of rule;
apc_authcap's `method` kept. On the code of 0.21.3 the 12 fail (5 failures, 7 errors). Mutants of the changed lines,
each file restored and checked by sha256: the author's 24 targeted mutants, 24 killed; an independent review's 68 on the
first version of this amendment left 11 alive (seven places of apc_svm, apc_xlm, apc_xrp and apc_permit2 that could skip
the rule, the second tag unchecked, DEL or `!` in iconUrl, one equivalent) and found `httpſ://` accepted (U+017F folds
to `s` under re.IGNORECASE); on the version with that review's fixes, 33 mutants (those 11 places and cases again, the
new iconUrl pattern in both modules), 32 killed and one equivalent (`(?![:@])` for `(?!:)` before a class without `@`: 0
differences on 471 453 strings, 9 467 for a non-equivalent control). On this final version (serviceName and tags
non-empty), the review's 101 mutants re-applied where their line still exists (85) and two on the lower bound (1 back to
0 in each module): one of the 87 had become the unmutated line and is not counted; of the 86, 84 killed and 2 equivalent
(the one above, and `min1=False` on apc_ap2's iconUrl, whose pattern already requires a character). `tools/regress.py
check`, 1123 bundles, 0 differences (no bundle of the corpus carries one of the three members), then refrozen under
0.21.4; the list rewritten: verifier and date only. On the final version: `tools/regress.py check` 1123 bundles, 0
differences; tools/run_ordered.py 1002 tests, OK (skipped=12), 2010 s; in the public tree, `unittest discover` on Python
3.9, 3.11 and 3.13, 290 tests, OK (skipped=132).
### 32.14 Amendment 0.21.5 (2026-11-03; apc_verify 0.21.5; every bundle version) — a member of the PaymentRequired that x402 does not define is ignored and reported, not refused
Source: x402-foundation/x402 @ 0aee759 (the pin of section 0), `specs/x402-specification-v2.md`, PaymentRequired:
`x402Version`, `error`, `resource`, `accepts`, `extensions`; v1 (the `PaymentRequirementsResponse` of section 21, SPEC 0.13):
`x402Version`, `error`, `accepts`. Neither version says what a reader does with another member (no rule on unknown or
additional members in the specification at 0aee759 nor on `main` at 2026-11-03). The reference implementation of the same
repository (`typescript/packages/core/src/schemas/index.ts`, `PaymentRequiredV2Schema` and `PaymentRequiredV1Schema`,
plain `z.object`) accepts such a member and drops it.

Until 0.21.4 every reader here (apc_verify, apc_svm, apc_xlm, apc_xrp, apc_authcap, apc_permit2 for v2; apc_v1 for v1)
refused such a member, so the 402 response a real server sends was refused whole, exit 3: agent-payment-chain issue #1,
comment of 2026-11-03 (the POPCORN witness service's 402 as received, with a member `payment_diagnostics`).

From 0.21.5, one rule in the seven places (apc_verify.payment_required_obj):
- a member of the PaymentRequired outside the members the specification defines for that version is not read and decides
  no check; the report names it in `notes` ("payment_required: member(s) the x402 specification does not define, ignored
  and not read (SPEC 32.14): [...]"), a name longer than 64 characters shown as its first 64 and `...`, at most 16
  names and the count of the others;
- every member the specification defines keeps its rules, and nothing inside them changes: ResourceInfo stays closed
  (32.13), each `accepts` entry is read as in 0.21.4, `extensions` keeps its rules of sections 13 to 15;
- the bounds of section 29 still apply to the whole document, the ignored members included;
- every grammar of a bundle version that carries payment_required and is called closed (sections 1, 7, 12, 20, 21, 25,
  26) reads, from 0.21.5, with this one exception: the top level of payment_required;
- not changed, and open: a member of `payment_required.extensions` whose name is not one of the extensions of sections
  13 to 15 (`offer-receipt`, `builder-code`, `payment-identifier`) is carried and not read, as before, and the report
  does not name it (the 402 of issue #1 carries `bazaar` and `popcorn-witness`); under `--drafts` one draft profile of
  section 23 (`x402-pr3741`, RM4) reads `extensions.bazaar.info.input.method`, and only when the resource carries the
  draft member `method`: on the 402 of issue #1 nothing of `bazaar` is read. Naming the extensions not read is a later
  amendment.

Our reading, declared: the specification is silent and the reference implementation drops the member; a verifier that
refused it could not read the 402 that servers send, and one that dropped it in silence would not say what it did not
read. Reporting is the third way (the author's decision, 2026-11-03). Inside the PaymentRequired nothing changes:
ResourceInfo stays closed, and K4 compares `accepted` with each `accepts` entry member by member, so a member that
`accepted` does not carry makes the entry not match. An unknown member of an `accepts` entry is refused only where a
reader reads the entry by its grammar: the `exact` entries on an EVM network (apc_verify, apc_permit2), on Solana
(apc_svm) and on a v1 EVM network (apc_v1); apc_xlm, apc_xrp and apc_authcap, and every other entry, read it only through
K4 (as in 0.21.4).

## 33. The real corpus as a LIST (2026-11-01, local; corpus/MANIFEST.json, format `apc-corpus-0.2`, `apc-corpus-0.3` by 33.10; tools/rebuild_corpus.py, tools/make_corpus_manifest.py) — what is distributed, what is rebuilt, what is accepted

The public tree does not carry bundles/ (the fascicles of real payments) nor oracle/ (the raw RPC replies they were
built from). It carries a LIST of those payments, `corpus/MANIFEST.json`, and a tool that rebuilds every listed bundle
from an endpoint chosen by whoever runs it. No reply of a third-party service is redistributed: the list holds chain
facts (identifiers, positions, consensus fingerprints), our own reconstruction parameters, and the digests of our files;
the bytes of each bundle are made again, by the reader, from the chain. The tests that read bundles/ or oracle/ skip
with the reason when they are absent, and name the rebuild command when one exists (tests/real_corpus.py, 33.8); they never pass on an empty glob
(`unittest discover` and tools/run_ordered.py report the skip; `python3 -m unittest tests.<name>` alone stops at the
SkipTest message, exit 1, since unittest imports a module named on the command line before the package loader runs).

### 33.1 What is of the CHAIN and what is OURS, per set (the `real` and `reconstructed` texts of each set repeat it)
- EVM EIP-3009 (bundles/real, real_world_20261026, real_v02, real_v02_misc, real_v03, real_msca_20261101, real_reverted,
  real_issue1062, the EVM negatives): CHAIN = the transaction object, the AuthorizationUsed and Transfer logs, the block
  header and the receipts (inclusion), the state proofs and state replies (payer_state). OURS = the x402 envelope
  (`accepted`, `settlement`) reconstructed from calldata and logs by the rules each README states; in real_issue1062 the
  settlement reply quoted from the public issue (an x402 errorReason, a network and a transaction hash, carried in the list
  under `ours.settlement` with its source).
- real_v02_wallet, real_v02_passkey (b001), real_v03 with `payer_wallet`: CHAIN = as above; `payer_wallet` holds three
  state replies of an archive endpoint (code, ERC-1967 slot, ownerAtIndex) — declared data in SPEC 3 already; 33.5.
- auth-capture (authcap_real_*): CHAIN = transaction and receipt; OURS = payload and reply from the authorize call;
  `provenance` names the fetch.
- Permit2 (real_permit2): CHAIN = transaction, receipt (its two logs), for p029 the inclusion and `payer_code`; OURS = the
  envelope from the proxy calldata.
- Solana (real_svm, real_svm_mandate, the SVM negatives): CHAIN = the confirmed transaction (signed message); the
  execution record (`slot`, `blockTime`, `meta`: balances, inner instructions, err) is what the endpoint reports of the
  execution and is not covered by a signature a reader can check offline — declared data, 33.5. OURS = the payload (fee
  payer signature zeroed), `accepted` (for m001 the memo and the accepted of the payment made for this work), and in
  real_svm_mandate the `mandate`: an ap2-evidence-pack built by us with test keys, carried whole in the list.
- XRPL (xrp_real_20261026, the XRPL negatives): CHAIN = tx_blob, meta, ledger header and the whole transaction set
  (inclusion). OURS = the requirements, the reply, `provenance`.
- Stellar (xlm_real_20261026): CHAIN = envelope, result and events of a testnet transaction; THIRD PARTY, not of the chain:
  the `facilitator` member (the signer list of x402.org's /supported). The set is `local_only` (33.3): the facilitator
  reply is not redistributed and not rebuildable from a chain, and Stellar testnet keeps a bounded history and is reset.
- real_v03_canonical, real_v04_l1state: `canonical` (L1 eth_call replies, dispute game, L1 proofs) is chain data but needs
  an L1 archive endpoint and the game search of tools/canonical.py: `local_only` in this version of the list.

### 33.2 The list (closed at every level: a member outside this grammar is refused with its path, exit 3)
The list carries no address of a third party in clear (format 0.2, 2026-11-01, the author's decision): the payer is
derived during the rebuild from the AuthorizationUsed log (topic 1) or from the Permit2 calldata, the Solana fee payer
from account 0 of the signed message (the pinned id is its signature), the owner of an MSCA payer from the state proof
and pinned only by `owner_keccak` (keccak256 of its 20 bytes). Addresses of CONTRACTS stay (token, escrow,
implementation, EIP-7702 delegate). Format 0.1 (`chain.state.payer`, `chain.state.owner`, `chain.fee_payer`,
`ours.accepted`) is refused as unknown members. Residual, declared: `ours.mandate` is our own fixture (test keys, a
throwaway merchant made for this work), `ours.settlement` of real_issue1062 holds a transaction hash and no address.
```
{"format": "apc-corpus-0.2", "written": <UTC>, "verifier": "apc_verify X.Y.Z",
 "oracle": <33.8>,
 "sets": {<name>: {"dir": "bundles/<name>", "recipe": <33.4>, "bundle_versions": [..], "real": <text>, "reconstructed": <text>,
                   "rebuild": "bytes"|"content"|"verdict"|"local_only", "reason": <text, required for local_only>,
                   "serialization": {"indent": 1, "sort_keys": bool, "newline": bool}, "params": {..}, "count": N}},
 "bundles": [{"file": "<name>/..json", "set": <name>, "network": <CAIP-2>, "bundle_version": ..,
              "recipe": <33.4, only when it differs from the set's>, "chain": <33.4; `anchor` by 33.10>, "ours": {..},
              "sha256": <of our file>, "content_sha256": <of the bundle without `provenance`, canonical JSON>,
              "verdict": <frozen>, "checks_sha256": <of the frozen checks map, canonical JSON>}]}
```
`count` must equal the entries of the set; files are unique and under their set; digests are 64 lowercase hex; EVM hashes
`0x` + 64 lowercase hex, XRPL hashes 64 uppercase hex, Solana ids base58. tools/make_corpus_manifest.py writes it from the
local corpus and the frozen verdicts of regress/VERDICTS.json; `python3 tools/rebuild_corpus.py --check-manifest` reads it.

### 33.3 Levels of rebuild, declared per set and measured per bundle
`bytes`: the file written is byte-identical to ours (sha256). `content`: identical but for `provenance`, which names the
endpoint host and time of the new fetch (authcap, XRPL). `verdict`: apc_verify gives the same verdict and the same checks
(digest of the map); the bytes may differ where a member is declared data of an endpoint (Solana meta; payer_wallet).
`local_only`: not rebuilt, reason in the list. The report says, per bundle, the level reached; a bundle below its set's
level, a refused reply or a mismatch is exit 1. The levels are ordered: bytes > content > verdict.

### 33.4 Recipes and what each ACCEPTS (the chain members of an entry; what is declared, not proven, is named in 33.5)
- `evm_eip3009`, `evm_authcap`, `evm_permit2`: `{block_number, block_hash, tx_hash, tx_index, receipt_hash|null,
  receipt_root_verified, [log_index], [state]}`. The header is read by number and accepted only if it hashes to
  `block_hash` (apc_block.header_hash) — except on the networks whose header layout our encoder does not know
  (Avalanche, eip155:43114, the only one in this version): there it is accepted on the hash it STATES, the report says
  `anchors.header: declared`, and its receiptsRoot anchors nothing; the transaction only if its RLP
  (tools/inclusion.encode_tx) hashes to `tx_hash`, its `from` is the address its signature recovers (type 0x2; another
  type is refused) and it sits at `tx_index` of that block; the receipt only as the member at `tx_index` of eth_getBlockReceipts whose
  receiptsRoot recomputes to the header's — or, when the endpoint has no such method or the set does not recompute
  (Avalanche, measured 2026-10-26), only if its keccak (the receipts-trie value) equals the list's `receipt_hash`; with
  neither, refused (`receipt_unanchored`). Logs are taken from eth_getLogs by block hash and accepted only if the verified
  receipt holds, at the same index, the same address, topics and data, and if the log names the pinned block (hash and
  number) and is not `removed`. Inclusion proofs come from the full block and
  its receipts through tools/inclusion.build (both roots and the header hash recompute, else refused). `receipt_hash`
  is written by the authors from a receipt they held; `receipt_root_verified` says whether they anchored it to the
  header's receiptsRoot (true) or only held its bytes (false).
- `svm_exact`: `{signature, slot, chain_tx_sha256}`. getTransaction (base64) is accepted only if the first
  signature is the pinned id, the ed25519 signature of account 0 (the fee payer, derived) verifies over the message
  (apc_solana), the slot is the pinned one, and the rebuilt `chain_tx` (slot, blockTime, reduced meta) has the recorded
  sha256 — the last is a declared anchor (33.5), not consensus.
- `xrpl_exact`: `{ledger_index, ledger_hash, tx_hash}`. One `ledger` call (binary, expanded) per ledger: accepted only if
  `ledger_data` hashes to `ledger_hash` (SHA-512Half of "LWR\0" + header) and the SHAMap root of every (tx_blob, meta)
  leaf equals the header's transaction_hash: the metadata of every transaction is covered. The pinned transaction must
  be among the leaves.
- `xlm_exact`: `{ledger, tx_hash}`, locator only (local_only set).
State members: `payer_state` (SPEC 32.4) is rebuilt from eth_getProof at the parent and at the block for the payer
derived from the log, the parent header accepted only if it hashes to the pinned header's parentHash, the owner read
from the proof's storage word and accepted only if its keccak256 is the list's `owner_keccak`; apc_verify then proves
everything against the headers (the rebuild compares its verdict). `payer_code` (12.5) likewise. `payer_wallet` replies (3) and the Permit2 `rpc` form
are declared data: the code by its keccak256, the implementation by its address, the ownerAtIndex and storage replies
by the sha256 the list recorded (`ours.state_sha256`).

### 33.5 Declared anchors, named
Five things in the corpus are not provable from a header a reader holds: the Solana execution record, the
`payer_wallet` ownerAtIndex reply, the Permit2 `rpc`-form storage reply, the Avalanche header (accepted on the hash it
states), and a receipt anchored to the list's `receipt_hash` instead of a receiptsRoot (the rebuild measured 54 such
bundles on 2026-11-01: Celo 27, Avalanche 18, Arbitrum 4, Optimism 4, Ethereum 1; and for 96 entries the authors held
the receipt's bytes without anchoring them, `receipt_root_verified: false`). For them the list records a digest of what
we saw: the rebuild refuses anything else, so a reader gets our bytes or nothing — it does not get consensus. Members
of a raw RPC object that no fingerprint covers (the order of members, a transaction's or log's `blockTimestamp`, a
1559 transaction's `gasPrice`) are the endpoint's: in a `verdict` set they may differ from ours while the verdict and
the checks stay the same. A bundle below its set's level is not written; a file already under `--out` is compared with
the list and counts as below its level when it differs. The report says the anchors per EVM bundle (`anchors.header`,
`anchors.receipt`).

### 33.6 Endpoints, pace, logs
No endpoint is written in the tool. Each network's URL comes from `--rpc CAIP2=URL` or `APC_RPC_<CAIP2>` in the
environment; whoever runs the tool is responsible for the terms of service of the endpoint chosen (a node of one's own is
the recommended one). Default pace 1 request per second per host (`--rate`, refused above 5), exponential backoff on
429/5xx/403, User-Agent `apc-rebuild-corpus/<version>`; URLs are never logged nor written: `provenance` and refusals
carry the host alone, and a URL that is not http(s) with a host is refused before any request without being printed.
`--rate` must be above 0 and at most 5. Archive reads (eth_getProof, eth_getCode, eth_getStorageAt, eth_call at an old block; a block of
January 2026 at some public endpoints) need an endpoint that serves them: measured 2026-11-01, Base eth_getProof at
block 52,338,084 is served by base.drpc.org, refused by base-rpc.publicnode.com ("Archive requests require a personal
token") and by mainnet.base.org ("distance to target block exceeds maximum proof window"). Ethereum, the L1 side of the
anchored bundles (33.10): measured 2026-11-02, eth_getProof at block 26,321,847 is served without a key by
eth-mainnet.public.blastapi.io and rpc.mevblocker.io, refused by ethereum-rpc.publicnode.com ("Archive requests require a
personal token") and by eth.drpc.org ("Unknown state"); 2 of the 25 public endpoints probed served it. The rebuild through
rpc.mevblocker.io is refused at the grammar of its storage keys (33.10); through blastapi it rebuilds to the byte.

### 33.7 Measured 2026-11-01 (the author's notes (not distributed) CORPUS_REBUILD_20261101.md holds the full table)
The whole corpus, not a sample, rebuilt from public endpoints and compared with our files: 1042 of 1094 bundles are
rebuildable (52 local_only); 1042/1042 rebuilt, none refused, none below its set's level — 425 byte-identical, 608
identical but for `provenance`, 9 verdict-equivalent (real_world: client-side members). Measured in the author's tree:
the public tree of the same day (37a506f, and b34fb47 after it) could not rebuild any bundle of the recipe svm_exact
(114 of the 1042: real_svm 46, real_svm_mandate 2, real_negatives_20261026 66; a run over the whole list stops at the
first of them, real_negatives_20261026/svm_*, in the order of the run), nor, once listed, the 28 anchored bundles of
33.10: its tools/make_bundles_svm.py and tools/make_bundles_l1state.py (this tree only) ended the program at import when the saved replies kept with the corpus were absent, before any report (exit
1); since the commit that carries this sentence the check runs in their main (tests: RebuildImportsItsRecipes, in the
public tree too). The public tree's measure of its own is below, 33.12. Anchors: header recomputed for
all but 18 (Avalanche, declared); receipt in the receiptsRoot for all EVM bundles but 54 (Celo 27, Avalanche 18,
Arbitrum 4, Optimism 4, Ethereum 1: anchored to the list's receipt_hash). Those notes name, per set, the endpoints and the reasons. Positive
controls (tests/test_corpus_manifest.py, offline): a list with a member outside the grammar, an altered block hash, an
altered transaction input, an altered receipt log, an altered XRPL metadata blob, an altered Solana message byte — each
refused with its reason; the same data unaltered rebuilds the bundle to the byte. Format 0.2 (no address of a person in
clear): the sets that derive the payer and the owner rebuilt again from the cached replies 63/63 byte-identical, a
sample of two per other set 16 bytes + 6 content; `--oracle blocks_v03,xrpl_20261026` 17/17 and 12/12 `content`.

### 33.8 The raw replies tests read (oracle/): rebuilt where the same anchors hold, declared where not (format 0.2)
The list carries an `oracle` member, closed: `{<dir>: {"kind": "evm_blocks"|"xrpl_ledgers"|"local_only", "network",
"items": [...], "files"|"file", "result_sha256": {...}, "reason", "read_by": [test modules]}}`. Two kinds are
rebuilt by `tools/rebuild_corpus.py --oracle <dir>` with the anchors of 33.4: `evm_blocks` (oracle/blocks_v03: per
block `<n>_block.json.gz` = eth_getBlockByNumber(n, true) and `<n>_receipts.json.gz` = eth_getBlockReceipts(n), each a
JSON-RPC envelope gzip-compressed; accepted only if the header hashes to the pinned hash and the transactions and
receipts roots recompute) and `xrpl_ledgers` (oracle/xrpl_20261026/mainnet_ledgers.json: per ledger the binary
`ledger` call and the JSON `ledger` call; accepted only if `ledger_data` hashes to the pinned ledger hash, the SHAMap
root of every transaction is the header's, and the JSON reply states that same ledger_hash, transaction_hash,
account_hash and parent_hash). A rebuilt raw file is written only at level `content`: its canonical `result` is ours
(`result_sha256`; for a ledger, the binary and the JSON reply whole). When the anchors hold but members no fingerprint
covers differ (a receipt's `from`, a log's `removed`, a JSON ledger's `close_time`, a reply's `validated`) the level is
`anchored`: reported, not written, exit 1; a file already there counts only if it is ours. The `fetched` time and
`server` host are the new fetch's. The member is closed: a rebuildable directory is one plain name, `file` one name
under it, `files` exactly `["<n>_block.json.gz", "<n>_receipts.json.gz"]`, one digest per file or ledger, no item twice. The other directories tests read are `local_only` with the reason written in the list (the
authors' censuses and scans over thousands of blocks, state replies behind bundles already rebuilt, probe texts): their
tests skip with that reason, never with a rebuild command that cannot produce them. For the sets, `need("*")` means
every set that is not `local_only`; a test that reads a `local_only` set names it.

### 33.9 The list rewritten on 0.21.3 (2026-11-02, local)

corpus/MANIFEST.json of 2026-11-01 was written on apc_verify 0.21.0 and gave `chain_verified` to the 56 bundles of
real_msca_20261101 (rpc and proof forms), which since 0.21.1 (32.10) are `chain_incomplete`: regress/VERDICTS.json,
refrozen then, said so; the list did not. Rewritten with tools/make_corpus_manifest.py on this tree (`--cache` at the
raw-reply caches of the 2026-11-01 runs, kept beside the author's bench; no network), measured against the old file:
1094 bundles, the same files in the same order; `verifier` apc_verify 0.21.3, `written`; 56 `verdict` and 56
`checks_sha256` changed, all of real_msca_20261101; no other member of any entry changes (0 `receipt_hash` null, as
before); the `oracle` section identical; of the `sets`, only the `real` text of real_msca_20261101 (the text of
tools/regress.py, which since 32.10 also names the anchored twins). Two defects of the tool found on the way, fixed:
it took bundles/real_msca_20261101/ANCHORED.json (the record anchor_msca writes, 32.10) for a bundle, a KeyError on the
frozen verdicts (regress.corpus() already left it out: the two walks now agree); and for an `_anchored_` bundle it
opened the bundle's own file as its rpc twin, a KeyError on `rpc`. The 28 anchored bundles are left out of the list
and the tool says so on standard error ("real_msca_20261101: 28 anchored bundles left out of the list (SPEC 33.9)"):
why, in Open below. tests.test_corpus_manifest, 67 tests, OK (49 s); `tools/rebuild_corpus.py --check-manifest`:
apc-corpus-0.2, 20 sets, 1094 bundles, exit 0.

### 33.10 The anchored bundles rebuilt: format `apc-corpus-0.3`, the `anchor` member (2026-11-02, local; the author's decision)

The 28 anchored bundles of bundles/real_msca_20261101 (32.10: the proof form plus `canonical`, its `l1_state` at ONE L1
block, one checkpoint for all) were out of the list (33.9). This amendment puts them in, as entries of the same set and the
same recipe, with one new member of `chain`, and bumps the format: a list in format 0.2 is refused by this reader as not the
format (`manifest.format: 'apc-corpus-0.2' is not 'apc-corpus-0.3'`, exit 3), as 0.1 was — the tool and the list travel
together in the tree. Nothing else of the grammar of 33.2 changes.

The member, closed (an entry with an `anchor` of another shape is refused with its path, exit 3):
```
"chain": {<the evm_eip3009 members of 33.4>,
          "anchor": {"l1_network": "eip155:1", "l1_block_number": N, "l1_block_hash": "0x<64 lowercase hex>",
                     "game": "0x<40 lowercase hex>", "root_index": I}}
```
`anchor` is optional and allowed only in an `evm_eip3009` entry whose `network` is `eip155:8453`, whose `bundle_version` is
`apc-0.3` and whose `ours.inclusion` is true (`canonical` needs `inclusion`, SPEC 0.3; the canonical rules of section 6 are
written for Base mainnet under Ethereum); `l1_network` must be `eip155:1`, `l1_block_number` and `root_index` non-negative
integers (a bool is not an integer). It holds chain facts and a position only: the L1 header's hash (the checkpoint the
reader passes to the verifier, 32.10), its number, the dispute game — a CONTRACT, the clone the DisputeGameFactory
deployed, not an account of a person (33.2) — and the index of the intermediate output root the block sits under. No
address of a person: the payer and the owner are derived and pinned as in 33.2. The entry's `ours` is the proof form's
(`extraction`, `inclusion`, `payer_state: "proof"`); its `state` is read from the rpc twin, as for the proof form.

The recipe is the `evm_eip3009` of 33.4 with one more step: the bundle is built as the proof form (transaction, receipt,
logs, inclusion, `payer_state` with its two proofs), then `canonical` is added and the whole is compared with the list
(the set's level stays `bytes`). What comes from where, and what is accepted:
- From L1 (`--rpc eip155:1=URL` or `APC_RPC_eip155_1`; archive reads — eth_getProof, eth_getCode, eth_call — at the pinned
  block): the header by number, accepted only if it hashes to `l1_block_hash` (apc_block.header_hash; there is no declared
  layout here: a header that does not recompute is refused); then what sources/l1proof_20261024/fetch_l1proof.py fetches
  at that block for the pinned game (`fetch`, without the author's control calls): the eight eth_call replies of O1, the
  game's code and its implementation's, and the account and storage proofs of the game, its implementation, the
  DisputeGameFactory, the AnchorStateRegistry, the SystemConfig and the SuperchainConfig with their implementations (the
  addresses of the implementations, of the SystemConfig and of the SuperchainConfig are read from the proofs' storage
  words, as that tool does; they are not in the list). `canonical.l1_replies` are the eight replies at that block;
  `canonical.l1_state` is tools/make_bundles_l1state.l1_state of that fetch — the header pruned to its members, the proofs
  the eight replies read (one not read is dropped: apc_verify refuses an unread one), the game code. A proof that does not
  recompute under the header's stateRoot, a code whose keccak is not the account's codeHash, an implementation not pinned
  (apc_l1proof) is refused here, `l1_state_not_recomputed:<reason>`.
- From the L1 replies above (startingBlockNumber and extraData of the game, at the pinned L1 block): the game's range and
  root spacing — start, l2SequenceNumber, the count of roots, k = (seq - start) / roots (tools/anchor_msca.place); the block n
  must satisfy start < n <= seq (`block_not_in_game_range`), the first root at or after n must be the pinned `root_index`
  (`root_index_not_the_first_root_at_or_after_the_block`), and its block m = start + (root_index + 1) * k at most 64 blocks
  above n (`root_block_too_far`; section 6 holds at most 64 headers). From L2 (the entry's network): the headers m, m-1,
  ..., n+1 are read by number
  (eth_getBlockByNumber(b, false)) and pruned to the header members.
- ACCEPTED only through apc_verify.check_canonical on the member just built, against the bundle's `inclusion.block_header`
  (already the pinned header, 33.4) and with `l1_block_hash` as the checkpoint: L1 verified (the L1 header hashes to the
  checkpoint, every proof holds under its stateRoot, the eight replies recomputed from the proofs equal the fetched ones
  byte for byte, no proof unread), O1 verified (game type 621, last root = rootClaim, range divisible), O2 verified (every
  L2 header hashes to its `hash`, the parent links hold from m down to the pinned block, m is the first root at or after n
  and `root_index` its index), O3 verified (the output root of header m — keccak256(bytes32(0) || stateRoot ||
  withdrawalsRoot || hash) — is the game's intermediate root at `root_index`). Anything else is refused with the check and
  its reason (`canonical_not_recomputed:O2:failed:header_hash_mismatch`, `canonical_refused:<grammar refusal>`). O4 — the
  game's state at that L1 block (final, pending, challenger wins) — is not a condition of the rebuild: it is what the L1
  state at the pinned block says, read from the same proofs, and the frozen verdict compares it (`compare`, 33.3: for
  these 28, chain_verified at finality_proven with the checkpoint, 32.10).
- What anchors what: the L1 side hangs on the pinned L1 header hash (consensus; the checkpoint a reader passes to the
  verifier); the L2 headers at both ends — the top one by the game's root proven from L1 state (O3), the bottom one by the
  pinned block hash (the bundle's own) — and in between by the parent links. Nothing of `canonical` is declared data
  (33.5 is unchanged): every byte is recomputed or hashes into something pinned. Members no fingerprint covers (the order
  of members, the hex form of a quantity) would move the level below `bytes`, and the bundle would not be written.
- One run fetches the L1 side once per (L1 block hash, game) and each L2 header once, whatever the number of bundles.
  The report row carries `anchors.canonical: recomputed` for an entry with `anchor`; the summary counts them.

Tools: tools/rebuild_corpus.py (`canonical_member`, the grammar), tools/make_corpus_manifest.py (an `_anchored_` bundle is
an entry: `anchor` from its `canonical` — `l1_state.headers` must be exactly one header, the replies' block, which is the
checkpoint; the set's `params.options.l1_checkpoint` is the option tools/regress.py freezes the verdicts with),
sources/l1proof_20261024/fetch_l1proof.py (`fetch(game, block, call, pins)` split out of `main`, same output; its
SHA256SUMS.txt line rewritten), tools/anchor_msca.py (the overrides of the three fetch functions moved from import time
into `main`, so that the module can be imported for `place`).

Tests (tests/test_corpus_manifest.py, `AnchoredControls`, offline: the saved replies of oracle/msca_20261101/raw and
/anchor through the fake endpoint): the unaltered data rebuilds m001's anchored bundle to the byte, level `bytes`, and
apc_verify with the checkpoint gives chain_verified, finality_proven, O4 and L1 verified; positive controls, each refused
with its reason: an L2 header altered by the endpoint (O2), an L1 proof node altered (`l1_state_not_recomputed`), another
game of the same set in the list (`block_not_in_game_range`), the L1 header altered by the endpoint and the checkpoint
altered in the list (`header_hash_mismatch`), an eth_call reply altered (rootClaim: the fetch then asks the factory's
proof at another slot and the replies recomputed from the real game's code do not find theirs,
`l1_state_not_recomputed:storage_proof_missing`; isGameClaimValid, which feeds no key: L1
`failed:l1_reply_not_proven:isGameClaimValid`; a status outside GameStatus: the verifier's grammar, `canonical_refused`),
`root_index` altered, the game code altered; the top L2 header m altered with its hash recomputed (held by O3 alone:
`output_root_not_the_game_root`); a startingBlockNumber stated at or above the payment's block (`block_not_in_game_range`,
before the root is placed) and one stated so low that the root's block moves beyond the 64 headers of section 6
(`root_block_too_far`, no L2 header asked); the L1 side fetched once per (block, game) and each L2 header once across
two bundles of one root; the grammar: a member outside `anchor`, an uppercase game, another `l1_network`, `anchor`
on an entry without `inclusion`, a bool as `root_index`, a list in format 0.2.

Measured 2026-11-02 (the author's notes (not distributed) ANCORATI_REBUILD_20261102.md holds the commands, the logs and the
reports): the 28 anchored bundles rebuilt from public endpoints, no key, 1 request per second per host. Four runs, the
L2 base.drpc.org throughout. Run A, L1 ethereum-rpc.publicnode.com: 28/28 refused at the first archive eth_call of the
fetch, `rpc_error:ethereum-rpc.publicnode.com:eth_call:Archive requests require a personal token`, 426 calls, exit 1.
Run B, L1 eth.drpc.org: 28/28 refused at the first eth_getProof, `Unknown state. First available state is 1`, 40 calls,
exit 1 (the L2 replies of run A read from the cache; the refusal is kept per L1 block and game: the other bundles of the
game ask no L1 again). Run B2, L1
eth-mainnet.public.blastapi.io, the L2 replies of run A read from the cache: 28/28 `bytes`, header recomputed 28,
receipt in the receiptsRoot 28, `anchors.canonical: recomputed` 28, none below its level, 128 calls, 5 min 19 s, exit 0;
apc_verify 0.21.3 `--l1-checkpoint 0x6e4d…5895` on the 28 files written: 28/28 chain_verified, finality_proven; `cmp`
with bundles/real_msca_20261101: 28/28 identical. Run C, a fresh cache, one bundle per game (4), both sides from the
network (L1 blastapi, L2 base.drpc.org): 4/4 `bytes`, 144 calls, 2 min 45 s, exit 0. Who serves the L1 archive read
(eth_getProof of the game at block 26,321,847, one request without a key at 25 public Ethereum endpoints, 09:35 UTC):
2 of 25 (eth-mainnet.public.blastapi.io, rpc.mevblocker.io); eth.meowrpc.com served it in an earlier probe the same
morning (09:33 UTC) and refused it at 09:35 ("historical state ... is not available"), so its answer varies between
requests; 18 others refused with a reason (a token or a plan: publicnode, ankr, blockpi, onfinality, nodies; the state
not held: drpc, 1rpc, zan "historical state", tenderly "distance
to target block exceeds maximum proof window", cloudflare "Cannot fulfill request"; rate limit, 5xx, discontinued: the
rest), 4 unreachable; the header by number stating the checkpoint as its hash: 10 of 25 (the probe compares the stated
hash; tools/rebuild_corpus.py recomputes it). Through rpc.mevblocker.io a rebuild of m028 (11:30 UTC) was refused at the
grammar, nothing written: it returned the game's storage keys as quantities (0x0, 0x1, 0x2), and apc_verify refuses a key
that is not a 32-byte hex slot (`canonical_refused:canonical.l1_state.accounts[4].storageProof[0].key`). An endpoint that serves the header but
not the proof refuses the rebuild at the L1 side, before the L2 headers of `canonical` are asked: nothing is written.

### 33.11 A document nested beyond the interpreter's limit is refused with where it came from, never a traceback (2026-11-02, local)
`json.loads` raises RecursionError on a document nested too deep (measured 2026-11-02, arrays at the top of the stack:
994 levels parse on CPython 3.9 and 3.11, 9,998 on 3.13; the limit depends on the interpreter and on the stack already in
use). tools/rebuild_corpus.py parses what it reads at five points and bounds each of them (the first two through
`rebuild_corpus.loads`, the others catch RecursionError where they parse): an endpoint's reply
is `refused:json_too_nested:rpc:<host>:<method>`, a reply read from `--cache` `refused:json_too_nested:cache:<method>`
(nothing written, the run goes on with the next bundle, exit 1 as any refusal); the body under an HTTP error status that
is nested beyond the limit counts as no JSON-RPC error (the HTTP status stands, `rpc_unreachable:<host>:HTTP <code>` after
the retries, as a body that is not JSON); a file already under `--out` that is nested beyond the limit is
`unreadable:RecursionError` in the row's note (not overwritten, below the level, exit 1, as any unreadable file there), and
one under `--out-oracle` is not ours (`existing_file_differs`, 33.8). A RecursionError raised while a recipe processes a
reply that passed the parse (a document just under the limit that the recipe wraps deeper) is
`refused:reply_shape:RecursionError:<message>`, as any reply outside the shape a recipe reads; the same list of errors
(`SHAPE_ERRORS`: KeyError, TypeError, ValueError, IndexError, AttributeError, ArithmeticError, RecursionError) closes the
bundle recipes and the two oracle recipes of 33.8 alike (before, an ArithmeticError in an oracle recipe was a traceback
too, and an AttributeError — a member of another JSON type where a recipe reads an object or a string — in any recipe). A
reply that is JSON but not an object (a list, a string, a number, null) is `refused:rpc_not_object:<host>:<method>`; an
error member that is not an object, or a message that is not a string, is `refused:rpc_error:<host>:<method>:<its text>`
or `...:error_not_text:<JSON type>` (before, both were an AttributeError out of the run; `{"error": "rate limited"}` after
its five retries). The list
itself is read by apc_verify.strict_json, which already refuses depth (`not JSON: nested too deep`, exit 3). Positive
controls (tests/test_corpus_manifest.py, NestedInputPublic — no saved block, it runs in the public tree too — and
NestedInput, offline): 100,000 nested arrays as the reply, as the cached reply, as
the HTTP error body and as the file under `--out`; a RecursionError and an OverflowError raised inside a recipe; the same
fixtures unaltered rebuild the bundle and the oracle files to the byte.

### 33.12 The public tree measured on its own (2026-11-02, local; the tree the publication tool builds from this commit)
Until this commit the public tree could not rebuild the anchored bundles of 33.10 nor any bundle of the recipe svm_exact
(real_svm, real_svm_mandate and the 66 Solana bundles of real_negatives_20261026):
tools/make_bundles_l1state.py and tools/make_bundles_svm.py of that tree (only there) ended the program at import when
the saved replies kept with the corpus were absent, and tools/rebuild_corpus.py imports both (exit 1, no report, every
later set never asked; the 33.7 figure was the author's tree). The check now runs in their main, and the tree is measured
by its own tools/rebuild_corpus.py, `env -u PYTHONPATH`, cache empty, 1 request per second per host (0.5 on drpc and
blastapi), one bundle per (set, network) of the list plus the first anchored one, 28 bundles over the 17 sets that are not
local_only and 10 networks: 26 of 28 at the first endpoint named — bytes 20, content 5, verdict 1 (base-rpc.publicnode.com;
base.drpc.org for the archive reads of real_msca, real_v02_passkey, real_v02_wallet, real_issue1062; avalanche-c-chain-rpc,
ethereum-rpc, optimism-rpc and polygon-bor-rpc of publicnode; rpc.monad.xyz; arb1.arbitrum.io; forno.celo.org;
api.mainnet-beta.solana.com; xrplcluster.com; eth-mainnet.public.blastapi.io for the L1 side of the anchored bundle,
`anchors.canonical: recomputed`); 2 refused by publicnode's archive policy, each with its reason and nothing written
(Optimism eth_getTransactionReceipt and Polygon eth_getLogs, "Archive requests require a personal token"), and rebuilt
through mainnet.optimism.io (content) and polygon.drpc.org (bytes): 28 of 28 at or above the set's level, 151 requests,
the smallest gap seen on any host 1.0 s. `--oracle blocks_v03,xrpl_20261026` in the same tree: 17 blocks and 12 ledgers
`content`, 75 requests. The whole list in the same tree from the replies cached by the runs of 2026-11-01 and 2026-11-02
(1737 replies; a reply not cached is asked live): 1070 of 1070 rebuildable entries rebuilt (1042 + the 28 anchored), 52
local_only reported, none below its set's level — bytes 453 (the 452 of the run plus eth_usdc/real_003 asked again,
below), content 607, verdict 10; `anchors.canonical: recomputed` 28, header recomputed 389 and declared 18 (Avalanche),
receipt in the receiptsRoot 354 and by the list's hash 53 (Celo 27, Avalanche 18, Arbitrum 4, Optimism 4;
no Ethereum entry, one in 33.7), counting the entry asked again below; 13 min 29 s. One entry of that run was refused at first,
`rpc_unreachable:eth-mainnet.public.blastapi.io:HTTP 401` (its eth_getBlockReceipts was not cached and blastapi answered
401 to that one request), and rebuilt to the byte through ethereum-rpc.publicnode.com with 1 request: the refusal names
the endpoint and the status, as 33.6 says. Every file written at level bytes is byte-identical to ours (`cmp`); of the
607 at content, 587 differ from ours in `provenance` alone and 20 are equal to ours as JSON with members in another order
(real_world: Celo 11, Ethereum 5, Optimism 4), by construction of the level (33.3). The notes of the review hold the
reports (the author's notes (not distributed) ANCORATI_FIX_20261102.md).

### 33.13 A payment brought by a third party: agent-payment-chain issue #1 (2026-11-02, local)
On 2026-11-02 giskard09 opened issue #1 of this repository with a real x402 v2 payment (Base mainnet, transaction
0xc8599161b6a9a7ffaa66fde11f0ac2971a813148b071ca66da4b9a69d41c8425, 0.001 USDC) and its payment payload, so that a
bundle is built and the outcome published whatever it is. It is in the list as the set `real_giskard_issue1`, one entry,
recipe `evm_eip3009` with the `anchor` member of 33.10, level `bytes`. Nothing of the grammar changes.

- What was checked before the entry was written: the transaction (block 53154089, status 1, a direct
  transferWithAuthorization on USDC) decoded to the same `from`, `to`, `value`, `validAfter`, `validBefore`, `nonce` and
  signature as the payload of the issue, 7 of 7; the bundle the recipe builds gives `chain_verified` and
  `finality_proven` under `--l1-checkpoint 0x7717e1e2a07cd03552c896eaa5a325cc8379d9b607f10a9a3ce75976a4662c5c` (Ethereum
  block 26329354, the same hash from ethereum-rpc.publicnode.com, eth.drpc.org and eth-mainnet.public.blastapi.io;
  dispute game 0x7b534dcc72a310837667ab1d66453baddb61ae0a, root index 10), `inclusion_proof` without it. Positive
  control, one change at a time on the bundle of the list: `value`, `to`, the signature, `accepted.amount` give
  `chain_failed`, the transaction input cut by its last byte `chain_incomplete` (cut by its whole 33-byte suffix,
  `chain_failed` on C2), a changed `parentHash` fails B1 and O2, a changed transaction-proof node B2, a changed
  checkpoint and a changed L1 storage-proof node fail L1: 9 of 9 refused.
- What is ours: `accepted` (the issue says the 402 response was not logged) and the settlement reply, reconstructed as
  for the sets built from chain data alone (real_issue1062 keeps members of the reply quoted in its issue; no
  facilitator reply was supplied, so `facilitator_reply` checks our reconstruction and is no evidence). The payer is an
  account without code here: no `payer_state`.
- Serialization with sorted keys, as the anchored bundles of real_msca_20261101: the members of the L1 header come in
  the endpoint's order (ethereum-rpc.publicnode.com and eth-mainnet.public.blastapi.io differ, measured), so a file in
  the endpoint's order rebuilt only to `content`. Sorted, the entry rebuilt from base.drpc.org and
  eth-mainnet.public.blastapi.io (28 requests, cache empty) is byte-identical to ours.
- Fixed on the way: tools/make_corpus_manifest.py still called `rc._svm_module`, renamed `_tool_module` in 5d402b3, an
  AttributeError the first time the list was written again (the published tree has the same line). A test now reads
  every `rc.<name>` of that tool against the names rebuild_corpus defines (red on the old line, green on the fix), and
  its `rc._tool_module` calls are a closed list, `make_bundles_svm` alone (the review found two names that passed the
  first check: no test runs `entry_svm`).
- Measured: tools/regress.py check 1123 bundles, no unjustified difference, then write; tests.test_corpus_manifest 103
  tests OK; `tools/rebuild_corpus.py --check-manifest`: apc-corpus-0.3, 21 sets, 1123 bundles.

### 33.14 The counts of the differential against the AP2 SDK restated: compared, not agreed (2026-11-03, local)
tools/diff_mandate_sdk.py sorts every generated pair into one of six classes — `agree`, `disagree`,
`declared_divergence_preset_payee`, `declared_divergence_preset_pisp_risk_data` (the pairs both sides decided) and
`apc_not_evaluated`, `sdk_error` (the pairs one side did not decide) — and until this commit printed no total of the
first four. 31.8 wrote "0 disagreements on 13 712 pairs" and, with `presets`, "0 disagreements on 13 549 pairs": 13 712
and 13 549 are the `agree` counts; the pairs compared were 13 736 and 14 256 (the agreements plus the declared
divergences, with 0 disagreements), and "0 disagreements on 73 137" read the same way (73 249 compared). The same
reading was in the author's comment of x402#2452 ("13 712 compared"), found by the independent review of 2026-11-02 that ran
the tool as its docstring says on 314ac9a. Done: the tool prints `compared` = agree + disagree + the two declared
classes, and its docstring says that the six classes sum to `n` and that `agree` alone is not the number compared;
every count of the differential in 31.8 re-measured 2026-11-03 on this tree, `env -u PYTHONPATH`, Python 3.11.2 with
the SDK at e1ea56d and the pack of v1.7.1 (seeds 20261031, 7, 99 × 5000, standard and `presets`; seed 31 × 10 000,
both; seeds 1-4 × 20 000), each count equal to the saved output of 2026-10-31, each sentence rewritten with the classes
apart. One count of 31.8 was wrong from the start: the boundary mutant `>=` for `>` on `not_after` gives 16
disagreements on 3000 pairs, not 3 — measured 2026-11-03 on this tree, on 3095ea5 and on 3df1e7d (the commit that wrote
"12, 3 and 3"), the mutation applied to the one line that compares `not_after`; the other two give 12 and 3, the
unmutated copy 0. A review note of 2026-11-02 reported the three as re-measured and equal; that was not reproduced.
The sentence now says 12, 3 and 16; tests/test_diff_mandate_sdk.py
(2 tests, run here against a stand-in SDK the test writes, with the pack: every class non-zero, `compared` the sum of
the four, the six summing to `n`; both fail with `compared` written as `agree`, and with the tool of 3095ea5 with a
KeyError). The messages of earlier commits on the working branch that carry the old wording are history and stay; the
published main up to c3fd67f carries no count of the differential in its commit messages, README.md none. Fixed on
the way: tests/test_amend0212 (ToolsWithoutTheLibrary) failed when the caller's environment had `AP2_SDK_PATH` set
(gen_mandate_fixtures then stopped at the next variable, `APC_AP2EV`, not at the one the test names), on this tree and on
6192960 alike; its control run now drops `AP2_SDK_PATH`. Measured 2026-11-03: tools/regress.py check 1123 bundles, 0
differences; tools/run_ordered.py, which stops at the first failure, ran 988 tests up to that one, which passes after
the fix with and without the variable; on this commit with the fix, tools/run_ordered.py 1004 tests OK (skipped=27,
`env -u PYTHONPATH -u AP2_SDK_PATH`); tests/test_diff_mandate_sdk.py OK.

## Open after 0.3
- (33.10) bundles/real_v04_l1state (8 bundles, `canonical` with `l1_state` at L1 block 26259631, one header) has the
  shape the `anchor` member describes; it stays `local_only` in this version of the list because its rebuild from a
  public endpoint was not measured (an archive read at that older block).
- The auth-capture scheme says collectorData is "the ABI-encoded Permit2 signature" (step 3 of settlement); the pinned
  collector passes collectorData to Permit2 as the signature itself (section 25.1 AC8): which bytes a Charge
  signature's collectorDataHash covers on the Permit2 path is read from the contract until the scheme says it.
- ERC-1271 checks for delegates and wallets outside the closed lists of 12.5 and 32.5 (32.9), and the ERC-7710 permissionContext of a
  named Delegation Manager implementation.
- Whether a receipt issued before the settlement block is an inconsistency (no source says so today).
- (0.17) A Coinbase Smart Wallet owner address with code (SignatureCheckerLib asks its ERC-1271), the decoder's
  non-canonical WebAuthnAuth forms, and FreshCryptoLib run rather than read; the ZIP-215 rule when SIMD-0376 lands.

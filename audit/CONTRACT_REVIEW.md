# Sigma Fleet contract review

Date: 5 September 2026. Scope: `contracts/sigmafleet.es` (game, 3383-byte ErgoTree, deployed) and `contracts/lobby.es` (escrow, 473 bytes, deployed), plus the off-chain builders in `src/lib/blockchain/fleet.ts` and the commitment scheme in `src/lib/crypto/merkle.ts` where they make an on-chain weakness reachable.

## How this was run

Five independent passes, reconciled by a coordinating reviewer:

1. EKB two-pass audit, Pass 1, on each contract separately (Opus).
2. EKB Pass 2 verification on each Pass 1 report (Opus), instructed to remove false positives and hunt for misses.
3. A blind red-team pass on both contracts (Opus), run before seeing any EKB output.
4. A second red-team round that attacked the EKB findings, the disputed severities, and every proposed fix.
5. The coordinator's own reading of both contracts and an independent proof of concept.

Every exploit claim in this document is backed by a transaction that reduces **and signs** against the compiled mainnet contracts through ergo-lib-wasm. Reduction alone does not fail on a false script, so each test file carries control cases that show the same harness rejecting a rule-abiding variant. All 117 tests pass (`npx vitest run`).

Bottom line: the cryptographic core holds. Nobody could forge a Merkle answer, replay a proof, promote an internal node to a leaf, under-report a score, sneak a phantom ship past the geometry audit, steal a pot as a third party, or deadlock an honest player. The weaknesses are all in transaction shape and game-flow rules, and the three that matter share a one-line fix each.

Final ratings from the EKB verification pass: game contract 6.5 / 10, lobby contract 6 / 10.

## Findings

| # | Severity | Contract | Title | Proof |
|---|---|---|---|---|
| 1 | HIGH | lobby, game | No single-input guard: identical boxes merge into one output and the surplus leaves as change | `tests/lobby_merge_exploit.test.ts`, `tests/adv_game_pot_merge.test.ts`, `tests/game_merge_and_fee_batch_exploit.test.ts` |
| 2 | HIGH at the shipped 30-block timeout, MEDIUM at 720 | game | Timeout sweep pays by phase, never by score; the 0-10 loser holds a never-expiring option on the pot | `tests/adv_timeout_theft.test.ts` (A1-A3, C1-C2) |
| 3 | HIGH at 30 blocks, MEDIUM at 720 | lobby | Unsigned accept, no lobby expiry, 20-block floor: a stranger can accept a stale lobby and sweep it | `tests/adv_timeout_theft.test.ts` (B1-B4), `tests/lobby_pass2_probes.test.ts` |
| 4 | MEDIUM | game | Play root is not bound to the settlement board hash; a one-cell lie collects the whole pot | `tests/root_board_desync_exploit.test.ts` |
| 5 | MEDIUM | lobby | `R8` is host-written data, so "Rule 8" verifies nothing; escrow can be routed to any script | `tests/adv_lobby_escrow_destination.test.ts`, `tests/lobby_pass2_probes.test.ts` |
| 6 | LOW | game | Mover chooses the opponent's deadline inside a 15-block window; amplifier for #2 | `tests/adv_timeout_theft.test.ts` (C1-C2) |
| 7 | LOW | game | Dev fee is per transaction, not per box: batched settlements pay one fee | `tests/adv_game_pot_merge.test.ts` (G1-G2) |
| 8 | LOW | game | No emergency refund; a box where both players fail `honestScore` is unspendable forever | argued |
| 9 | LOW | game | Game re-validates none of the lobby's shape guarantees; an empty history would grant claim rights on move zero | `tests/audit_verification_probes.test.ts` (R2-2) |
| 10 | LOW | lobby | Output `creationHeight` unconstrained; a storage-rent-expired game box would go to a miner | `tests/lobby_pass2_probes.test.ts` |
| 11 | LOW | lobby | Point at infinity accepted as a player key; `proveDlog(identity)` is spendable by anyone | `tests/audit_verification_probes.test.ts` (R2-3) |
| 12 | LOW | off-chain | `generateMasterSeed` falls back to `Math.random()` outside a browser; settlement publishes the master salt | argued |
| 13 | INFO | both | README says 24-hour timeouts; `DEV_CONFIG.TIMEOUT_BLOCKS` is 30 (about one hour) | — |
| 14 | INFO | game | `R6(3)` "last sunk code" is written by the attacker and never validated | — |
| 15 | INFO | game | Settlement outputs consume the pot exactly; the miner fee needs a separate UTXO | `tests/audit_verification_probes.test.ts` (R2-1) |
| 16 | INFO | tests | 13 of 16 tests in `tests/contracts_fleet.test.ts` only check that reduction returns a string, which a rejected script also does | — |
| 17 | INFO | repo | `tests/contract_reference.test.ts` fails: `src/contracts/` does not exist | — |

Severity is the coordinator's call after reconciling the passes. Where the passes disagreed, the reasoning is given under the finding.

### 1. No single-input guard (HIGH)

Neither contract ever references `INPUTS`. Every rule is a predicate from `SELF` to `OUTPUTS(0)`, so N boxes under the same script that agree on the fields the rules compare all accept the same single output, and ERG conservation lets the difference leave as change.

Lobby (`contracts/lobby.es:43`, `:82`): two lobbies from the same host with the same commitment, stake, and timeout can be spent in one transaction into one game box worth `2V`. The challenger stakes nothing beyond the miner fee. With three such lobbies, one full stake returns to the attacker as change. The accept branch has no signature, so anyone scanning the lobby address can do this. Proven in `tests/lobby_merge_exploit.test.ts`.

Game (`contracts/sigmafleet.es:69`, `:209`): two game boxes with identical R4, R5, R6, R7, R8, and value collapse into one under Action 0, and the mover receives a whole pot as change. Proven for two and three boxes, and for a mid-match state with real proofs and different in-flight salvos, in `tests/adv_game_pot_merge.test.ts` and `tests/game_merge_and_fee_batch_exploit.test.ts`.

Reachability is the only thing between this and CRITICAL. The precondition is host-side duplication of a commitment. The client makes that plausible: `merkle.ts` persists `masterSeedHex` under `ergo_battleships_last_placed`, `generateBoardCommitment(grid, seed)` is deterministic, and `buildCreateLobbyTx` accepts whatever root and hash it is given, so any "list another game with the same board" flow reproduces R5 byte for byte. Cloning someone else's lobby does not work as a precondition, because the clone's refund branch is `proveDlog(victim)`.

Fix, in all three game actions and in the lobby accept branch (not the lobby cancel branch, which is the host's own money and should stay batchable):

```ergoscript
val singleInput = INPUTS.filter({ (b: Box) => b.propositionBytes == SELF.propositionBytes }).size == 1
```

The red team verified this against every shipped builder: each spends exactly one contract box, so nothing regresses. `SELF.id == INPUTS(0).id` is cheaper but pins the box to input index 0, which the Fleet SDK coin selector does not guarantee. The structurally stronger fix is a per-match nonce (a singleton minted in the lobby, or the spent lobby's box id written into the freed R8 once finding 5 is fixed), which makes two register-identical boxes impossible rather than merely un-mergeable. This also closes finding 7. Off-chain, refuse to create a lobby whose R5 matches a commitment already on chain for that key.

### 2. Timeout sweep by phase, not score (HIGH at 30 blocks)

`contracts/sigmafleet.es:348-350`: Action 2 pays `winPayout` to whichever player is not active and checks no claim rights. The normal end state of every match P2 wins is "P2 has 10 hits and it is P2's move", because P1's answering turn is what records the tenth hit. In that state Action 2 pays P1, the loser.

`honestScore` at `:368` does not help: it tests the timed-out player's recorded hits against the claimant's revealed board, so an honest 10-hit winner is exactly what makes the loser's sweep pass. Proven in `tests/adv_timeout_theft.test.ts` A1 (loser sweeps 1.98 of a 2 ERG pot one block after the clock lapses), A2 (rejected at `HEIGHT == timeoutHeight`).

Two things make this more than a plain forfeit rule. The loser's forced concede turn (`:94`, the `p2AlreadyWon` empty salvo) is what writes the winner's deadline, and finding 6 lets the loser set it to the 20-block floor (about 40 minutes at the shipped 30-block constant). And neither Action 1 nor Action 2 ever expires, so the option is permanent and repeatable.

The EKB verifier's structural claims are confirmed and worth keeping: a player with claim rights always holds the running clock at the moment they gain them, there is no state in which they are denied a window, and Action 1's lack of a HEIGHT guard is the winner's only post-expiry recourse rather than an aggravating factor. Pass 1's "loser can fee-race the winner" framing was inverted and is withdrawn.

Fix. Deny the sweep while the timed-out player is the recorded winner, with a grace window so a winner who genuinely vanishes still forfeits one window later:

```ergoscript
val loserAlreadyWon = opponentRecordedHits >= 10
val graceOver       = HEIGHT > timeoutHeight + timeoutBlocks
val timeoutValid    = (HEIGHT > timeoutHeight) && (!loserAlreadyWon || graceOver)
```

The red team proved the coverage case needs no extra limb: when the active player covered the board against a lying opponent, `honestScore` already blocks the opponent's sweep. This form only delays the loser's free option, from about 20 blocks to about 40 at the shipped constant. The complete fix is to pay the timeout to the score leader when one exists (`if (p1Hits >= 10) p1Prop else if (p2Hits >= 10) p2Prop else <by phase>`, selecting `winnerBoardHash`, `opponentHistory`, and `opponentRecordedHits` the same way).

### 3. Stale-lobby accept and sweep (HIGH at 30 blocks)

`contracts/lobby.es:75-79`: the accept branch is `sigmaProp(isAccept)` with no signature, lobbies never expire, and the challenger writes the host's first-move deadline with a floor of `HEIGHT + timeoutBlocks - 10`. At the shipped constant that is 20 blocks. The post-accept histories are all zero, so `honestScore` holds trivially and the sniper needs no gameplay, only their own committed board. Proven in `tests/adv_timeout_theft.test.ts` B1-B4: accept at the floor, sweep 1.98 ERG 21 blocks later, both controls rejected.

The host is never notified that a match started. For turns two onward a player knows a move is due because someone just moved; for turn one the trigger is a stranger's transaction at a moment of their choosing. At 720 blocks this is a design trade-off. At 30 it is a free option against any host who opened a lobby and stepped away for an hour.

Fix. The cleanest primary fix is a lobby time-to-live on the accept branch, which removes the stale-offer snipe at its source without holding the challenger's stake hostage:

```ergoscript
val LOBBY_TTL = 720
val notExpired = HEIGHT <= SELF.creationInfo._1 + LOBBY_TTL
```

A first-turn grace is a useful second layer, but it must be a floor rather than a replacement, or it shortens the opening window for 720-block lobbies from about 710 blocks to 360. The game contract only checks `nextTimeouts(1) == timeoutBlocks` afterwards, so a larger opening deadline disturbs nothing:

```ergoscript
val FIRST_TURN_GRACE = 360
val opening = if (timeoutBlocks > FIRST_TURN_GRACE) timeoutBlocks else FIRST_TURN_GRACE
... (outTimeouts(0) >= HEIGHT + opening) && (outTimeouts(0) <= HEIGHT + opening + 14)
```

Neither touches the per-turn exposure at 30 blocks. Raise the lobby's `timeoutBlocks` floor and reconcile finding 13.

### 4. Play root not bound to the board hash (MEDIUM)

This is the README's disclosed issue, and the disclosure understates it. The all-water root is the weakest form. The strong form is a one-cell lie: the play root declares one real ship cell as water, the settlement hash commits the real board.

- During play the hidden cell answers "miss" with a proof that validates against the committed root.
- The opponent's recorded hits are capped at 9, so `hasClaimRights` (`:285`) can never be met by score. They can only win by firing all 64 cells, which takes 13 turns.
- `honestScore` (`:316`) counts only answered shots. A hidden cell fired in the still-pending R7 salvo is subtracted by `pendingHits` (`:307`), so the lie is laundered as long as the cell was never fired in an answered salvo.

Proven in `tests/root_board_desync_exploit.test.ts`: the cheater collects 990,000,000 of a 1,000,000,000 nanoERG pot, the same claim is rejected once the hidden cell has been fired and answered, and a hidden cell inside the pending salvo still passes.

On expected value the two passes disagreed and the red team's simulation is the one to trust. A 5×5 skill matrix (10,000 matches per cell, hunt-and-target versus parity versus uniform shooters) finds no realistic pairing where the best lie beats honest play. Against a hunt-and-target opponent the one-cell lie wins about 13.5 percent of matches; against a uniform-random shooter about 45 percent, which is the number the EKB verifier's formula produces and why it over-estimated. So the README's conclusion that it is not profitable survives. Its reasoning does not: the cheat is a signable transaction in which a provably lying player takes an honest opponent's whole stake, in one match out of seven at equal skill, and the honest player has no way to detect it during play. A griefer or a mistaken client is enough to fire it.

One more consequence neither pass caught at first: when the gate closes, the cheater is locked out of both Action 1 and Action 2, since `honestScore` is identical at `:316` and `:368`. If the honest opponent walks away instead of grinding 13 turns of coverage, the box is unspendable forever.

Fix, the author's own, now recommended rather than deferred. Extend the payload to 134 bytes with the play root appended after the salt and check it at settlement, in **both** Action 1 and Action 2. Action 2 has its own hash check, and a binding that lands only in Action 1 still lets the desynced cheater collect by timeout:

```ergoscript
// shared block: (rawPayload.size == 134) in validBoardFormat
// Action 1:
val rootBound = rawPayload.slice(102, 134) == (if (isP1Claiming) p1Root else p2Root)
// Action 2:
val rootBound = rawPayload.slice(102, 134) == (if (phase == 0) p2Root else p1Root)
```

Appending after the salt keeps bytes 0-101 unchanged, so `extractShipGeometry` is unaffected. `buildBoardAuditPayload` must change: its pass-through branch allocates 102 bytes and copies indices 64 to 101, so a 134-byte committed payload is silently truncated and the digest no longer matches R5. This is a commitment-format change and needs a redeploy and a client update. Until then, correct the README's "only ever loses money" wording.

### 5. Escrow destination is host-written data (MEDIUM)

`contracts/lobby.es:41`, `:85`: the game script the lobby hands off to is whatever hash the host wrote into R8. A lobby carrying `R8 = blake2b256(hostP2PK)` is accepted, and the resulting 2 ERG output is a plain P2PK box owned by the host. Proven in `tests/adv_lobby_escrow_destination.test.ts` D1 and `tests/lobby_pass2_probes.test.ts`. The README's "a lobby can only ever hand its escrow to this exact contract" is false as written.

Not HIGH because no shipped code path funds it. `buildAcceptLobbyTx` always builds the output at the compiled game address and never reads R8, and `parseLobbyBox` in the indexer never reads R8 either, so against the shipped client a forged lobby is an accept that fails to reduce. Real money moves only if a challenger uses a client or bot that derives the output script from R8, which is the obvious generic implementation and is what the README invites by offering the contracts for reuse.

There is no cyclic dependency preventing the fix. The game contract references no lobby hash, so its digest can be a compile-time constant in the lobby, exactly as `buildCreateLobbyTx` already computes it off-chain at `fleet.ts:779`:

```ergoscript
val BATTLESHIPS_HASH = fromBase16("<blake2b256 of the compiled game ErgoTree>")
val validContract = blake2b256(outGame.propositionBytes) == BATTLESHIPS_HASH
```

Keep R8 only for a versioned upgrade path, and make the client assert R8 and the dev key before ever showing a lobby.

### 6. Mover chooses the opponent's deadline (LOW)

`contracts/sigmafleet.es:205` allows `nextTimeoutHeight` anywhere in `[HEIGHT + tb - 10, HEIGHT + tb + 4]`. The `-10` is meant as mempool tolerance but lets the mover shorten the defender's clock by a third at the 30-block floor. The honest client always writes `+4`; a custom one gains 14 blocks for free. Alone this is LOW. Combined with finding 2 it is the loser choosing the window in which the winner must act. Fix: make the window one-sided, `[HEIGHT + tb, HEIGHT + tb + 14]`, which keeps the same 15 blocks of mempool tolerance without ever narrowing the defender's clock. Apply the same change to the lobby.

### 7. Dev fee per transaction (LOW)

Both settlement branches (`:333-340`, `:370-371`) only require some output at index 1 (or 2 on a tie) to pay `>= devFeeNano` to the dev key. Two won games with the same winner settle in one transaction against a single dev output. Proven in `tests/adv_game_pot_merge.test.ts` G1-G2. A batch can never redirect another player's payout, because `OUTPUTS(0)` must match every input's winner. The fix for finding 1 closes this.

### 8 to 12. Low findings

- **8, no emergency refund.** A box is unspendable only if both players fail `validHash && honestScore` and Action 0 is exhausted. No honest player can be caught in it alone. A two-signature refund branch is safe but only helps when both parties are present, which is not the common stranding case. A unilateral branch that pays the tie split after a long absolute grace (about 1440 blocks, never `4 * timeoutBlocks`, which a locked-out loser would happily wait out) does recover from a vanished counterparty.
- **9, no shape re-validation.** The game trusts the lobby for `roots.size == 4`, 64-byte histories, and `30 <= timeoutBlocks <= 720`. `p1History.forall(...)` on an empty history is vacuously true, and the red team showed a box with an empty `R8(0)` pays the whole pot to P1 on move zero. Unreachable through the shipped lobby, but one `validParams` conjunct at the top of the script removes the dependency.
- **10, unconstrained creation height.** The lobby never constrains `OUTPUTS(0).creationHeight`. A game box born 4 years old is storage-rent-expired and goes to a miner, not to either player. EIP-39's monotonic creation height rule is listed as implemented and would block backdating below the lobby input, so this stays LOW; a `creationHeight >= HEIGHT - 10` check is cheap defence in depth.
- **11, identity point.** 33 zero bytes deserialize as a GroupElement, and `proveDlog(identity)` is satisfiable by anyone. A lobby or game keyed to it is spendable by strangers, including on the lobby refund branch. Self-harm only, but rejecting the identity point in R4 is one comparison.
- **12, seed hygiene.** `generateMasterSeed` falls back to `Math.random()` when `require` is unavailable, which is any ESM Node context such as a bot. Settlement publishes the master salt on chain, so any reuse of a board or seed hands the next opponent the full board, and reuse is also the precondition for finding 1. Make the fallback throw.

### 13 to 17. Informational

- **13.** README says 24-hour turn timeouts; `DEV_CONFIG.TIMEOUT_BLOCKS` is 30, `buildCreateLobbyTx` clamps below 30 up to 30, and every test uses 30. Findings 2, 3, and 6 are calibrated to 30. If the live client really uses 720, say so in the repo; if it uses 30, the HIGH ratings stand.
- **14.** `R6(3)` is written by the attacking player each turn and never read by the contract. Any UI rendering it as "ship sunk" is rendering a value the opponent chose.
- **15.** `winPayout + devFeeNano == totalPot` exactly, so a claimant whose only UTXO is their stake cannot pay the miner fee and forfeits by timeout. Worth a pre-flight check in the client.
- **16.** `ReducedTransaction.from_unsigned_tx` succeeds on a script that reduces to false; only `sign_reduced_transaction` throws. The 13 positive-path tests in `tests/contracts_fleet.test.ts` that assert `typeof reduced === 'string'` would pass against a contract that rejects every transaction. The new exploit files show the sign-based pattern.
- **17.** `tests/contract_reference.test.ts` imports `src/contracts/lobby` and `src/contracts/sigma_fleet`, which are not in the repository.

## What held

Attacked and rejected, with the line that stopped each (details in `tests/adv_proof_verifier.test.ts` and the pass reports):

- Proof for cell t replayed at cell t': the six path bits `(t / powers(lvl)) % 2` are the bits of t, unique for 0-63.
- Fifth proof duplicated, leaf state byte flipped, proof padded to 256 bytes, level-1 internal node presented as a leaf: `pr.size == 224`, the leaf preimage binds the state byte, and 32-byte leaf versus 64-byte node preimages give domain separation.
- Under-reported score, 4-cell salvo mid-game, target 64: `validHits` equality, `expectedSalvoSize`, and throwing `p1History(cell)` indexing.
- Settlement geometry: negative or off-grid starts throw, `start % 8` bounds prevent row wrap, `shipCount == 10 && validCells && validNoOverlap` forces exactly the declared fleet.
- Absorbing a victim's lobby into an existing game box: blocked because the lobby demands `R6 == [0,0,0]` and an empty R7 while `validSalvoSize` forbids an empty salvo at phase 1. This holds only because there is no `p1AlreadyWon` branch. Do not add one for symmetry.
- Third-party pot theft: R4 is immutable and every value-moving branch ends in a signature derived from it.
- Honest-player deadlock: at 64 shots fired the turn is blocked but coverage grants claim rights on the player's own phase; the `<= 10` hit cap is reachable only with an over-shipped root; the `p2AlreadyWon` asymmetry is correct turn parity.
- Tie theft, payout re-ordering, token smuggling, dust pots: `winPayout + devFee == pot` leaves no slack, the tie branch pins `OUTPUTS(0)` to P1 regardless of claimant, `validTokens` keeps the box pure ERG, and the dust break-even is about 0.0021 ERG of pot, not the 0.06 ERG one pass first claimed.

## Recommended patch set, in order

1. `singleInput` guard in the three game actions and the lobby accept branch. Closes 1 and 7.
2. Deny-and-grace timeout guard in Action 2, or pay the timeout to the score leader. Closes 2.
3. One-sided timeout window in both contracts in the same deployment, a lobby time-to-live, and a first-turn grace floor. Closes 3 and 6.
4. Hard-code the game tree hash in the lobby. Closes 5. Changes the lobby address.
5. Bind the play root into the 134-byte payload in both settlement actions. Closes 4. Needs a redeploy and client change.
6. `validParams` shape assertion, identity-point rejection, creation-height bound, a long-grace tie-split refund. Closes 8 to 11.
7. Off-chain: make the CSPRNG fallback throw, refuse commitment reuse, verify R8 and the dev key before showing a lobby, fix the timeout contradiction, convert the reduce-only tests to reduce-and-sign, restore or drop `src/contracts/`.

Items 1 to 4 are one line each and do not change any commitment format. With 1 to 3 applied the EKB verifier estimated the game contract at 8.5 / 10.

## Status after patching

Patch-set items 1 to 4 are applied on this branch (commit "Harden game and lobby contracts against merge, timeout, and escrow-routing attacks"):

- Both contracts require exactly one box of their own script per transaction (findings 1 and 7).
- Action 2 defers the sweep by one window when the timed-out player is the recorded winner (finding 2).
- Deadline windows are one-sided in both contracts, the lobby refuses offers older than 720 blocks, and the host's opening move gets `max(timeoutBlocks, 360)` blocks (findings 3 and 6).
- The lobby compares the game script against a compile-time constant instead of `R8` (finding 5).

New build: game ErgoTree 3432 bytes, lobby 549 bytes, game tree hash `8e92acff548e5f242726819cf206973db4935f0ccb4930032d57623c5302722e`. Both addresses change, so this is a redeploy; the mainnet addresses in `Deployment_Contracts.md` still describe the previous build. The exploit tests for the fixed findings now assert rejection and carry positive controls for the honest paths. Finding 4 (root binding) and items 6 and 7 are not applied.

## Corrections to the README "Known issues" section

- "It is not exploitable for profit" is true in expectation but "the attack only ever loses money" is not. The one-cell variant wins outright in roughly one match in seven at equal skill and cannot be detected during play.
- "The lobby ... refuses to open a match whose output script does not match it" is true only for the hash the host chose to write.
- "Turn timeouts are currently fixed at 24 hours" contradicts the shipped 30-block constant.

## Artefacts

Pass reports live outside the repository in the session scratchpad. Committed proof-of-concept tests, all passing against the compiled contracts:

```
tests/lobby_merge_exploit.test.ts
tests/lobby_pass2_probes.test.ts
tests/adv_lobby_escrow_destination.test.ts
tests/adv_game_pot_merge.test.ts
tests/game_merge_and_fee_batch_exploit.test.ts
tests/root_board_desync_exploit.test.ts
tests/adv_timeout_theft.test.ts
tests/adv_proof_verifier.test.ts
tests/audit_verification_probes.test.ts
```

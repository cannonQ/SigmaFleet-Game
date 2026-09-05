/**
 * Adversarial PoCs against lobby.es, re-pointed at the hardened contract.
 *
 * D. R8 SCRIPT SUBSTITUTION (FIXED).  The lobby's "the escrow can only ever go to the
 *    battleships contract" guarantee used to be
 *        val battleshipsScript = SELF.R8[Coll[Byte]].get
 *        val validContract = blake2b256(outGame.propositionBytes) == battleshipsScript
 *    R8 is per-box data written by whoever created the lobby, i.e. the host, not a constant
 *    baked into the script, so a host could point the escrow anywhere. The hardening commit
 *    stopped reading R8 and compares against a hard-coded BATTLESHIPS_HASH constant instead.
 *    D1 is the original PoC transaction (a 2 ERG "game box" paid to the host's own P2PK) and
 *    is now REJECTED; D2 is the same payout with an honest R8 (still rejected); D3 is the
 *    honest accept (still accepted), proving the harness is not vacuous in either direction.
 *
 *    Two further rules from the same commit are exercised implicitly here: the lobby input's
 *    creationHeight must be within LOBBY_TTL_BLOCKS of HEIGHT, and the game box's opening
 *    deadline must land in [HEIGHT + max(tb, FIRST_TURN_GRACE_BLOCKS), ... + 14].
 *
 * E. LOBBY + GAME MERGE (attack that FAILED, documented with the exact blocker).
 *    Every input under the same script sees only OUTPUTS(0), so an attacker holding a game
 *    box worth exactly 2V could try to absorb a victim's V lobby into it and take V as
 *    change (inputs 3V, OUTPUTS(0) 2V, change V). E1/E2 show both phase choices rejected;
 *    both contracts now also carry a singleInput rule that independently forbids this shape.
 */
import { describe, it, expect } from 'vitest';
import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  ErgoAddress, SColl, SInt, SByte, SGroupElement, OutputBuilder, TransactionBuilder,
} from '@fleet-sdk/core';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { serializeBox } from '@fleet-sdk/serializer';
import { generateBoardCommitment, hashBlake2b256 } from '../src/lib/crypto/merkle';
import {
  getBattleshipsErgoTree, getBattleshipsAddress, getLobbyErgoTree,
  normalizeInputBox, DEFAULT_DEV_PK,
  FIRST_TURN_GRACE_BLOCKS, TIMEOUT_SLACK_BLOCKS,
} from '../src/lib/blockchain/fleet';

const DEV_PK = DEFAULT_DEV_PK;
const WAGER = 1000000000n;
const POT = WAGER * 2n;
const TB = 30;
const FEE = 1100000n;
const H = 1250000;
// tb = 30 is below the 360-block first-turn grace, so the lobby demands an opening deadline in
// [HEIGHT + 360, HEIGHT + 374]. Every tx in this file is reduced at state height H.
const OPENING = Math.max(TB, FIRST_TURN_GRACE_BLOCKS);
const OPENING_DEADLINE = H + OPENING + TIMEOUT_SLACK_BLOCKS;

function stateCtx(height: number) {
  const hs: any[] = [];
  for (let i = 0; i < 10; i++) {
    hs.push({
      extensionId: '00'.repeat(32), difficulty: '1', votes: '000000', timestamp: Date.now() - i * 120000,
      size: 1000, stateRoot: '00'.repeat(33), height: height - i, nBits: 100000, version: 2,
      id: (i + 1).toString(16).padStart(64, '0'), adProofsRoot: '00'.repeat(32),
      transactionsRoot: '00'.repeat(32), extensionHash: '00'.repeat(32),
      parentId: (i + 2).toString(16).padStart(64, '0'),
      powSolutions: {
        pk: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        w: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        n: '0000000000000000', d: 0,
      },
    });
  }
  const bh = wasm.BlockHeaders.from_json(hs);
  return new wasm.ErgoStateContext(wasm.PreHeader.from_block_header(bh.get(0)), bh, wasm.Parameters.default_parameters());
}
const s = (o: any) => JSON.stringify(o, (_: any, v: any) => (typeof v === 'bigint' ? v.toString() : v));
function reduceAndSign(tx: any, boxes: any[], sk: any, height: number) {
  const utx = wasm.UnsignedTransaction.from_json(s(tx.toPlainObject ? tx.toPlainObject() : tx));
  const bs = wasm.ErgoBoxes.empty();
  for (const b of boxes) bs.add(wasm.ErgoBox.from_json(s(b)));
  const reduced = wasm.ReducedTransaction.from_unsigned_tx(utx, bs, wasm.ErgoBoxes.empty(), stateCtx(height));
  const secrets = new wasm.SecretKeys();
  secrets.add(sk);
  return wasm.Wallet.from_secrets(secrets).sign_reduced_transaction(reduced);
}
function withId(b: any) { b.boxId = bytesToHex(hashBlake2b256(serializeBox(b).toBytes())); return b; }
function utxo(addr: string, v: bigint, h: number, tag = 'ab') {
  return withId({
    value: v.toString(), ergoTree: ErgoAddress.fromBase58(addr).ergoTree, assets: [],
    creationHeight: h, additionalRegisters: {}, transactionId: tag.repeat(32), index: 0,
  });
}

const hostSecret = wasm.SecretKey.dlog_from_bytes(hexToBytes('11'.repeat(32)));
const hostAddr = ErgoAddress.fromBase58(hostSecret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const hostPk = bytesToHex(hostAddr.getPublicKeys()[0]);
const chalSecret = wasm.SecretKey.dlog_from_bytes(hexToBytes('22'.repeat(32)));
const chalAddr = ErgoAddress.fromBase58(chalSecret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const chalPk = bytesToHex(chalAddr.getPublicKeys()[0]);

const g1 = new Array(64).fill(0); [0, 1, 2, 3, 4, 16, 17, 18, 32, 33].forEach((c) => (g1[c] = 1));
const g2 = new Array(64).fill(0); [8, 9, 10, 11, 12, 24, 25, 26, 40, 41].forEach((c) => (g2[c] = 1));
const com1 = generateBoardCommitment(g1, '11'.repeat(32));
const com2 = generateBoardCommitment(g2, '22'.repeat(32));

const HONEST_R8 = hashBlake2b256(hexToBytes(getBattleshipsErgoTree().toHex()));
const EVIL_R8 = hashBlake2b256(hexToBytes(hostAddr.ergoTree)); // hash of the host's own P2PK tree

function lobbyBox(r8: Uint8Array, value = WAGER) {
  return withId({
    // creationHeight must be within LOBBY_TTL_BLOCKS (720) of HEIGHT or the accept branch refuses outright.
    value: value.toString(), ergoTree: getLobbyErgoTree().toHex(), assets: [], creationHeight: H - 100,
    additionalRegisters: {
      R4: SColl(SGroupElement, [hexToBytes(hostPk), hexToBytes(DEV_PK)]).toHex(),
      R5: SColl(SColl(SByte), [
        Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com1.boardHashHex)),
      ]).toHex(),
      R6: SColl(SInt, []).toHex(),
      R7: SColl(SByte, []).toHex(),
      R8: SColl(SByte, Array.from(r8)).toHex(),
      R9: SInt(TB).toHex(),
    },
    transactionId: '44'.repeat(32), index: 0,
  });
}

// The register set the lobby's accept branch demands of OUTPUTS(0). The script-hash comparison
// value is now a constant in the contract rather than R8, so the destination is no longer
// host-controlled; the rest of the register shape is unchanged.
const acceptRegisters = {
  R4: SColl(SGroupElement, [hexToBytes(hostPk), hexToBytes(chalPk), hexToBytes(DEV_PK)]).toHex(),
  R5: SColl(SColl(SByte), [
    Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com2.rootHex)),
    Array.from(hexToBytes(com1.boardHashHex)), Array.from(hexToBytes(com2.boardHashHex)),
  ]).toHex(),
  R6: SColl(SInt, [0, 0, 0]).toHex(),
  R7: SColl(SInt, []).toHex(),
  R8: SColl(SColl(SByte), [Array(64).fill(0), Array(64).fill(0)]).toHex(),
  R9: SColl(SInt, [OPENING_DEADLINE, TB]).toHex(),
};

function acceptTx(lobby: any, destination: string) {
  const fund = utxo(chalAddr.encode(), WAGER + 50000000n, H - 10, 'ee');
  const out = new OutputBuilder(POT, destination).setAdditionalRegisters(acceptRegisters as any);
  const tx = new TransactionBuilder(H)
    .from([
      { ...normalizeInputBox(lobby as any), extension: { 0: SByte(1).toHex() } } as any,
      normalizeInputBox(fund as any) as any,
    ])
    .to(out).sendChangeTo(chalAddr.encode()).payFee(FEE).build();
  return { tx, inputs: [lobby, fund] };
}

describe('D. lobby escrow destination is code, not host-controlled data (R8)', () => {
  it('D1 REGRESSION: a lobby whose R8 is the host P2PK hash paying the whole 2 ERG escrow to the host is now rejected', () => {
    // Unchanged PoC transaction: same evil R8, same P2PK destination. R8 is no longer read, so the
    // hard-coded BATTLESHIPS_HASH comparison fails and the accept reduces to false.
    const { tx, inputs } = acceptTx(lobbyBox(EVIL_R8), hostAddr.encode());
    expect(() => reduceAndSign(tx, inputs, chalSecret, H)).toThrow(/reduced to false/i);
  });

  it('D2 CONTROL: the same payout with the honest R8 in the lobby is rejected', () => {
    const { tx, inputs } = acceptTx(lobbyBox(HONEST_R8), hostAddr.encode());
    expect(() => reduceAndSign(tx, inputs, chalSecret, H)).toThrow(/reduced to false/i);
  });

  it('D3 CONTROL: the honest accept into the battleships contract is accepted', () => {
    const { tx, inputs } = acceptTx(lobbyBox(HONEST_R8), getBattleshipsAddress());
    const signed = reduceAndSign(tx, inputs, chalSecret, H);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(getBattleshipsErgoTree().toHex());
  });
});

// ============================================================ E. blocked lobby+game merge
function gameBox(phase: number) {
  return withId({
    value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: H - 40,
    additionalRegisters: {
      R4: acceptRegisters.R4,
      R5: acceptRegisters.R5,
      R6: SColl(SInt, [phase, 0, 0]).toHex(),
      R7: SColl(SInt, []).toHex(),          // nothing in flight -> no Merkle proofs needed
      R8: SColl(SColl(SByte), [Array(64).fill(0), Array(64).fill(0)]).toHex(),
      R9: SColl(SInt, [H + 20, TB]).toHex(),
    },
    transactionId: 'cd'.repeat(32), index: 0,
  });
}

describe('E. absorbing a victim lobby into an existing game box (FAILS)', () => {
  function mergeTx(phase: number) {
    const lobby = lobbyBox(HONEST_R8);
    const game = gameBox(phase);
    const fund = utxo(chalAddr.encode(), 20000000n, H - 10, 'ee');
    const out = new OutputBuilder(POT, getBattleshipsAddress()).setAdditionalRegisters({
      ...acceptRegisters,
      R9: SColl(SInt, [H + TB - 10, TB]).toHex(),
    } as any);
    const tx = new TransactionBuilder(H)
      .from([
        { ...normalizeInputBox(lobby as any), extension: { 0: SByte(1).toHex() } } as any,
        { ...normalizeInputBox(game as any), extension: { 0: SByte(0).toHex() } } as any,
        normalizeInputBox(fund as any) as any,
      ])
      .to(out).sendChangeTo(chalAddr.encode()).payFee(FEE).build();
    return { tx, inputs: [lobby, game, fund] };
  }

  it('E1 phase 1 (so nextPhase == 0 as the lobby demands): rejected by validSalvoSize', () => {
    const { tx, inputs } = mergeTx(1);
    expect(() => reduceAndSign(tx, inputs, chalSecret, H)).toThrow(/reduced to false/i);
  });

  it('E2 phase 0 (so an empty salvo would be legal): rejected by validPhase', () => {
    const { tx, inputs } = mergeTx(0);
    expect(() => reduceAndSign(tx, inputs, chalSecret, H)).toThrow(/reduced to false/i);
  });
});

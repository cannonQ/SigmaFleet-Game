/**
 * Round 2 — independent verification of the EKB pass-2 findings I did not raise,
 * plus two tests that dispute EKB's stated impact / fix.
 *
 * R2-1  VF-03 confirmed: winPayout + devFeeNano == totalPot exactly, so a settlement cannot
 *       pay its own miner fee. The claimant must hold a separate UTXO or the pot is stranded.
 * R2-2  VF-04 DISPUTED (impact): EKB says an empty history is "denial rather than theft".
 *       When the *claimant's own* history is the empty one, the follow-on fold never touches it,
 *       so p1CoveredBoard is vacuously true and P1 collects the entire pot having fired nothing.
 * R2-3  L-07 extended: proveDlog(identity) is spendable by anyone — shown on the LOBBY's own
 *       refund branch, which EKB did not test (they only showed the register deserialises).
 * R2-4  SF-02 fix comparison: the `activeCovered` limb of EKB's proposed guard is unreachable.
 *       Whenever the active player's claim rights come from coverage rather than 10 hits, the
 *       opponent's Action 2 sweep is ALREADY blocked by honestScore.
 * R2-5  SF-02 structural claim CONFIRMED: a player whose claim rights arrive on the wrong phase
 *       is blocked from Action 1 but is never denied a window — Action 2 pays them instead.
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
  getBattleshipsErgoTree, getLobbyErgoTree, normalizeInputBox, DEFAULT_DEV_PK,
} from '../src/lib/blockchain/fleet';

const DEV_PK = DEFAULT_DEV_PK;
const POT = 2000000000n;
const DEV_FEE = POT / 100n;
const WIN = POT - DEV_FEE;
const TB = 30;
const FEE = 1100000n;
const H = 1250000;

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
const hist = (cells: number[]) => { const a = new Array(64).fill(0); cells.forEach((c) => (a[c] = 1)); return a; };
const ALL_FIRED = new Array(64).fill(1);

const p1Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('11'.repeat(32)));
const p1Addr = ErgoAddress.fromBase58(p1Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p1Pk = bytesToHex(p1Addr.getPublicKeys()[0]);
const p2Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('22'.repeat(32)));
const p2Addr = ErgoAddress.fromBase58(p2Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p2Pk = bytesToHex(p2Addr.getPublicKeys()[0]);
const DEV_ADDR = ErgoAddress.fromPublicKey(DEV_PK).encode();

const g1 = new Array(64).fill(0); [0, 1, 2, 3, 4, 16, 17, 18, 32, 33].forEach((c) => (g1[c] = 1));
const g2 = new Array(64).fill(0); [8, 9, 10, 11, 12, 24, 25, 26, 40, 41].forEach((c) => (g2[c] = 1));
const com1 = generateBoardCommitment(g1, '11'.repeat(32));
const com2 = generateBoardCommitment(g2, '22'.repeat(32));

const R4 = SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(p2Pk), hexToBytes(DEV_PK)]).toHex();
const R5 = SColl(SColl(SByte), [
  Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com2.rootHex)),
  Array.from(hexToBytes(com1.boardHashHex)), Array.from(hexToBytes(com2.boardHashHex)),
]).toHex();

function gameBox(o: {
  phase: number; p1Hits: number; p2Hits: number; pending: number[];
  p1History: number[]; p2History: number[]; timeoutHeight: number; tag?: string;
}) {
  return withId({
    value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: H - 60,
    additionalRegisters: {
      R4, R5,
      R6: SColl(SInt, [o.phase, o.p1Hits, o.p2Hits]).toHex(),
      R7: SColl(SInt, o.pending).toHex(),
      R8: SColl(SColl(SByte), [o.p1History, o.p2History]).toHex(),
      R9: SColl(SInt, [o.timeoutHeight, TB]).toHex(),
    },
    transactionId: (o.tag || 'cd').repeat(32), index: 0,
  });
}

// ---------------------------------------------------------------- R2-1  (VF-03)
describe('R2-1 VF-03: the settlement outputs consume the whole pot, so the fee needs a second UTXO', () => {
  // p2 fired only water on P1's board, nothing pending -> honestScore 0 == 0, P1 has 10 hits.
  const st = {
    phase: 0, p1Hits: 10, p2Hits: 0, pending: [] as number[],
    p1History: hist([5, 6, 7]), p2History: hist([56, 57, 58, 59, 60]), timeoutHeight: H + 20,
  };
  const ext = { 0: SByte(1).toHex(), 99: SColl(SByte, Array.from(com1.saltedBoardPayload)).toHex() };

  it('arithmetic: winPayout + devFeeNano == totalPot exactly, leaving zero slack', () => {
    expect(WIN + DEV_FEE).toBe(POT);
  });

  it('R2-1a CONFIRMED: paying the miner fee out of the pot is rejected (OUTPUTS(0).value >= winPayout)', () => {
    const gb = gameBox(st);
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(gb as any), extension: ext } as any])
      .to([new OutputBuilder(WIN - FEE, p1Addr.encode()), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .payFee(FEE)
      .build();
    expect(() => reduceAndSign(tx, [gb], p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('R2-1b CONTROL: the same settlement with an independent funding UTXO signs', () => {
    const gb = gameBox({ ...st, tag: 'ce' });
    const u = utxo(p1Addr.encode(), 20000000n, H - 60);
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(gb as any), extension: ext } as any, normalizeInputBox(u as any) as any])
      .to([new OutputBuilder(WIN, p1Addr.encode()), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    const signed = reduceAndSign(tx, [gb, u], p1Secret, H);
    expect(BigInt(JSON.parse(signed.outputs().get(0).to_json()).value)).toBe(WIN);
  });
});

// ---------------------------------------------------------------- R2-2  (VF-04)
describe('R2-2 VF-04: an empty claimant history is theft, not denial', () => {
  function emptyHistBox(p1History: number[]) {
    return withId({
      value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: H - 60,
      additionalRegisters: {
        R4, R5,
        R6: SColl(SInt, [0, 0, 0]).toHex(),           // zero hits, opening state
        R7: SColl(SInt, []).toHex(),
        R8: SColl(SColl(SByte), [p1History, hist([56, 57, 58, 59, 60])]).toHex(),
        R9: SColl(SInt, [H + 20, TB]).toHex(),
      },
      transactionId: 'df'.repeat(32), index: 0,
    });
  }
  const ext = { 0: SByte(1).toHex(), 99: SColl(SByte, Array.from(com1.saltedBoardPayload)).toHex() };
  function claim(gb: any) {
    const u = utxo(p1Addr.encode(), 20000000n, H - 60, 'ac');
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(gb as any), extension: ext } as any, normalizeInputBox(u as any) as any])
      .to([new OutputBuilder(WIN, p1Addr.encode()), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    return { tx, inputs: [gb, u] };
  }

  it('R2-2a EXPLOIT: R8(0) empty -> p1CoveredBoard is vacuously true and P1 takes the whole pot on move zero', () => {
    const { tx, inputs } = claim(emptyHistBox([]));
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(p1Addr.ergoTree);
    expect(BigInt(out0.value)).toBe(WIN);
  });

  it('R2-2b CONTROL: the identical box with a proper 64-byte zero history is rejected (no claim rights)', () => {
    const { tx, inputs } = claim(emptyHistBox(hist([])));
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });
});

// ---------------------------------------------------------------- R2-3  (L-07)
describe('R2-3 L-07: proveDlog(identity) is spendable by anyone, on the lobby refund branch too', () => {
  const zeroSecret = wasm.SecretKey.dlog_from_bytes(new Uint8Array(32));
  // fleet-sdk's ErgoAddress.fromBase58 refuses the identity address outright, so read the
  // point straight out of sigma-rust instead of round-tripping through an address.
  const IDENTITY_PK = bytesToHex(new Uint8Array(zeroSecret.get_address().to_bytes(wasm.NetworkPrefix.Mainnet)).slice(1, 34));
  const IDENTITY_TREE = '0008cd' + IDENTITY_PK;

  function lobby(hostPk: string) {
    return withId({
      value: '1000000000', ergoTree: getLobbyErgoTree().toHex(), assets: [], creationHeight: H - 500,
      additionalRegisters: {
        R4: SColl(SGroupElement, [hexToBytes(hostPk), hexToBytes(DEV_PK)]).toHex(),
        R5: SColl(SColl(SByte), [
          Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com1.boardHashHex)),
        ]).toHex(),
        R6: SColl(SInt, []).toHex(),
        R7: SColl(SByte, []).toHex(),
        R8: SColl(SByte, Array.from(hashBlake2b256(hexToBytes(getBattleshipsErgoTree().toHex())))).toHex(),
        R9: SInt(TB).toHex(),
      },
      transactionId: 'e4'.repeat(32), index: 0,
    });
  }
  function cancel(lb: any) {
    const u = utxo(p2Addr.encode(), 20000000n, H - 500, 'e5');
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(lb as any), extension: { 0: SByte(0).toHex() } } as any, normalizeInputBox(u as any) as any])
      .to(new OutputBuilder(1000000000n, p2Addr.encode()))
      .sendChangeTo(p2Addr.encode()).payFee(FEE).build();
    return { tx, inputs: [lb, u] };
  }

  it('the zero scalar yields the identity point and a bare 0008cd + 33 zero-byte tree', () => {
    // eslint-disable-next-line no-console
    console.log(`  identity pk = ${IDENTITY_PK}  tree = ${IDENTITY_TREE}`);
    expect(IDENTITY_PK).toBe('00'.repeat(33));
  });

  it('R2-3a: a lobby whose R4(0) is the identity point is refunded to a stranger holding the zero secret', () => {
    const { tx, inputs } = cancel(lobby(IDENTITY_PK));
    const secrets = new wasm.SecretKeys();
    secrets.add(zeroSecret); secrets.add(p2Secret);
    const utx = wasm.UnsignedTransaction.from_json(s(tx.toPlainObject()));
    const bs = wasm.ErgoBoxes.empty();
    for (const b of inputs) bs.add(wasm.ErgoBox.from_json(s(b)));
    const reduced = wasm.ReducedTransaction.from_unsigned_tx(utx, bs, wasm.ErgoBoxes.empty(), stateCtx(H));
    const signed = wasm.Wallet.from_secrets(secrets).sign_reduced_transaction(reduced);
    expect(JSON.parse(signed.outputs().get(0).to_json()).ergoTree).toBe(p2Addr.ergoTree);
  });

  it('R2-3b CONTROL: the same refund of a real host lobby is rejected without the host key', () => {
    const { tx, inputs } = cancel(lobby(p1Pk));
    const secrets = new wasm.SecretKeys();
    secrets.add(zeroSecret); secrets.add(p2Secret);
    const utx = wasm.UnsignedTransaction.from_json(s(tx.toPlainObject()));
    const bs = wasm.ErgoBoxes.empty();
    for (const b of inputs) bs.add(wasm.ErgoBox.from_json(s(b)));
    const reduced = wasm.ReducedTransaction.from_unsigned_tx(utx, bs, wasm.ErgoBoxes.empty(), stateCtx(H));
    expect(() => wasm.Wallet.from_secrets(secrets).sign_reduced_transaction(reduced)).toThrow();
  });
});

// ---------------------------------------------------------------- R2-4  (SF-02 fix design)
describe('R2-4 SF-02 fix: the `activeCovered` limb of EKB guard is unreachable', () => {
  function sweep(gb: any, sk: any, addr: string, payload: Uint8Array, height: number) {
    const u = utxo(addr, 20000000n, H - 60, 'e7');
    const tx = new TransactionBuilder(height)
      .from([
        { ...normalizeInputBox(gb as any), extension: { 0: SByte(2).toHex(), 99: SColl(SByte, Array.from(payload)).toHex() } } as any,
        normalizeInputBox(u as any) as any,
      ])
      .to([new OutputBuilder(WIN, addr), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .sendChangeTo(addr).payFee(FEE).build();
    return { tx, inputs: [gb, u] };
  }

  it('R2-4a: active player covered with p1Hits < 10 (opponent lied) — the opponent sweep is ALREADY blocked by honestScore', () => {
    // phase 0 -> Action 2 pays P2. opponentRecordedHits = p1Hits = 6, but P1 fired every cell,
    // so opponentTrueHits against P2's revealed board is 10. honestScore fails.
    const gb = gameBox({
      phase: 0, p1Hits: 6, p2Hits: 3, pending: [],
      p1History: ALL_FIRED, p2History: hist([0, 1, 2]), timeoutHeight: H - 1, tag: 'e8',
    });
    const { tx, inputs } = sweep(gb, p2Secret, p2Addr.encode(), com2.saltedBoardPayload, H);
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('R2-4b: active player covered with p1Hits == 10 (opponent honest) — the sweep succeeds, and `opponentRecordedHits < 10` is exactly what stops it', () => {
    const gb = gameBox({
      phase: 0, p1Hits: 10, p2Hits: 3, pending: [],
      p1History: ALL_FIRED, p2History: hist([0, 1, 2]), timeoutHeight: H - 1, tag: 'e9',
    });
    const { tx, inputs } = sweep(gb, p2Secret, p2Addr.encode(), com2.saltedBoardPayload, H);
    const signed = reduceAndSign(tx, inputs, p2Secret, H);
    expect(JSON.parse(signed.outputs().get(0).to_json()).ergoTree).toBe(p2Addr.ergoTree);
  });
});

// ---------------------------------------------------------------- R2-5  (SF-02 structural)
describe('R2-5 SF-02 structural claim: claim rights on the wrong phase are never a dead end', () => {
  // P1 has just fired their 64th cell, so coverage arrives on P1's own move and the phase is now 1.
  const st = {
    phase: 1, p1Hits: 7, p2Hits: 0, pending: [60, 61, 62, 63],
    p1History: ALL_FIRED, p2History: hist([56, 57, 58, 59, 60]),
  };
  const claimExt = { 0: SByte(1).toHex(), 99: SColl(SByte, Array.from(com1.saltedBoardPayload)).toHex() };

  it('R2-5a: P1 cannot settle at phase 1 — claimerHasPendingSalvo blocks Action 1', () => {
    const gb = gameBox({ ...st, timeoutHeight: H + 20, tag: 'ea' });
    const u = utxo(p1Addr.encode(), 20000000n, H - 60, 'eb');
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(gb as any), extension: claimExt } as any, normalizeInputBox(u as any) as any])
      .to([new OutputBuilder(WIN, p1Addr.encode()), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    expect(() => reduceAndSign(tx, [gb, u], p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('R2-5b: but P1 is not stranded — once P2 lets the clock run out, Action 2 pays P1', () => {
    const gb = gameBox({ ...st, timeoutHeight: H - 1, tag: 'ec' });
    const u = utxo(p1Addr.encode(), 20000000n, H - 60, 'ed');
    const tx = new TransactionBuilder(H)
      .from([
        { ...normalizeInputBox(gb as any), extension: { 0: SByte(2).toHex(), 99: SColl(SByte, Array.from(com1.saltedBoardPayload)).toHex() } } as any,
        normalizeInputBox(u as any) as any,
      ])
      .to([new OutputBuilder(WIN, p1Addr.encode()), new OutputBuilder(DEV_FEE, DEV_ADDR)])
      .sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    const signed = reduceAndSign(tx, [gb, u], p1Secret, H);
    expect(JSON.parse(signed.outputs().get(0).to_json()).ergoTree).toBe(p1Addr.ergoTree);
  });
});

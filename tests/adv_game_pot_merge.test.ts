/**
 * F. ACTION 0 GAME-BOX MERGE -- outright pot theft, now closed by Rule 0.
 *
 * Before the hardening patch every input under the battleships script inspected only
 * OUTPUTS(0), and the only value rule in ACTION 0 was
 *      val validOutput = (outGame.propositionBytes == SELF.propositionBytes) &&
 *                        (outGame.value == SELF.value) && validTokens
 * There was no "the sum of the inputs under this script equals OUTPUTS(0)". So n game boxes
 * that agree on R4, R5, R6, R8, R9(1) and value could all be spent in ONE ACTION 0
 * transaction against a single OUTPUTS(0) worth one pot, and the other n-1 pots left as
 * change to whoever built the transaction.
 *
 * The patched contract adds
 *      val singleInput = INPUTS.filter({ (b: Box) => b.propositionBytes == SELF.propositionBytes }).size == 1
 * to ACTION 0, ACTION 1 and ACTION 2, so every merged transaction below now reduces to false.
 * The transactions are byte-for-byte the attacks that used to succeed, with one unavoidable
 * update: the hand-built output R9(0) moved into the new Rule 7 band
 * [HEIGHT + timeoutBlocks, HEIGHT + timeoutBlocks + 14] so that the ONLY thing rejecting them
 * is the merge guard, not a stale deadline. The single-box CONTROLs prove exactly that:
 * the identical turn on one input still signs.
 *
 * F1  REGRESSION: two fresh 2 ERG game boxes -> rejected.
 * F2  REGRESSION: three boxes -> rejected.
 * F3  REGRESSION: the same trick mid-match, on P2's turn, with genuine Merkle proofs supplied
 *     separately per input and DIFFERENT in-flight salvos in R7 -> rejected.
 * F3b CONTROL: the same mid-match turn on ONE box signs.
 * F4  CONTROL: differing commitments in R5 -> rejected (outHashes == roots).
 * F5  CONTROL: differing pot values -> rejected (outGame.value == SELF.value).
 * F6  CONTROL: a single fresh game box played alone under ACTION 0 signs.
 * F7..F10 Rule 7 band regression: HEIGHT + tb - 1 and HEIGHT + tb + 15 are rejected,
 *     HEIGHT + tb and HEIGHT + tb + 14 sign.
 */
import { describe, it, expect } from 'vitest';
import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  ErgoAddress, SColl, SInt, SByte, SGroupElement, OutputBuilder, TransactionBuilder,
} from '@fleet-sdk/core';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { serializeBox } from '@fleet-sdk/serializer';
import { generateBoardCommitment, hashBlake2b256, generateMerkleProof } from '../src/lib/crypto/merkle';
import {
  getBattleshipsErgoTree, getBattleshipsAddress, normalizeInputBox, DEFAULT_DEV_PK,
} from '../src/lib/blockchain/fleet';

const DEV_PK = DEFAULT_DEV_PK;
const POT = 2000000000n;   // 2 ERG: two 1 ERG stakes
const TB = 30;
const FEE = 1100000n;
const H = 1250000;
// Rule 7 mempool tolerance: nextTimeoutHeight must land in [HEIGHT + TB, HEIGHT + TB + 14].
// The state context below puts HEIGHT exactly at H, so H + TB + 14 is the top of the band
// and the value the production builder (buildPlayTurnTx) writes.
const SLACK = 14;

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
function utxo(addr: string, v: bigint, h: number) {
  return withId({
    value: v.toString(), ergoTree: ErgoAddress.fromBase58(addr).ergoTree, assets: [],
    creationHeight: h, additionalRegisters: {}, transactionId: 'ab'.repeat(32), index: 0,
  });
}
const hist = (cells: number[]) => { const a = new Array(64).fill(0); cells.forEach((c) => (a[c] = 1)); return a; };

const p1Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('11'.repeat(32)));
const p1Addr = ErgoAddress.fromBase58(p1Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p1Pk = bytesToHex(p1Addr.getPublicKeys()[0]);
const p2Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('22'.repeat(32)));
const p2Addr = ErgoAddress.fromBase58(p2Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p2Pk = bytesToHex(p2Addr.getPublicKeys()[0]);

const g1 = new Array(64).fill(0); [0, 1, 2, 3, 4, 16, 17, 18, 32, 33].forEach((c) => (g1[c] = 1));
const g2 = new Array(64).fill(0); [8, 9, 10, 11, 12, 24, 25, 26, 40, 41].forEach((c) => (g2[c] = 1));
const com1 = generateBoardCommitment(g1, '11'.repeat(32));
const com2 = generateBoardCommitment(g2, '22'.repeat(32));
const comX = generateBoardCommitment(g1, '33'.repeat(32)); // a different commitment, same fleet

const R4 = SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(p2Pk), hexToBytes(DEV_PK)]).toHex();
const mkR5 = (a: any, b: any) => SColl(SColl(SByte), [
  Array.from(hexToBytes(a.rootHex)), Array.from(hexToBytes(b.rootHex)),
  Array.from(hexToBytes(a.boardHashHex)), Array.from(hexToBytes(b.boardHashHex)),
]).toHex();
const R5 = mkR5(com1, com2);

function box(o: {
  tag: string; value?: bigint; r5?: string; phase: number; p1Hits: number; p2Hits: number;
  pending: number[]; p1History: number[]; p2History: number[]; timeoutHeight: number;
}) {
  return withId({
    value: (o.value ?? POT).toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [],
    creationHeight: H - 30,
    additionalRegisters: {
      R4, R5: o.r5 ?? R5,
      R6: SColl(SInt, [o.phase, o.p1Hits, o.p2Hits]).toHex(),
      R7: SColl(SInt, o.pending).toHex(),
      R8: SColl(SColl(SByte), [o.p1History, o.p2History]).toHex(),
      R9: SColl(SInt, [o.timeoutHeight, TB]).toHex(),
    },
    transactionId: o.tag.repeat(32), index: 0,
  });
}

const fresh = (tag: string, extra: any = {}) => box({
  tag, phase: 0, p1Hits: 0, p2Hits: 0, pending: [],
  p1History: hist([]), p2History: hist([]), timeoutHeight: H + 20, ...extra,
});

// P1's opening salvo; no incoming salvo means no Merkle proofs are needed.
const OPENING = [10, 25, 42, 51, 60];
function openingOutput(value = POT, nextTimeoutHeight = H + TB + SLACK) {
  return new OutputBuilder(value, getBattleshipsAddress()).setAdditionalRegisters({
    R4, R5,
    R6: SColl(SInt, [1, 0, 0]).toHex(),
    R7: SColl(SInt, OPENING).toHex(),
    R8: SColl(SColl(SByte), [hist(OPENING), hist([])]).toHex(),
    R9: SColl(SInt, [nextTimeoutHeight, TB]).toHex(),
  } as any);
}

// One transaction shape for every ACTION 0 case: n game boxes (n == 1 is the honest path,
// n > 1 is the merge attack) plus one funding box, against a single game output.
function mergeTx(boxes: any[], out: OutputBuilder) {
  const u = utxo(p1Addr.encode(), 20000000n, H - 30);
  const tx = new TransactionBuilder(H)
    .from([
      ...boxes.map((b) => ({ ...normalizeInputBox(b as any), extension: { 0: SByte(0).toHex() } }) as any),
      normalizeInputBox(u as any) as any,
    ])
    // fleet-sdk runs coin selection over .from(); pin every box so the merge really happens.
    .configureSelector((sel: any) => sel.ensureInclusion(boxes.map((b) => b.boxId)))
    .to(out).sendChangeTo(p1Addr.encode()).payFee(FEE).build();
  return { tx, inputs: [...boxes, u] };
}

const changeTo = (signed: any, tree: string) => {
  let total = 0n;
  const outs = signed.outputs();
  for (let i = 1; i < outs.len(); i++) {
    const o = outs.get(i);
    if (o.ergo_tree().to_base16_bytes() === tree) total += BigInt(o.value().as_i64().to_str());
  }
  return total;
};

// ---------------------------------------------------------------------------
// F3 shared fixture: a real mid-match turn on P2's side, with genuine Merkle proofs.
// Identical shot histories, but the two matches reached them in a different salvo order,
// so R7 differs. Both salvos are water on P2's board, so both answer with newHits == 0.
// ---------------------------------------------------------------------------
const F3_P1_FIRED = [0, 1, 2, 3, 4, 16, 17, 18, 19, 20];
const F3_SALVO_A = [0, 1, 2, 3, 4];
const F3_SALVO_B = [16, 17, 18, 19, 20];
const F3_P2_FIRED = [56, 57, 58, 59, 60];
const F3_NEXT_SALVO = [32, 33, 34, 35, 36];

function midMatchBox(tag: string, pending: number[]) {
  return box({
    tag, pending, phase: 1, p1Hits: 0, p2Hits: 0,
    p1History: hist(F3_P1_FIRED), p2History: hist(F3_P2_FIRED), timeoutHeight: H + 20,
  });
}
function midMatchOutput() {
  return new OutputBuilder(POT, getBattleshipsAddress()).setAdditionalRegisters({
    R4, R5,
    R6: SColl(SInt, [0, 0, 0]).toHex(),
    R7: SColl(SInt, F3_NEXT_SALVO).toHex(),
    R8: SColl(SColl(SByte), [hist(F3_P1_FIRED), hist([...F3_P2_FIRED, ...F3_NEXT_SALVO])]).toHex(),
    R9: SColl(SInt, [H + TB + SLACK, TB]).toHex(),
  } as any);
}
// Per-input context extension: action 0 plus one 224-byte Merkle proof per incoming target.
const midMatchExt = (cells: number[]) => {
  const e: Record<number, string> = { 0: SByte(0).toHex() };
  cells.forEach((c, i) => {
    e[i + 1] = SColl(SByte, Array.from(generateMerkleProof(c, com2.rawLeaves, com2.tree).proofBytes)).toHex();
  });
  return e;
};
function midMatchTx(entries: { box: any; salvo: number[] }[]) {
  const u = utxo(p2Addr.encode(), 20000000n, H - 30);
  const tx = new TransactionBuilder(H)
    .from([
      ...entries.map((e) => ({ ...normalizeInputBox(e.box as any), extension: midMatchExt(e.salvo) }) as any),
      normalizeInputBox(u as any) as any,
    ])
    .configureSelector((sel: any) => sel.ensureInclusion(entries.map((e) => e.box.boxId)))
    .to(midMatchOutput()).sendChangeTo(p2Addr.encode()).payFee(FEE).build();
  return { tx, inputs: [...entries.map((e) => e.box), u] };
}

describe('F. ACTION 0 no longer collapses several game boxes into one', () => {
  it('F1 REGRESSION: merging two identical 2 ERG game boxes is now rejected', () => {
    const { tx, inputs } = mergeTx([fresh('c1'), fresh('c2')], openingOutput());
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F2 REGRESSION: merging three identical game boxes is now rejected', () => {
    const { tx, inputs } = mergeTx([fresh('c1'), fresh('c2'), fresh('c3')], openingOutput());
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F3 REGRESSION: the mid-match merge on P2 turn, with real proofs and DIFFERENT in-flight salvos per input, is now rejected', () => {
    const { tx, inputs } = midMatchTx([
      { box: midMatchBox('d1', F3_SALVO_A), salvo: F3_SALVO_A },
      { box: midMatchBox('d2', F3_SALVO_B), salvo: F3_SALVO_B },
    ]);
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('F3b CONTROL: the same mid-match turn on ONE box signs', () => {
    const { tx, inputs } = midMatchTx([{ box: midMatchBox('d1', F3_SALVO_A), salvo: F3_SALVO_A }]);
    const signed = reduceAndSign(tx, inputs, p2Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe(POT.toString());
    // Only the funding box is left over, never a whole pot.
    expect(changeTo(signed, p2Addr.ergoTree)).toBeLessThan(20000000n);
  });

  it('F4 CONTROL: two boxes with different R5 commitments are rejected', () => {
    const { tx, inputs } = mergeTx([fresh('c1'), fresh('c2', { r5: mkR5(comX, com2) })], openingOutput());
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F5 CONTROL: two boxes with different pot values are rejected', () => {
    const { tx, inputs } = mergeTx([fresh('c1'), fresh('c2', { value: POT + 1000000n })], openingOutput());
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F6 CONTROL: a single fresh game box played alone under ACTION 0 signs', () => {
    const { tx, inputs } = mergeTx([fresh('c1')], openingOutput());
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe(POT.toString());
    expect(changeTo(signed, p1Addr.ergoTree)).toBeLessThan(20000000n); // funding change only
  });
});

/**
 * Rule 7 band regression. The old window was [HEIGHT + tb - 10, HEIGHT + tb + 4], which let a
 * mover hand the opponent a deadline up to ten blocks EARLIER than nominal. The patched window
 * is [HEIGHT + tb, HEIGHT + tb + 14]: never early, and up to 14 blocks of mempool slack late.
 * HEIGHT is exactly H under the state context built above.
 */
describe('F7-F10. ACTION 0 next-deadline band is [HEIGHT + tb, HEIGHT + tb + 14]', () => {
  const play = (nextTimeoutHeight: number) => mergeTx([fresh('c1')], openingOutput(POT, nextTimeoutHeight));

  it('F7 REGRESSION: a single-box turn setting nextTimeoutHeight = HEIGHT + tb - 1 is rejected', () => {
    const { tx, inputs } = play(H + TB - 1);
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F8 REGRESSION: a single-box turn setting nextTimeoutHeight = HEIGHT + tb + 15 is rejected', () => {
    const { tx, inputs } = play(H + TB + 15);
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('F9 CONTROL: nextTimeoutHeight = HEIGHT + tb (bottom of the band) signs', () => {
    const { tx, inputs } = play(H + TB);
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe(POT.toString());
  });

  it('F10 CONTROL: nextTimeoutHeight = HEIGHT + tb + 14 (top of the band, what buildPlayTurnTx writes) signs', () => {
    const { tx, inputs } = play(H + TB + SLACK);
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe(POT.toString());
  });
});

/**
 * G. The same missing "one box in, one box out" invariant in ACTION 1, also closed by Rule 0.
 *
 * getVar(99) is a PER-INPUT context extension, so two settlements with completely different
 * board commitments used to share one transaction. validPayout only says
 *      OUTPUTS(0).value >= winPayout  &&  OUTPUTS(1).value >= devFeeNano
 * per box, so n concluded matches settled against ONE dev-fee output: the protocol was paid
 * once instead of n times, and the surplus landed in the claimant's change. Unlike F this was
 * not pot theft -- the claimant had to be the rightful winner of every box it merged -- it was
 * a protocol-fee leak. singleInput now rejects the batch, while a lone settlement still signs.
 */
describe('G. ACTION 1 no longer settles several matches against a single dev-fee output', () => {
  const comY = generateBoardCommitment(g1, '44'.repeat(32)); // P1's board, different salt
  const p2Fired = [56, 57, 58, 59, 60];                      // all water on P1's board
  const settleBox = (tag: string, r5: string) => withId({
    value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: H - 30,
    additionalRegisters: {
      R4, R5: r5,
      R6: SColl(SInt, [0, 10, 0]).toHex(),   // phase 0 (P1's turn), P1 on ten hits
      R7: SColl(SInt, []).toHex(),
      R8: SColl(SColl(SByte), [hist([0, 1, 2, 3, 4]), hist(p2Fired)]).toHex(),
      R9: SColl(SInt, [H + 20, TB]).toHex(),
    },
    transactionId: tag.repeat(32), index: 0,
  });

  const ext = (payload: Uint8Array) => ({
    0: SByte(1).toHex(),
    99: SColl(SByte, Array.from(payload)).toHex(),
  });

  // entries: the concluded matches being settled. One entry is the honest path; two is the batch.
  function settleTx(devValue: bigint, entries: { box: any; payload: Uint8Array }[]) {
    const u = utxo(p1Addr.encode(), 20000000n, H - 30);
    const win = new OutputBuilder(POT - POT / 100n, p1Addr.encode());
    const dev = new OutputBuilder(devValue, ErgoAddress.fromPublicKey(DEV_PK).encode());
    const tx = new TransactionBuilder(H)
      .from([
        ...entries.map((e) => ({ ...normalizeInputBox(e.box as any), extension: ext(e.payload) }) as any),
        normalizeInputBox(u as any) as any,
      ])
      .configureSelector((sel: any) => sel.ensureInclusion(entries.map((e) => e.box.boxId)))
      .to([win, dev]).sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    return { tx, inputs: [...entries.map((e) => e.box), u] };
  }

  const batch = (devValue: bigint) => settleTx(devValue, [
    { box: settleBox('e1', mkR5(com1, com2)), payload: com1.saltedBoardPayload },
    { box: settleBox('e2', mkR5(comY, com2)), payload: comY.saltedBoardPayload },
  ]);
  const single = (devValue: bigint) => settleTx(devValue, [
    { box: settleBox('e1', mkR5(com1, com2)), payload: com1.saltedBoardPayload },
  ]);

  const devTotal = (signed: any) => {
    let total = 0n;
    const outs = signed.outputs();
    const devTree = ErgoAddress.fromPublicKey(DEV_PK).ergoTree;
    for (let i = 0; i < outs.len(); i++) {
      const o = outs.get(i);
      if (o.ergo_tree().to_base16_bytes() === devTree) total += BigInt(o.value().as_i64().to_str());
    }
    return total;
  };

  it('G1 REGRESSION: settling two 2 ERG matches against a single 0.02 ERG dev fee is now rejected', () => {
    const { tx, inputs } = batch(POT / 100n);
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('G1b CONTROL: a single settlement paying one dev fee signs', () => {
    const { tx, inputs } = single(POT / 100n);
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe((POT - POT / 100n).toString());
    expect(devTotal(signed)).toBe(POT / 100n);                 // exactly one pot's fee, for one pot
    expect(changeTo(signed, p1Addr.ergoTree)).toBeLessThan(20000000n);
  });

  it('G2 CONTROL: a dev output one nanoErg below devFeeNano is rejected', () => {
    const { tx, inputs } = batch(POT / 100n - 1n);
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });
});

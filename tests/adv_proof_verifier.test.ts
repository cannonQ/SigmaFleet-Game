/**
 * Adversarial probing of the ACTION 0 Merkle verifier and salvo rules.
 *
 * V0 is the honest control (accepted). V1..V7 are the attacks I could think of against the
 * 224-byte proof layout, the (t / powers(lvl)) % 2 path bits, and the score enforcement.
 * All of V1..V7 are REJECTED; the file exists to record exactly which rule stops each one.
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
const POT = 2000000000n;
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

// It is P2's turn (phase 1). P1's salvo [8, 9, 10, 20, 21] is in flight against P2's board:
// 8, 9, 10 are carrier cells, 20 and 21 are water. Honest answer -> 3 hits, p1Hits 0 -> 3.
const INCOMING = [8, 9, 10, 20, 21];
const P2_NEXT_SALVO = [0, 1, 2, 3, 4];
const R4 = SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(p2Pk), hexToBytes(DEV_PK)]).toHex();
const R5 = SColl(SColl(SByte), [
  Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com2.rootHex)),
  Array.from(hexToBytes(com1.boardHashHex)), Array.from(hexToBytes(com2.boardHashHex)),
]).toHex();

function gameBox() {
  return withId({
    value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: H - 30,
    additionalRegisters: {
      R4, R5,
      R6: SColl(SInt, [1, 0, 0]).toHex(),
      R7: SColl(SInt, INCOMING).toHex(),
      R8: SColl(SColl(SByte), [hist(INCOMING), hist([])]).toHex(),
      R9: SColl(SInt, [H + 20, TB]).toHex(),
    },
    transactionId: 'cd'.repeat(32), index: 0,
  });
}

function turnTx(opts: { proofs: Uint8Array[]; claimedP1Hits: number; salvo?: number[] }) {
  const gb = gameBox();
  const u = utxo(p2Addr.encode(), 20000000n, H - 30);
  const salvo = opts.salvo ?? P2_NEXT_SALVO;
  const ext: Record<number, string> = { 0: SByte(0).toHex() };
  opts.proofs.forEach((p, i) => { ext[i + 1] = SColl(SByte, Array.from(p)).toHex(); });
  const out = new OutputBuilder(POT, getBattleshipsAddress()).setAdditionalRegisters({
    R4, R5,
    R6: SColl(SInt, [0, opts.claimedP1Hits, 0]).toHex(),
    R7: SColl(SInt, salvo).toHex(),
    R8: SColl(SColl(SByte), [hist(INCOMING), hist(salvo)]).toHex(),
    R9: SColl(SInt, [H + TB + 4, TB]).toHex(),
  } as any);
  const tx = new TransactionBuilder(H)
    .from([{ ...normalizeInputBox(gb as any), extension: ext } as any, normalizeInputBox(u as any) as any])
    .to(out).sendChangeTo(p2Addr.encode()).payFee(FEE).build();
  return { tx, inputs: [gb, u] };
}

const honestProofs = INCOMING.map((c) => generateMerkleProof(c, com2.rawLeaves, com2.tree).proofBytes);

describe('ACTION 0 Merkle verifier', () => {
  it('V0 CONTROL: the honest five-proof answer (3 hits) is accepted', () => {
    const { tx, inputs } = turnTx({ proofs: honestProofs, claimedP1Hits: 3 });
    const signed = reduceAndSign(tx, inputs, p2Secret, H);
    expect(JSON.parse(signed.outputs().get(0).to_json()).ergoTree).toBe(getBattleshipsErgoTree().toHex());
  });

  it('V1 REJECTED: proof for a different cell replayed against target t (path bits differ)', () => {
    const swapped = [...honestProofs];
    swapped[0] = generateMerkleProof(20, com2.rawLeaves, com2.tree).proofBytes; // water cell, wrong index
    const { tx, inputs } = turnTx({ proofs: swapped, claimedP1Hits: 2 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V2 REJECTED: the fifth proof duplicated from the fourth', () => {
    const dup = [...honestProofs];
    dup[4] = dup[3];
    const { tx, inputs } = turnTx({ proofs: dup, claimedP1Hits: 3 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V3 REJECTED: leaf state byte flipped from ship to water', () => {
    const forged = honestProofs.map((p) => new Uint8Array(p));
    forged[0][0] = 0; // claim the carrier cell is water
    const { tx, inputs } = turnTx({ proofs: forged, claimedP1Hits: 2 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V4 REJECTED: valid 224-byte proof padded to 256 bytes (pr.size == 224 guard)', () => {
    const padded = honestProofs.map((p) => { const q = new Uint8Array(256); q.set(p, 0); return q; });
    const { tx, inputs } = turnTx({ proofs: padded, claimedP1Hits: 3 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V5 REJECTED: level-1 internal node presented as the 32-byte leaf preimage', () => {
    // Shift the proof up one level: preimage = level-1 node for the cell, then the level 1..5
    // siblings, padded. The fold always runs six levels, so the recomputed root cannot match.
    const forged = honestProofs.map((p) => new Uint8Array(p));
    const cell = INCOMING[0];
    const node1 = com2.tree[1][Math.floor(cell / 2)];
    const q = new Uint8Array(224);
    q.set(node1, 0);
    for (let lvl = 1; lvl < 6; lvl++) {
      q.set(forged[0].slice(32 + lvl * 32, 64 + lvl * 32), 32 + (lvl - 1) * 32);
    }
    forged[0] = q;
    const { tx, inputs } = turnTx({ proofs: forged, claimedP1Hits: 3 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V6 REJECTED: honest proofs but the score under-reported (validHits equality)', () => {
    const { tx, inputs } = turnTx({ proofs: honestProofs, claimedP1Hits: 0 });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V7 REJECTED: firing a four-cell salvo mid-game to shrink the next proof burden', () => {
    const { tx, inputs } = turnTx({ proofs: honestProofs, claimedP1Hits: 3, salvo: [0, 1, 2, 3] });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('V8 REJECTED: out-of-range target 64 in the outgoing salvo', () => {
    const { tx, inputs } = turnTx({ proofs: honestProofs, claimedP1Hits: 3, salvo: [0, 1, 2, 3, 64] });
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false|out of bounds|index/i);
  });
});

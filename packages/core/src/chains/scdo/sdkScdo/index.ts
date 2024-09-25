import RLP from 'rlp';
import { keccak256 } from 'viem';

import bufferUtils from '@onekeyhq/shared/src/utils/bufferUtils';
import hexUtils from '@onekeyhq/shared/src/utils/hexUtils';

import { secp256k1 } from '../../../secret';

export function publicKeyToAddress(publicKey: Buffer) {
  let publicKeyBytes = Buffer.alloc(0);
  if (publicKey.length === 33) {
    publicKeyBytes = secp256k1.transformPublicKey(publicKey).subarray(1);
  } else if (publicKey.length === 65) {
    publicKeyBytes = publicKey.subarray(1);
  } else {
    throw new Error('Invalid public key');
  }
  const shard = 1;
  const pubkey = RLP.encode(publicKeyBytes);
  const pubkeyHash = bufferUtils.hexToBytes(
    hexUtils.stripHexPrefix(keccak256(pubkey)),
  );
  const addr = pubkeyHash.slice(-20);
  addr[0] = shard;
  // eslint-disable-next-line no-bitwise
  addr[19] = (addr[19] & 0xf0) | 1;
  return `${shard}S${bufferUtils.bytesToHex(addr)}`;
}

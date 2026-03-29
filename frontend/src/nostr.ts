import { hexToBytes } from '@noble/hashes/utils';

export function toBech32(hrp: string, hexStr: string): string {
	const words = convertBits(hexToBytes(hexStr), 8, 5, true);
	return bech32Encode(hrp, words);
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
	let acc = 0, bits = 0;
	const maxv = (1 << toBits) - 1;
	const ret: number[] = [];
	for (const val of data) {
		acc = (acc << fromBits) | val;
		bits += fromBits;
		while (bits >= toBits) {
			bits -= toBits;
			ret.push((acc >> bits) & maxv);
		}
	}
	if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
	return ret;
}

function bech32Encode(hrp: string, data: number[]): string {
	const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
	const values: number[] = [];
	for (const c of hrp) values.push(c.charCodeAt(0) >> 5);
	values.push(0);
	for (const c of hrp) values.push(c.charCodeAt(0) & 31);
	values.push(...data, 0, 0, 0, 0, 0, 0);

	let polymod = 1;
	const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	for (const v of values) {
		const b = polymod >> 25;
		polymod = ((polymod & 0x1ffffff) << 5) ^ v;
		for (let i = 0; i < 5; i++) {
			if ((b >> i) & 1) polymod ^= GEN[i];
		}
	}
	polymod ^= 1;

	const checksum: number[] = [];
	for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);

	return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

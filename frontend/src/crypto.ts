import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1.js';

const NONCE_STORE = 'splitsig_nonces';
const KEY_STORE = 'splitsig_keys';

export function generateNonce(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return bytesToHex(bytes);
}

export function getOrCreateNonce(contextId: string): string {
	try {
		const nonces = JSON.parse(localStorage.getItem(NONCE_STORE) || '{}');
		if (nonces[contextId]) return nonces[contextId];
		const nonce = generateNonce();
		nonces[contextId] = nonce;
		localStorage.setItem(NONCE_STORE, JSON.stringify(nonces));
		return nonce;
	} catch {
		throw new Error('localStorage unavailable — cannot persist nonce');
	}
}

export function getNonce(contextId: string): string | null {
	try {
		const nonces = JSON.parse(localStorage.getItem(NONCE_STORE) || '{}');
		return nonces[contextId] || null;
	} catch {
		return null;
	}
}

export interface NostrKey {
	nsec: string; // 32-byte hex
	npub: string; // 32-byte x-only hex
}

export function deriveNostrKey(sigHex: string, nonceHex: string, contextId: string): NostrKey {
	const sigBytes = hexToBytes(sigHex);
	const nonceBytes = hexToBytes(nonceHex);
	const nsec = bytesToHex(sha256(concatBytes(sigBytes, nonceBytes)));
	const npub = bytesToHex(schnorr.getPublicKey(hexToBytes(nsec)));

	try {
		const keys = JSON.parse(localStorage.getItem(KEY_STORE) || '{}');
		keys[contextId] = nsec;
		localStorage.setItem(KEY_STORE, JSON.stringify(keys));
	} catch { /* ignore */ }

	return { nsec, npub };
}

export function getStoredNsec(contextId: string): string | null {
	try {
		const keys = JSON.parse(localStorage.getItem(KEY_STORE) || '{}');
		return keys[contextId] || null;
	} catch {
		return null;
	}
}

export function clearStoredKeys(): void {
	try {
		localStorage.removeItem(KEY_STORE);
		localStorage.removeItem(NONCE_STORE);
	} catch { /* ignore */ }
}

export function importNonce(contextId: string, nonce: string): void {
	try {
		const nonces = JSON.parse(localStorage.getItem(NONCE_STORE) || '{}');
		nonces[contextId] = nonce;
		localStorage.setItem(NONCE_STORE, JSON.stringify(nonces));
	} catch {
		throw new Error('Failed to import nonce to localStorage');
	}
}

export { bytesToHex, hexToBytes, schnorr };

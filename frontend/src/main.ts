import { api } from './api';
import { getOrCreateNonce, getNonce, deriveNostrKey, getStoredNsec, clearStoredKeys, importNonce, schnorr, bytesToHex, hexToBytes } from './crypto';
import { toBech32 } from './nostr';

let npub = '';
let nsec = '';
let linkingPubKey = '';
let pollTimer: ReturnType<typeof setInterval> | null = null;

const $ = (id: string) => document.getElementById(id)!;
const show = (id: string) => $(id).classList.remove('hidden');
const hide = (id: string) => $(id).classList.add('hidden');

document.addEventListener('DOMContentLoaded', () => {
	const stored = getStoredNsec('nostr');
	if (stored) {
		nsec = stored;
		npub = bytesToHex(schnorr.getPublicKey(hexToBytes(nsec)));
		showSignedIn();
	}

	$('btn-signin').addEventListener('click', startAuth);
	$('btn-signout').addEventListener('click', () => show('signout-confirm'));
	$('btn-signout-confirm').addEventListener('click', signOut);
	$('btn-signout-cancel').addEventListener('click', () => hide('signout-confirm'));
	$('btn-download-kit').addEventListener('click', downloadRecoveryKit);
	$('btn-copy-npub').addEventListener('click', () => copyText(toBech32('npub', npub), 'btn-copy-npub'));
	$('btn-copy-nsec').addEventListener('click', () => copyText(toBech32('nsec', nsec), 'btn-copy-nsec'));
	$('btn-toggle-nsec').addEventListener('click', toggleNsec);
	$('btn-import-kit').addEventListener('click', () => ($('kit-file-input') as HTMLInputElement).click());
	($('kit-file-input') as HTMLInputElement).addEventListener('change', handleKitImport);

	if (getNonce('nostr')) {
		$('kit-status').textContent = 'Recovery kit loaded';
		$('kit-status').classList.add('success');
	}
});

async function startAuth() {
	try {
		const ch = await api.challenge('nostr');

		($('qr-img') as HTMLImageElement).src =
			`https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(ch.qr_content)}`;
		hide('landing');
		show('auth-screen');

		$('btn-test-login').onclick = async () => {
			try {
				const res = await api.testAuth(ch.k1);
				if (pollTimer) clearInterval(pollTimer);
				pollTimer = null;
				onAuthenticated(res.signature, res.pubkey);
			} catch (e: any) {
				$('auth-error').textContent = e.message;
			}
		};

		$('btn-cancel-auth').onclick = () => {
			if (pollTimer) clearInterval(pollTimer);
			pollTimer = null;
			hide('auth-screen');
			show('landing');
		};

		pollTimer = setInterval(async () => {
			try {
				const status = await api.status(ch.challenge_id);
				if (status.verified && status.signature) {
					clearInterval(pollTimer!);
					pollTimer = null;
					onAuthenticated(status.signature, status.linking_pubkey!);
				}
			} catch { /* keep polling */ }
		}, 2000);

	} catch (e: any) {
		$('auth-error').textContent = e.message;
	}
}

function onAuthenticated(signature: string, pubkey: string) {
	linkingPubKey = pubkey;
	const nonce = getOrCreateNonce('nostr');
	const key = deriveNostrKey(signature, nonce, 'nostr');
	nsec = key.nsec;
	npub = key.npub;
	showSignedIn();
}

function showSignedIn() {
	hide('landing');
	hide('auth-screen');
	show('signed-in');
	$('display-npub').textContent = toBech32('npub', npub);
	$('display-nsec').textContent = '****';
	($('display-nsec') as any)._revealed = false;
}

function signOut() {
	nsec = '';
	npub = '';
	linkingPubKey = '';
	clearStoredKeys();
	hide('signout-confirm');
	hide('signed-in');
	show('landing');
	$('kit-status').textContent = '';
	$('kit-status').classList.remove('success');
}

function toggleNsec() {
	const el = $('display-nsec');
	if ((el as any)._revealed) {
		el.textContent = '****';
		(el as any)._revealed = false;
		$('btn-toggle-nsec').textContent = 'Reveal';
	} else {
		el.textContent = toBech32('nsec', nsec);
		(el as any)._revealed = true;
		$('btn-toggle-nsec').textContent = 'Hide';
	}
}

function downloadRecoveryKit() {
	const nonce = getNonce('nostr');
	if (!nonce) {
		alert('Nonce not found');
		return;
	}
	const kit = {
		splitsig_version: 1,
		nonce,
		auth_domain: window.location.hostname,
		context_identifier: 'nostr',
		linking_pubkey: linkingPubKey,
	};
	const blob = new Blob([JSON.stringify(kit, null, 2)], { type: 'application/json' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = 'splitsig-recovery-kit.json';
	a.click();
	URL.revokeObjectURL(url);
}

function handleKitImport(e: Event) {
	const file = (e.target as HTMLInputElement).files?.[0];
	if (!file) return;

	const reader = new FileReader();
	reader.onload = () => {
		try {
			const kit = JSON.parse(reader.result as string);
			if (!kit.nonce || typeof kit.nonce !== 'string' || kit.nonce.length !== 64) {
				$('kit-status').textContent = 'Invalid kit: missing or bad nonce';
				$('kit-status').classList.remove('success');
				return;
			}
			importNonce(kit.context_identifier || 'nostr', kit.nonce);
			$('kit-status').textContent = 'Recovery kit loaded — sign in to restore your identity';
			$('kit-status').classList.add('success');
		} catch {
			$('kit-status').textContent = 'Invalid recovery kit file';
			$('kit-status').classList.remove('success');
		}
	};
	reader.readAsText(file);
}

function copyText(text: string, btnId: string) {
	navigator.clipboard.writeText(text).then(() => {
		const btn = $(btnId);
		const orig = btn.textContent;
		btn.textContent = 'Copied!';
		setTimeout(() => { btn.textContent = orig; }, 1500);
	}).catch(() => {});
}

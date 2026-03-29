export interface ChallengeResponse {
	challenge_id: string;
	k1: string;
	qr_content: string;
}

export interface StatusResponse {
	verified: boolean;
	linking_pubkey?: string;
	signature?: string;
	session_token?: string;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const opts: RequestInit = { method };
	if (body !== undefined) {
		opts.headers = { 'Content-Type': 'application/json' };
		opts.body = JSON.stringify(body);
	}
	const res = await fetch(path, opts);
	const data = await res.json();
	if (!res.ok) throw new Error(data.error || res.statusText);
	return data as T;
}

export const api = {
	challenge(context = 'nostr') {
		return request<ChallengeResponse>('GET', `/auth/challenge?context=${encodeURIComponent(context)}`);
	},
	status(challengeId: string) {
		return request<StatusResponse>('GET', `/auth/status/${challengeId}`);
	},
	testAuth(k1: string) {
		return request<{ status: string; pubkey: string; signature: string }>('POST', '/test/auth', { k1 });
	},
};

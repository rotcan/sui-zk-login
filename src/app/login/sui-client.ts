// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { API_ENV, ENV_TO_API, type NetworkEnvType } from './api-env';
import { SentryHttpTransport } from './SentryHttpTransport';
import { SuiClient, SuiHTTPTransport } from '@mysten/sui.js/client';
import networkEnv from './NetworkEnv';

const suiClientPerNetwork = new Map<string, SuiClient>();
const SENTRY_MONITORED_ENVS = [API_ENV.mainnet,API_ENV.devNet];

export function getSuiClient({ env, customRpcUrl }: NetworkEnvType): SuiClient {
	const key = `${env}_${customRpcUrl}`;
    console.log("key",key,suiClientPerNetwork);
	if (!suiClientPerNetwork.has(key)) {
		const connection = customRpcUrl ? customRpcUrl : ENV_TO_API[env];
        if (!connection) {
			throw new Error(`API url not found for network env ${env} ${customRpcUrl}`);
		}
		suiClientPerNetwork.set(
			key,
			new SuiClient({
				transport:
					!customRpcUrl && SENTRY_MONITORED_ENVS.includes(env)
						? new SentryHttpTransport(connection)
						: new SuiHTTPTransport({ url: connection }),
			}),
		);
	}
	return suiClientPerNetwork.get(key)!;
}

export async function getActiveNetworkSuiClient(): Promise<SuiClient> {
	return getSuiClient(await networkEnv.getActiveNetwork());
}
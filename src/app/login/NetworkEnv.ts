// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
'use client';
import { API_ENV, type NetworkEnvType } from './api-env';
import mitt from 'mitt';
// import Browser from 'webextension-polyfill';
// var Browser = require("webextension-polyfill");

console.log(" process.env.NEXT_API_ENV", process.env.NEXT_PUBLIC_API_ENV);
function getDefaultApiEnv() {
	const apiEnv = process.env.NEXT_PUBLIC_API_ENV;
	if (apiEnv && !Object.keys(API_ENV).includes(apiEnv)) {
		throw new Error(`Unknown environment variable API_ENV, ${apiEnv}`);
	}
	return apiEnv ? API_ENV[apiEnv as keyof typeof API_ENV] : API_ENV.devNet;
}

export const DEFAULT_API_ENV = getDefaultApiEnv();
console.log("DEFAULT_API_ENV",DEFAULT_API_ENV);
export function isValidUrl(url: string | null) {
	if (!url) {
		return false;
	}
	try {
		new URL(url);
		return true;
	} catch (e) {
		return false;
	}
}



class NetworkEnv {
	#events = mitt<{ changed: NetworkEnvType }>();
    async getActiveNetwork(): Promise<NetworkEnvType> {
        const sui_Env = localStorage.getItem("env") ?  localStorage.getItem("env")  as API_ENV : DEFAULT_API_ENV;
        const sui_Env_RPC=localStorage.getItem("rpc") ?? null;
		const adjCustomUrl = sui_Env === API_ENV.customRPC ? sui_Env_RPC : null;
        if(adjCustomUrl)
		    return { env: API_ENV.customRPC, customRpcUrl: adjCustomUrl };
        return {env: sui_Env as Exclude<API_ENV, API_ENV.customRPC>,customRpcUrl: null  };
	}

	async setActiveNetwork(network: NetworkEnvType) {
		const { env, customRpcUrl } = network;
		if (env === API_ENV.customRPC && !isValidUrl(customRpcUrl)) {
			throw new Error(`Invalid custom RPC url ${customRpcUrl}`);
		}
        localStorage.setItem("env",env);
        localStorage.setItem("rpc",customRpcUrl!);
		this.#events.emit('changed', network);
	}

	on = this.#events.on;

	off = this.#events.off;
}

const networkEnv = new NetworkEnv();
export default networkEnv;
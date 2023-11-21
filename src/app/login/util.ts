import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui.js/keypairs/ed25519';

import { generateNonce, generateRandomness } from '@mysten/zklogin';
import { getActiveNetworkSuiClient } from './sui-client';
import { Buffer } from "buffer";
import { poseidonHash } from './poseiden';
import { hexToBytes } from '@noble/hashes/utils';
import { base64url } from 'jose';
import { fromB64 } from '@mysten/bcs';
import { EPH_KEY, EPOCH_KEY, JWT_KEY, NONCE_KEY, RANDOMNESS_KEY } from './page';


const CLIENT_ID=process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!;
export const REDIRECT_URL = 'http://localhost:3000/login';

export const getSuiBalance=async(account: string):Promise<string>=>{
    const suiClient = await getActiveNetworkSuiClient();
    console.log("account",account);
    const balances=await suiClient.getAllBalances({owner: account});
    const suiBalance=balances.filter(m=>m.coinType==="0x2::sui::SUI");
    if(suiBalance.length>0){
        return suiBalance[0].totalBalance;
    }
    return "0";
}
export const getEphPublicKey=(clearOldValue?: boolean)=>{
    if(!localStorage.getItem(EPH_KEY) || clearOldValue===true)
    {
        localStorage.setItem(EPH_KEY,new Ed25519Keypair().export().privateKey);    
    }
    const secretKey=localStorage.getItem(EPH_KEY)!;
    return Ed25519Keypair.fromSecretKey(fromB64(secretKey)).getPublicKey().toBase64();
    
}

const getRandomness=(clearOldValue? : boolean):bigint=>{
    if(!localStorage.getItem(RANDOMNESS_KEY) || clearOldValue===true)
    {
        const r=generateRandomness().toString();
        localStorage.setItem(RANDOMNESS_KEY, r);
    }    
    return BigInt(localStorage.getItem(RANDOMNESS_KEY)!);
}

const getEpoch=async():Promise<number>=>{
    const suiClient = await getActiveNetworkSuiClient();
    const { epoch } = await suiClient.getLatestSuiSystemState();
    if(!localStorage.getItem(EPOCH_KEY) || parseInt(localStorage.getItem(EPOCH_KEY)!)<
    (+epoch + 2)){
        localStorage.setItem(EPOCH_KEY, (+epoch + 2).toString() );
        //clear randomness and eph key
        getRandomness(true);
        getEphPublicKey(true);
        localStorage.removeItem(JWT_KEY)
        localStorage.removeItem(NONCE_KEY);
    }
    return parseInt(localStorage.getItem(EPOCH_KEY)!);
}

const getNonce=async()=>{
    // const suiClient = await getActiveNetworkSuiClient();
    // const { epoch, epochDurationMs, epochStartTimestampMs } = await suiClient.getLatestSuiSystemState();

    // const maxEpoch =localStorage.getItem("epoch") ? parseInt(localStorage.getItem("epoch")!) : +epoch + 2; // this means the ephemeral key will be active for 2 epochs from now.
    // localStorage.setItem("epoch",maxEpoch.toString());
    const maxEpoch=await getEpoch();
    // const ephemeralKeyPair = new Ed25519Keypair();
    const pubkey=getEphPublicKey();
    
    const randomness =getRandomness();
    if(!localStorage.getItem(NONCE_KEY)){
        const nonce = generateNonce(new Ed25519PublicKey(pubkey), maxEpoch, randomness);
        console.log("ephemeralKeyPair.getPublicKey()",pubkey);
        console.log("maxEpoch",maxEpoch);
        console.log("randomness",randomness);
        localStorage.setItem(NONCE_KEY,nonce);
    }
    return localStorage.getItem(NONCE_KEY)!;
}

export const getNonceFromValues=(pubkey: string, maxEpoch: string, randomness: string)=>{
    const nonce = generateNonce(new Ed25519PublicKey(pubkey), parseInt(maxEpoch), BigInt(randomness));
    return nonce;

}

// const getOAuthUrl=async()=>{
//     const nonce=await getNonce();
//     const url=`https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&response_type=id_token&redirect_uri=${REDIRECT_URL}&scope=openid&nonce=${nonce}`;


// }



 
export const loginURL =async ()=>{

    const nonce=await getNonce();
    
    console.log("nonce",nonce);
    const params = new URLSearchParams({
        // When using the provided test client ID + redirect site, the redirect_uri needs to be provided in the state.
        state: new URLSearchParams({
           redirect_uri: REDIRECT_URL
        }).toString(),
        // Test Client ID for devnet / testnet:
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URL,
        response_type: 'id_token',
        scope: 'openid',
        // See below for details about generation of the nonce
        nonce: nonce,
     });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
 } ;

export const getGoogleJWT=async(idToken: string):Promise<any>=>{
    const url=`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`;
    const result=await fetch(url);
    const json=await result.json()
    //console.log("result", json);
    return json;
}

const decode = (str: string):string => Buffer.from(str, 'base64').toString('binary');

export const parseJWS=async(idToken: string)=>{
    const data=idToken.split(".");
    const joseHeader=decode(data[0]);
    const payload=decode(data[1]);
    const signature=decode(data[2]);
    console.log("joseHeader",joseHeader,"payload",payload,"signature",signature);
    return undefined;
}

export const getKeyParts=(keyStr: string,epoch: string, randomness: string)=>{
    const key=new Ed25519PublicKey(keyStr);
    const publicKeyBytes= toBigIntBE(key.toSuiBytes());
    console.log("publicKeyBytes",key.toSuiBytes(),publicKeyBytes);
    console.log("Bigint test",BigInt("0x12321afde23"));
    const eph_public_key_0 = publicKeyBytes / 2n ** 128n;
	const eph_public_key_1 = publicKeyBytes % 2n ** 128n;
    console.log("eph_public_key_0",eph_public_key_0);
    console.log("eph_public_key_1",eph_public_key_1);
    const hash=poseidonHash([eph_public_key_0,eph_public_key_1,epoch,randomness]);
    const Z=toBigEndianBytes(hash,20);
    console.log("Z",Z);
    convertStrToBigInt('"iss":"https://accounts.google.com"');
    console.log("test string",BigInt("0x"+"2B6D915C2D39A8F14CCCBE9340F02CB1F87597A1FC77F06F9D2172DE1E7AE4A5"))
    console.log("phash",poseidonHash(["34140318743088489","140307608250876946713912415302722131415556694541956166611896162452242575972","203810812921613846319060315810887187786414195542245808560141018835141525504","0","0","0","0","0"]));
    const b64_hash=base64url.encode(Z);
    console.log("hash",hash,b64_hash);
}

export function toBigIntBE(bytes: Uint8Array) {
	const hex = toHEX(bytes);
	if (hex.length === 0) {
		return BigInt(0);
	}
	return BigInt(`0x${hex}`);
}

export function toHEX(bytes: Uint8Array): string {
	return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}



function findFirstNonZeroIndex(bytes: Uint8Array) {
	for (let i = 0; i < bytes.length; i++) {
		if (bytes[i] !== 0) {
			return i;
		}
	}

	return -1;
}

export function toBigEndianBytes(num: bigint, width: number): Uint8Array {
	const hex = num.toString(16);
    console.log("hex",hex);
	const bytes = hexToBytes(hex.padStart(width * 2, '0').slice(-width * 2));

	const firstNonZeroIndex = findFirstNonZeroIndex(bytes);

	if (firstNonZeroIndex === -1) {
		return new Uint8Array([0]);
	}
    console.log("toBigEndianBytes",bytes);
	return bytes.slice(firstNonZeroIndex);
}

const convertStrToBigInt=(s: string)=>{
    var hexString = "";

    for (var i = 0; i < s.length; i++) {
        hexString += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
    }
    console.log("convertStrToBigInt",s,BigInt("0x"+hexString));
}
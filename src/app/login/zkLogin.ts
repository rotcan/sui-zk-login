import { getZkLoginSignature,jwtToAddress,genAddressSeed } from '@mysten/zklogin';

import { getBigNumber, getJWTAudSub, getPaddedBase64Ascii } from './zk';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui.js/keypairs/ed25519';
import { SuiClient } from '@mysten/sui.js/client';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { SerializedSignature } from '@mysten/sui.js/cryptography';
import {bcs, fromB64} from '@mysten/bcs';
import { toBigIntBE } from './util';
import { EPH_KEY, SPONSOR_KEY } from './page';


export interface ZKProofRequest{
    jwt: string;
    randomness: string;
    key: string;
    epoch: string;
    salt: string;
}

export const zkLoginSignature = bcs.struct('ZkLoginSignature', {
	inputs: bcs.struct('ZkLoginSignatureInputs', {
		proofPoints: bcs.struct('ZkLoginSignatureInputsProofPoints', {
			a: bcs.vector(bcs.string()),
			b: bcs.vector(bcs.vector(bcs.string())),
			c: bcs.vector(bcs.string()),
		}),
		issBase64Details: bcs.struct('ZkLoginSignatureInputsClaim', {
			value: bcs.string(),
			indexMod4: bcs.u8(),
		}),
		headerBase64: bcs.string(),
		addressSeed: bcs.string(),
	}),
	maxEpoch: bcs.u64(),
	userSignature: bcs.vector(bcs.u8()),
});

export type PartialZkLoginSignature = Omit<
    Parameters<typeof getZkLoginSignature>['0']['inputs'],
    'addressSeed'
>;

const getKeyParts=(keyStr: string)=>{
    const key=new Ed25519PublicKey(keyStr);
    const publicKeyBytes= toBigIntBE(key.toSuiBytes());
    const eph_public_key_0 = publicKeyBytes / 2n ** 128n;
	const eph_public_key_1 = publicKeyBytes % 2n ** 128n;
    return {eph_public_key_0,eph_public_key_1};
}
export const getAndProcessProof=async({epoch,jwt,keyStr,randomness,saltBase64,rpc}:
    {jwt:string,epoch:string,keyStr:string,randomness:string,saltBase64:string,rpc: string,}):Promise<string|undefined>=>{
    const url="http://localhost:8080/get-zk-proof";
    console.log("getting and processing proof",jwt);
    console.log("key",getKeyParts(keyStr));
    const response=await fetch(url,{method: 'POST',headers:new Headers({
        'Content-Type':'application/json'
    }), body:JSON.stringify({
        epoch,jwt,key: keyStr,randomness,salt:saltBase64
    } as ZKProofRequest)});
    const json=await response.json();
    console.log("json",json);
    const {aud,sub}=getJWTAudSub({jwt})
    const result=await processProof({aud,jwt,maxEpoch:epoch,proofResponse:json,rpcUrl:rpc,
    saltBase64,sub});
    if(result){
        console.log("result",result);
        return result.digest;
    }
    return undefined;
}

export const getSenderAddress=({jwt,saltBase64}:{jwt: string,saltBase64: string}): string=>{
    const saltBN=getBigNumber(getPaddedBase64Ascii({base64:saltBase64,length:saltBase64.length,paddingValue:0}))
    const zkLoginUserAddress = jwtToAddress(jwt, saltBN.valueOf());
    return zkLoginUserAddress;
}

export const processProof=async({aud,jwt,maxEpoch,proofResponse,saltBase64,sub,rpcUrl}:
    {proofResponse:any,jwt: string,saltBase64: string,sub: string,aud:string,maxEpoch: string,rpcUrl: string})=>{
    const saltBN=getBigNumber(getPaddedBase64Ascii({base64:saltBase64,length:saltBase64.length,paddingValue:0}))
    const zkLoginUserAddress = jwtToAddress(jwt, saltBN.valueOf());
    const partialZkLoginSignature = {proofPoints:{
        a: proofResponse.proof.pi_a,
        b: proofResponse.proof.pi_b,
        c: proofResponse.proof.pi_c,
    },headerBase64: proofResponse.suiFields.headerBase64,issBase64Details:proofResponse.suiFields.issBase64Details} as PartialZkLoginSignature;
    console.log("partialZkLoginSignature",partialZkLoginSignature,proofResponse);
    //const feePayerPK="HEff2nttXMg5uHyWItotPFIGukKdVCJTy5pqLYn5Wzg="//process.env.SPONSOR_PRIVATE_KEY!;
    const sponsor= Ed25519Keypair.fromSecretKey(fromB64(localStorage.getItem(SPONSOR_KEY)!));
    const ephemeralKeyPair =  Ed25519Keypair.fromSecretKey(fromB64(localStorage.getItem(EPH_KEY)!));
    console.log("sponsor",sponsor.getPublicKey().toSuiAddress());
    console.log("ephemeralKeyPair",ephemeralKeyPair.getPublicKey().toSuiAddress());;
    
    const client = new SuiClient({ url: rpcUrl });
    
    const txb = new TransactionBlock();
    
    txb.setSender(zkLoginUserAddress);
    txb.setGasOwner(sponsor.getPublicKey().toSuiAddress());

    
    const txBytes=await txb.build({client});
    const {bytes: _t1, signature: userSignature}=await ephemeralKeyPair.signTransactionBlock(txBytes);
    const {bytes: _t2, signature: sponsorSignature}=await sponsor.signTransactionBlock(txBytes);
    
    
    const addressSeed : string = genAddressSeed(saltBN.valueOf(), "sub", sub, aud).toString();
    const zkLoginSignature : SerializedSignature = getZkLoginSignature({
    inputs: {
        ...partialZkLoginSignature,
        addressSeed
    },
    maxEpoch,
    userSignature: userSignature,
    });

    const response=await client.executeTransactionBlock({
        signature:[sponsorSignature,zkLoginSignature],
        transactionBlock: txBytes,
    })
    return response;
}
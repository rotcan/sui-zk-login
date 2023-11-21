import { Ed25519PublicKey } from '@mysten/sui.js/keypairs/ed25519';
import { JWTPayload, decodeJwt } from 'jose';
import { poseidonHash } from './poseidon';
import axios from 'axios';
//@ts-ignore
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import { findZKFile } from '../helper';
import { zkeyPath } from '../app';

interface GoogleJWTHeader{
    alg: string;
    kid: string;
    typ: string;
}

interface GoogleJWTPublicKeyData{
    kty: string;
    alg: string;
    kid: string;
    use: string;
    e: string;
    n: string;
}

interface ZKLoginInput{
    padded_unsigned_jwt: string[];
    payload_len: string;
    num_sha2_blocks: string;
    payload_start_index: string;
    modulus: string[];
    signature: string[];
    ext_kc: string[];
    ext_kc_length: string;
    kc_index_b64: string;
    kc_length_b64: string;
    kc_name_length: string;
    kc_colon_index: string;
    kc_value_index: string;
    kc_value_length: string;
    ext_nonce: string[];
    ext_nonce_length: string;
    nonce_index_b64: string;
    nonce_length_b64: string;
    nonce_colon_index: string;
    nonce_value_index: string;
    ext_ev: string[];
    ext_ev_length: string;
    ev_index_b64: string;
    ev_length_b64: string;
    ev_name_length: string;
    ev_colon_index: string;
    ev_value_index: string;
    ev_value_length: string;
    ext_aud: string[];
    ext_aud_length: string;
    aud_index_b64: string;
    aud_length_b64: string;
    aud_colon_index: string;
    aud_value_index: string;
    aud_value_length: string;
    iss_index_b64: string;
    iss_length_b64: string;
    eph_public_key: string[];
    max_epoch: string;
    jwt_randomness: string;
    salt: string;
    all_inputs_hash: string;
}

interface SuiProofFields{
    issBase64Details:{
        value: string,
        indexMod4: number,
    };
    headerBase64: string;
}

export interface ZKProofRequest{
    jwt: string;
    randomness: string;
    key: string;
    epoch: string;
    salt: string;
}

export const generateZKInput=async({jwt,salt,epoch,keyStr,randomness}:{jwt: string,salt: string,
    keyStr: string,epoch: string, randomness: string}):Promise<{inputs:ZKLoginInput,suiFields: SuiProofFields}>=>{
    const {header,payload,signature}=parseJWT({jwt});
    const headerBase64=jwt.split('.')[0];
    const payloadBase64=jwt.split('.')[1];
    const signatureBase64=jwt.split('.')[2];
    const payloadStr=decodeBase64(payloadBase64);
    const modulus=await getModulus({header});
    const modulusBN=getBigNumber(decodeBase64Url(modulus));
    const signatureBN=getBigNumber(decodeBase64Url(signatureBase64));
    const modulusZK: string[]=getLimbs({base:64 ,num: BigInt( modulusBN.toString()) });
    const signatureZK=getLimbs({base:64 ,num: BigInt( signatureBN.toString()) });
    const subPadLength=126;
    const noncePadLength=44;
    const extEvLength=53;
    const extAudLength=160;

    const issPaddingLength=224;
    const kcNameLength=32;
    const kcValueLength=115;
    const audValueLength=145;
    const maxHeaderLen=248;
    const paddedUnsignedJWTLength=1600;

    const {numSha2Blocks,paddedUnsignedJwt,
    payloadLen,payloadStartIndex}=getUnsignedPaddedJWT({jwt,length: paddedUnsignedJWTLength, paddingValue:0});
    const {asciiArrayLength: ext_kc_length,asciiVal:ext_kc,b64Index:kc_index_b64,
    b64Size:kc_length_b64,colonIndex:kc_colon_index,nameLength:kc_name_length,
    valueIndex:kc_value_index,valueLength:kc_value_length}=getExtKCFields({jwt,len:subPadLength,name:"sub",payload:payloadStr,excludeEndComma: false});
    const {asciiArrayLength: ext_nonce_length,asciiVal:ext_nonce,b64Index:nonce_index_b64,
        b64Size:nonce_length_b64,colonIndex:nonce_colon_index,nameLength:nonce_name_length,
        valueIndex:nonce_value_index,valueLength:nonce_value_length, value: nonce}=getExtKCFields({jwt,len:noncePadLength,name:"nonce",payload:payloadStr,excludeEndComma: false});
    const {asciiArrayLength: ext_ev_length,asciiVal:ext_ev,b64Index:ev_index_b64,
        b64Size:ev_length_b64,colonIndex:ev_colon_index,nameLength:ev_name_length,
        valueIndex:ev_value_index,valueLength:ev_value_length}=getExtKCFields({jwt,len:extEvLength,name:"nonce",payload:payloadStr,excludeEndComma: false});
    const {asciiArrayLength: ext_aud_length,asciiVal:ext_aud,b64Index:aud_index_b64,
        b64Size:aud_length_b64,colonIndex:aud_colon_index,nameLength:aud_name_length,
        valueIndex:aud_value_index,valueLength:aud_value_length}=getExtKCFields({jwt,len:extAudLength,name:"aud",payload:payloadStr,excludeEndComma: false});
    const {b64Index:iss_index_b64_t,
        b64Size:iss_length_b64_t}=getExtKCFields({jwt,len:extAudLength,name:"iss",payload:payloadStr,excludeEndComma: false});
    // console.log("original iss_length_b64_t",iss_length_b64_t);
    const iss_index_b64=iss_index_b64_t;
    const iss_length_b64=iss_length_b64_t;
    const key=new Ed25519PublicKey(keyStr);
    const publicKeyBytes= toBigIntBE(key.toSuiBytes());
    const eph_public_key_0 = publicKeyBytes / 2n ** 128n;
	const eph_public_key_1 = publicKeyBytes % 2n ** 128n;
    // console.log("nonce",nonce,getPoseidonHash({fields:[eph_public_key_0.toString(),eph_public_key_1.toString(),
    // epoch,randomness]}));
    // console.log("eph_public_key_0",eph_public_key_0);
    // console.log("eph_public_key_1",eph_public_key_1);
    const issBase64=jwt.substring(iss_index_b64,iss_index_b64+iss_length_b64);
    const issFieldF=getPoseidonHash({fields:hashStringToField({paddingLength:issPaddingLength,inBase:8,outBase:248,value:issBase64})});
    // console.log("ext_kc_length",ext_kc_length,"ext_kc",ext_kc ,"kc_index_b64",
    // kc_index_b64,"kc_length_b64",kc_length_b64,"kc_colon_index",kc_colon_index,"kc_name_length",kc_name_length,
    //     "kc_value_index",kc_value_index,"kc_value_length",kc_value_length);
    const kcNameF=getPoseidonHash({fields:hashStringToField({paddingLength:kcNameLength,inBase:8,outBase:248,value:"sub"})});
    const kcValueF=getPoseidonHash({fields:hashStringToField({paddingLength:kcValueLength,inBase:8,outBase:248,value:payload.sub!})});
    const audValueF=getPoseidonHash({fields:hashStringToField({paddingLength:audValueLength,inBase:8,outBase:248,value:payload.aud! as string})});
    const headerF=getPoseidonHash({fields:hashStringToField({paddingLength:maxHeaderLen,inBase:8,outBase:248,value:headerBase64})});
    const modulusF=getPoseidonHash({fields:hashArrayToField({inBase:64,outBase:248,valueBE:modulusZK.reverse()})});
    const saltBN=getBigNumber(getPaddedBase64Ascii({base64:salt,length:salt.length,paddingValue:0}))
    const addressSeed=getAddressSeed({audValueF:audValueF.toString(),
        kcNameF:kcNameF.toString(),kcValueF:kcValueF.toString(),salt: saltBN.toString()});
    // console.log("issFieldF",issFieldF);
    // console.log("modulus_F",modulusF)
    // console.log("kcName_F",kcNameF)
    // console.log("kcValue_F",kcValueF)
    // console.log("headerBase64",headerBase64.length);
    // console.log("iss_index_mod4",iss_index_b64%(headerBase64.length+1));
    // console.log("headerF",headerF);
    // console.log("address Seed", addressSeed.toString(),"0x"+addressSeed.toString(16),saltBN.toString());
    const issMod4=(iss_index_b64-(headerBase64.length+1))%4;
    // console.log("decodedJWT",header,payload,signature.length,signature,modulus,modulusBN);
    const allInputsHash=getAllInputsHash({addressSeed: addressSeed.toString(),headerF: headerF.toString(),
    issFieldF: issFieldF.toString(),issIndexMod4: ""+issMod4,
    keyStr: keyStr,maxEpoch: epoch, modulusF: modulusF.toString()});
    // console.log("salt",salt);
    // console.log("allInputsHash",allInputsHash);
    // console.log("keys",eph_public_key_0.toString(),eph_public_key_1.toString());
    const inputs= {
        all_inputs_hash: allInputsHash.toString(),
        aud_colon_index:aud_colon_index.toString(),
        aud_index_b64:aud_index_b64.toString(),aud_length_b64:aud_length_b64.toString(),
        aud_value_index:aud_value_index.toString(),aud_value_length:aud_value_length.toString(),
        eph_public_key:[eph_public_key_0.toString(),eph_public_key_1.toString()],
        ev_colon_index:ev_colon_index.toString(),
        ev_index_b64:ev_index_b64.toString(),ev_length_b64:ev_length_b64.toString(),
        ev_name_length:ev_name_length.toString(),ev_value_index:ev_value_index.toString(),
        ev_value_length:ev_value_length.toString(),
        ext_aud:ext_aud.map(m=>m.toString()),
        ext_aud_length:ext_aud_length.toString(),ext_ev:ext_ev.map(m=>m.toString()),
        ext_ev_length:ext_ev_length.toString(),ext_kc:ext_kc.map(m=>m.toString()),
        ext_kc_length:ext_kc_length.toString(),ext_nonce:ext_nonce.map(m=>m.toString()),
        ext_nonce_length:ext_nonce_length.toString(),
        iss_index_b64:iss_index_b64.toString(),
        iss_length_b64:iss_length_b64.toString(),jwt_randomness: randomness,
        kc_colon_index:kc_colon_index.toString(),
        kc_index_b64:kc_index_b64.toString(),
        kc_length_b64:kc_length_b64.toString(),
        kc_name_length:kc_name_length.toString(),
        kc_value_index:kc_value_index.toString(),kc_value_length:kc_value_length.toString(),max_epoch: epoch,
        modulus: modulusZK.reverse(),
        nonce_colon_index:nonce_colon_index.toString(),
        nonce_index_b64:nonce_index_b64.toString(),
        nonce_length_b64:nonce_length_b64.toString(),nonce_value_index:nonce_value_index.toString(),
        num_sha2_blocks:numSha2Blocks.toString(),
        padded_unsigned_jwt: paddedUnsignedJwt.map(m=>m.toString()),
        payload_len: payloadLen.toString(),payload_start_index:payloadStartIndex.toString(),
        salt:saltBN.toString(),signature: signatureZK,
    } as ZKLoginInput;
    return {inputs,suiFields:{
        headerBase64,
        issBase64Details:{
            indexMod4: issMod4,
            value: issBase64
        }
    }};
}

const getAddressSeed=({audValueF,salt,kcNameF,kcValueF,}:{kcNameF: string, kcValueF: string, audValueF: string,
salt: string})=>{
    const hashedSalt=getPoseidonHash({fields:[salt]}).toString();
    return getPoseidonHash({fields:[kcNameF,kcValueF,audValueF,hashedSalt]});
}

const getAllInputsHash=({addressSeed,headerF,issFieldF,issIndexMod4,
keyStr,maxEpoch,modulusF}:{keyStr: string,addressSeed: string, maxEpoch: string,
issFieldF: string,issIndexMod4:string,headerF:string, modulusF:string})=>{
    const key=new Ed25519PublicKey(keyStr);
    const publicKeyBytes= toBigIntBE(key.toSuiBytes());
    const bytes=[];
    let tempKey=publicKeyBytes;
    while(tempKey>0){
        bytes.push(tempKey% 2n ** 8n);
        tempKey=tempKey/ 2n ** 8n;
    }
    bytes.reverse();
    // console.log("bytes ",bytes);
    const eph_public_key_0 = publicKeyBytes / 2n ** 128n;
	const eph_public_key_1 = publicKeyBytes % 2n ** 128n;
   
    // eph_public_key[0],
    //     eph_public_key[1],
    //     address_seed, //  kc_name_F, kc_value_F, aud_value_F, hashed_salt
    //     max_epoch,
    //     iss_b64_F,
    //     iss_index_in_payload_mod_4,
    //     header_F,
    //     modulus_F
    // console.log("eph_public_key_0.toString()",eph_public_key_0.toString());
    // console.log("eph_public_key_1.toString()",eph_public_key_1.toString());
    // console.log("addressSeed",addressSeed);
    // console.log("maxEpoch",maxEpoch);
    // console.log("issFieldF",issFieldF);
    // console.log("issIndexMod4",issIndexMod4);
    // console.log("headerF",headerF);
    // console.log("modulusF",modulusF);
    return getPoseidonHash({
        fields:[eph_public_key_0.toString(),eph_public_key_1.toString(),
            addressSeed,maxEpoch,issFieldF,
        issIndexMod4,headerF,modulusF]
    });
}

const getPoseidonHash=({fields}:{fields: string[]})=>{
    return poseidonHash(fields);
}

const hashStringToField=({paddingLength,value,inBase,outBase}:{value: string,paddingLength: number,inBase:number,outBase:number})=>{
    const asciiBe=getPaddedBase64Ascii({base64: value,length: paddingLength,paddingValue:0});
    asciiBe.reverse();
    return convertBase({inArrayLE: [...asciiBe].map(m=>BigInt(m)),inBase,outBase});
}

const hashArrayToField=({valueBE,inBase,outBase}:{valueBE: string[],inBase:number,outBase:number})=>{
    return convertBase({inArrayLE: [...valueBE.map(m=>BigInt(m)).reverse()],inBase,outBase});
}


const convertBase=({inArrayLE,inBase,outBase}:{inBase:number,outBase:number,inArrayLE: bigint[]})=>{
    //Convert to binary
    const binaryValue=convertArrayToBinary({valuesLE:inArrayLE.map(m=>m.toString()),inBase})
    const convertedValueLE: string[]=[];
    const chunkSize=outBase;
    // console.log("extraItemsCount",extraItemsCount);
    // Array(extraItemsCount).map(_m=>inArrayLE.push(0n));
    const chunks:string[][]=[];
    const binaryValueLE=binaryValue.split('').reverse();
    for(let i=0;i<binaryValueLE.length;i+=chunkSize){
        chunks.push(binaryValueLE.slice(i,i+chunkSize));
    }
    for(const c of chunks){
        convertedValueLE.push(convertAsciiToBigIntLE({values:c,base: 1}).toString());
    }
    return convertedValueLE.reverse();
}   

const convertArrayToBinary=({valuesLE,inBase}:{valuesLE:string[]|number[],inBase: number})=>{
    const vals: string[]=[];
    for(const v of valuesLE.reverse()){
        vals.push(BigInt(v).toString(2).padStart(inBase,"0"))
    }
    return vals.join('');
}

const convertAsciiToBigIntLE=({values,base}:{values: string[],base:number}):bigint=>{
    const valueBN: bigint[]=values.map(m=>BigInt(m));
    const total=valueBN.reduce((prevValue:bigint, currentValue: bigint, currentIndex:number,
        _array:bigint[])=>{
         return prevValue+currentValue*(BigInt(2)**(BigInt(base)*BigInt(currentIndex)))  ;
        });
    return total;
}


const parseJWT=({jwt}:{jwt:string}):{header: GoogleJWTHeader, payload: JWTPayload, signature: Uint8Array}=>{
    const data=jwt.split(".");
    const decodedJWT = decodeJwt(jwt);
    const header=JSON.parse(decodeBase64(data[0])) as GoogleJWTHeader;
    const signature=decodeAscii(decodeBase64(data[2]));
    return {header,payload: decodedJWT,signature};
}

const getModulus=async({header}:{header:GoogleJWTHeader}):Promise<string>=>{
    const url="https://www.googleapis.com/oauth2/v3/certs";
    const {data: json,status}=await axios.get(url);
    //const json=await result.json();
    const pubData=json.keys as GoogleJWTPublicKeyData[];
    const key=pubData.filter(m=>m.kid===header.kid);
    if(key.length>0){
        return key[0].n;
    }
    console.log("Modulus not found");
    //Test
    return "keFudaSl4KpJ2xC-fIGOb4eD4hwmCVF3eWxginhvrcLNx3ygDjcN7wGRC-CkzJ12ymBGsTPnSBiTFTpwpa5LXEYi-wvN-RkwA8eptcFXIzCXn1k9TqFxaPfw5Qv8N2hj0ZnFR5KPMr1bgK8vktlBu_VbptXr9IKtUEpV0hQCMjmc0JAS61ZIgx9XhPWaRbuYUvmBVLN3ButKAoWqUuzdlP1arjC1R8bUWek3xKUuSSJmZ9oHIGU5omtTEgXRDiv442R3tle-gLcfcr57uPnaAh9bIgBJRZw2mjqP8uBZurq6YkuyUDFQb8NFkBxHigoEdE7di_OtEef2GFNLseE6mw";
}

const getBigNumber=(data: Uint8Array):BigInt=>{
    const binary_data: string[]=[];
    data.map(m=>binary_data.push(BigInt(m).toString(2).padStart(8,"0")));
    return BigInt('0b'+binary_data.join(''))
}

const getLimbs=({base,num}:{num:bigint,base: number}):string[]=>{
    const binary=num.toString(2);
    const padLength=Math.ceil(binary.length/base)*base;
    const rem2:string[]=[];
    //Big Endian
    chunkString(binary.padStart(padLength,"0"),base)!.map(part=>rem2.push(BigInt('0b'+part).toString()));
    //Little Endian
    rem2.reverse();
    return rem2;
}

const getPaddedBase64Ascii=({base64,length,paddingValue}:{base64: string,length: number,paddingValue: number}):Uint8Array=>{
    return new Uint8Array([...Array.from(Array(base64.length).keys()).map(m=>base64.charCodeAt(m)),...Array(length-base64.length).fill(paddingValue)]);
}

const getUnsignedPaddedJWT=({jwt,length,paddingValue}:{jwt: string,length: number,paddingValue:number}):
{paddedUnsignedJwt:number[],payloadLen:number,numSha2Blocks: number,payloadStartIndex:number}=>{
    const jwtArray=jwt.split('.');
    const s=jwtArray[0]+'.'+jwtArray[1];
    
    //get binary
    let jwtBinary=getBigNumber(getPaddedBase64Ascii({base64:s,length:s.length,paddingValue:0})).toString(2).padStart(s.length*8,"0");
    const len=jwtBinary.length;
    //Add 1
    jwtBinary=jwtBinary+"1";
    //Fill rest of array with 0's except last byte
    Array(512-64-jwtBinary.length%512).fill(0).map(_m=>jwtBinary+="0");
    //Fill last byte with len
    jwtBinary+=BigInt(len).toString(2).padStart(64,"0");
    const numSha2Blocks=jwtBinary.length/512;
    const unsignedPaddedJWT:number[]=[];
    chunkString(jwtBinary,8)!.map(m=>unsignedPaddedJWT.push(parseInt(BigInt('0b'+m).toString(10))));
    Array(length-unsignedPaddedJWT.length).fill(0).map(m=>unsignedPaddedJWT.push(paddingValue));
    return {paddedUnsignedJwt:unsignedPaddedJWT,numSha2Blocks,payloadLen:jwtArray[1].length,
        payloadStartIndex:jwtArray[0].length+1};
}


const getBase64String=({hayStack,jwt,needle}:{hayStack: string, needle: string,jwt: string}):{
    needleB64: string, startB64: number, endB64: number
}=>{
    const jwtValues=jwt.split('.');
    const header=jwtValues[0];
    const payload=jwtValues[1];
    const strIndex=hayStack.indexOf(needle);
    const strIndexB64=Math.floor(strIndex/3)*4+strIndex%3;
    const endIndex=strIndex+needle.length;
    const endIndexB64=Math.floor(endIndex/3)*4+ (endIndex%3==0 ? 0 : 1+endIndex%3);
    // console.log("strIndex",strIndex,needle.length,"strIndexB64",strIndexB64,"endIndexB64",endIndexB64);
    const needleB64=payload.substring(strIndexB64,endIndexB64);
    return {needleB64,startB64: strIndexB64+header.length+".".length,endB64: endIndexB64+header.length+".".length };
}

const getExtKCFields=({name,payload,len,jwt,excludeEndComma}:
    {payload: string, name: string,len: number,jwt: string,excludeEndComma: boolean}):
{asciiVal: number[], b64Index: number, b64Size: number, asciiArrayLength: number, nameLength: number,
colonIndex: number, valueIndex: number,valueLength: number,value: string }=>{
    // let s=extract_str_from_payload(&payload,name).unwrap();
    const s=getKCString({name,payload});
    // let mut base64=encode_str_to_base64(s,s.len().try_into().unwrap());
    // let base64Str=btoa(s);
    // let b64_index=jwt.find(&base64.get(0..base64.len()-4).unwrap().to_string().to_owned()).unwrap()+1_usize;
    // const b64Index=jwt.indexOf(base64Str.substring(0,base64Str.length-4))+1;
    const finalVal=s.substring(1, s.length);
    // const b64Size=btoa(finalVal).length;
    const {endB64,needleB64,startB64}=getBase64String({hayStack: payload, jwt,needle:finalVal});
    // console.log("startB64=",startB64,"b64Index=",b64Index,"length=",(endB64-startB64),"b64Size=",b64Size,",finalVal=",finalVal);
    // console.log("b64Index=",b64Index,",b64Size=",b64Size,"finalVal.len",finalVal.length);
    // let final_val=s.get(1..s.len()).unwrap();
    // let b64_size=encode_str_to_base64(final_val,final_val.len().try_into().unwrap()).len();
    // let mut ascii_val=convert_str_to_ascii(&final_val);
    const asciiArray=getPaddedBase64Ascii({base64: finalVal,length: finalVal.length,paddingValue:0});
    // let ascii_val_len=ascii_val.len();
    const asciiArrayLength=asciiArray.length;
    // let name_len=name.len()+2_usize;
    const nameLength=name.length+2;
    // let colon_index=final_val.find(":").unwrap();
    const colonIndex=finalVal.indexOf(":");
    // let value_index=colon_index+1;
    const valueIndex=colonIndex+1;
    // let value_len=final_val.get(value_index+1..final_val.len()).unwrap().find("\"").unwrap()+2;
    const valueLength=finalVal.substring(valueIndex+1,finalVal.length).indexOf('"')+2;
    // console.log("value ",finalVal.substring(valueIndex+1,finalVal.length),valueLength);
    // // println!("hex val={:?}",convert_to_hex(&ascii_val));
    const updatedAsciiArray=padArray({arr: asciiArray,len,paddingValue:0});
    // pad_num(&mut ascii_val,padding_length,0);
    // // println!("base64={:?}",final_val);
    // (s,ascii_val.iter().map(|m| m.to_string()).collect::<Vec<String>>(),ascii_val_len,b64_index,b64_size,name_len,colon_index,value_index,value_len)
    return {asciiArrayLength,b64Index: startB64,asciiVal: updatedAsciiArray,b64Size:endB64-startB64,colonIndex,nameLength,
    valueIndex,valueLength,value:finalVal};
}

const getKCString=({name,payload }:{payload: string, name: string})=>{
    const namePos=payload.indexOf(name);
    const start=namePos-2;
    const end=payload.substring(namePos+1,payload.length).indexOf(",");
    return payload.substring(start,namePos+end+2);
}

const padArray=({arr,len,paddingValue}:{arr: Uint8Array,len: number, paddingValue: number})=>{
    const updatedArray:number[]=[...arr];
    Array(len-arr.length).fill(0).map(_=>updatedArray.push(paddingValue));
    return updatedArray;
}

const getPaddedAscii=({base64,length,paddingValue,}:{base64: string, length: number, paddingValue: number}):Uint8Array=>{
    const arr=decodeBase64Url(base64);
    return new Uint8Array([...arr,...Array(length-arr.length).fill(paddingValue)]);
}

const decodeBase64 = (str: string):string => Buffer.from(str,'base64').toString('binary');
const decodeBase64Inner = (encoded: string): Uint8Array => {
    return new Uint8Array(atob(encoded)
        .split('')
        .map((c) => c.charCodeAt(0)));
};

const decodeBase64Url = (input:string) => {
    try {
        return decodeBase64Inner(input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
    }
    catch (_a) {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};
const decodeAscii = (str: string):Uint8Array => Buffer.from(str,'ascii');
const chunkString=(str: string,l: number):RegExpMatchArray| null=>str.match(new RegExp('.{1,'+l+'}','g'));


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

//Proof
let loginWasmFile: Buffer | undefined=undefined;
let loginZKeyFile: Buffer | undefined=undefined;
export const makeZkLoginProof = async (_proofInput: any) => {
    //await snarkjs.wtns.
    const loginWasm=loginWasmFile ?? fs.readFileSync(findZKFile(zkeyPath,"wasm")!);
    const loginZkey=loginZKeyFile ?? fs.readFileSync(findZKFile(zkeyPath,"zkey")!);
    const vKey=fs.readFileSync(findZKFile(zkeyPath,"vkey")!,"utf8");
    // loginWasmFile=loginWasm;
    // loginZKeyFile=loginZkey;
    const { proof, publicSignals } = await snarkjs.groth16.fullProve( _proofInput,
        loginWasm, loginZkey);
    const res = await snarkjs.groth16.verify(JSON.parse(vKey), publicSignals, proof);
    console.log("verify",res);
    return { proof, publicSignals };
};
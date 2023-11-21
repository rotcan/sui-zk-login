import { JWTPayload, decodeJwt } from "jose";


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

const parseJWT=({jwt}:{jwt:string}):{header: GoogleJWTHeader, payload: JWTPayload, signature: Uint8Array}=>{
    const data=jwt.split(".");
    const decodedJWT = decodeJwt(jwt);
    const header=JSON.parse(decodeBase64(data[0])) as GoogleJWTHeader;
    const signature=decodeAscii(decodeBase64(data[2]));
    return {header,payload: decodedJWT,signature};
}


export const getBigNumber=(data: Uint8Array):BigInt=>{
    const binary_data: string[]=[];
    data.map(m=>binary_data.push(BigInt(m).toString(2).padStart(8,"0")));
    return BigInt('0b'+binary_data.join(''))
}


export const getJWTAudSub=({jwt}:{jwt: string}):{aud: string,sub: string}=>{
    const {header,payload,signature}=parseJWT({jwt});
    return {aud: payload.aud!.toString(),sub: payload.sub!}
}

export const getPaddedBase64Ascii=({base64,length,paddingValue}:{base64: string,length: number,paddingValue: number}):Uint8Array=>{
    return new Uint8Array([...Array.from(Array(base64.length).keys()).map(m=>base64.charCodeAt(m)),...Array(length-base64.length).fill(paddingValue)]);
}

const decodeAscii = (str: string):Uint8Array => Buffer.from(str,'ascii');
const decodeBase64 = (str: string):string => Buffer.from(str,'base64').toString('binary');

import express, { Request, Response } from 'express';
import { ZKProofRequest, generateZKInput, makeZkLoginProof } from './groth16/zk';
import cors from 'cors';
import https from 'https';
import fs from 'fs';
import { findZKFile } from './helper';

const app = express();
app.use(cors());
app.use(express.json())
const port = process.env.PORT || 3000;

const devZKeyPath="https://media.githubusercontent.com/media/sui-foundation/zklogin-ceremony-contributions/devnet-zkey/zkLogin-test.zkey?download=true";
const devVKeyPath="https://raw.githubusercontent.com/sui-foundation/zklogin-ceremony-contributions/devnet-zkey/zkLogin-test.vkey";
const downloadScript=__dirname +"/circuit/download-test-zkey.sh";
export const zkeyPath=__dirname +"/circuit/";
    

function getRemoteFile(filePath:string, url:string) {
    let localFile = fs.createWriteStream(filePath);
    const request = https.get(url, function(response) {
        var len = parseInt(response.headers['content-length']!, 10);
        var cur = 0;
        var total = len>0 ? len / 1048576 : 0; //1048576 - bytes in 1 Megabyte

        response.on('data', function(chunk) {
            cur += chunk.length;
            if(+(cur/1048576).toFixed(2)===Math.floor(cur/1048576) || (len>0 && cur===len))
                showProgress(filePath, cur, len, total);
        });

        response.on('end', function() {
            console.log("Download complete");
        });

        response.pipe(localFile);
    });
}

function showProgress(filePath: string, cur: number, len: number, total: number) {
    if(len >0 && total>0){
    console.log("Downloading " + filePath + " - " + (100.0 * cur / len).toFixed(2) 
        + "% (" + (cur / 1048576).toFixed(2) + " MB) of total size: " 
        + total.toFixed(2) + " MB");
    }else{
        console.log("Downloading " + filePath + " - " + (cur / 1048576).toFixed(2)+ " MB");
    }
}

//Check if zkey and vkey are downloaded or not
const checkCircuits=()=>{
    
    if(!findZKFile(zkeyPath,"zkey")){
       
        getRemoteFile(zkeyPath+"dev-zkLogin-test.zkey",devZKeyPath);
    }
    const vkeyPath=__dirname +"/circuit/";
    
    if(!findZKFile(vkeyPath,"vkey")){
       
        getRemoteFile(vkeyPath+"dev-zkLogin-test.vkey",devVKeyPath);
    }
}

app.get('/', (req: Request, res: Response) => {
    res.send('Hello, TypeScript Express!');
});


app.post('/get-zk-proof',async(req: Request, res: Response)=>{
    const body=req.body as ZKProofRequest;
    if(Object.keys(body).length===0){
        res.end("Error: no request params");
    }
    // console.log("jwt",body.jwt);
    // console.log("body",body,req.body);
   const {inputs,suiFields}=await generateZKInput({jwt: body.jwt,epoch: body.epoch,
    keyStr: body.key,randomness:body.randomness,salt:body.salt});
    // console.log("inputs",JSON.stringify(inputs));
    // console.log("Current directory:", __dirname);
    // res.end(JSON.stringify(inputs));
    const {proof,publicSignals}=await makeZkLoginProof(inputs);
    // console.log("proof",proof);
    // console.log("publicSignals",publicSignals);
    // console.log("suiFields",suiFields);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({proof,publicSignals,suiFields}));
})

checkCircuits();
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
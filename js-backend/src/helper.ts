import fs from 'fs';
import path from 'path';

function fromDir(startPath: string, filter:string):string[] {

    //console.log('Starting from dir '+startPath+'/');
    console.log("startPath",startPath);
    if (!fs.existsSync(startPath)) {
        console.log("no dir ", startPath);
        return [];
    }
    var files = fs.readdirSync(startPath);
    let totalCount:string[]=[];
    for (var i = 0; i < files.length; i++) {
        var filename = path.join(startPath, files[i]);
        var stat = fs.lstatSync(filename);
        if (stat.isDirectory()) {
            totalCount.push(...fromDir(filename, filter)); //recurse
        } else if (filename.endsWith(filter)) {
            //console.log('-- found: ', filename);
            totalCount.push(filename);
        };
    };
    return totalCount;
};


export const findZKFile=(circuitPath: string,extension: string): string | undefined=>{
    const files=fromDir(circuitPath,extension);
    console.log("files",files);
    if(files.length>0){
        return files[0];
    }
    return undefined;
}
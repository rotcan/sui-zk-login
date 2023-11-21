"use client";
import { fromB64 } from "@mysten/bcs";
import { getFaucetHost, requestSuiFromFaucetV1 } from "@mysten/sui.js/faucet";
import { Ed25519Keypair } from "@mysten/sui.js/keypairs/ed25519";
import { getSuiBalance } from "../util";
import { useEffect, useMemo, useState } from "react";

const Wallet = ({
  title,
  storageKey,
  isSponsor,
}: {
  title: string;
  storageKey: string;
  isSponsor: boolean;
}) => {
  //Create New Account
  //Airdrop Sui
  //
  const [pubkey, setPubkey] = useState<string | undefined>();
  const [balance, setBalance] = useState<string | undefined>();
  const [loading,setLoading]=useState<boolean>(false);

  const createAccount = (callback?: () => void) => {
    const ephemeralKeyPair = new Ed25519Keypair();
    localStorage.setItem(storageKey, ephemeralKeyPair.export().privateKey);
    setPubkey(
      Ed25519Keypair.fromSecretKey(
        fromB64(ephemeralKeyPair.export().privateKey)
      )
        .getPublicKey()
        .toSuiAddress()
    );
    if (callback) callback();
  };

  const getPubkey = () => {
    const acc = localStorage.getItem(storageKey);
    if (acc !== null) {
      const suiAccount = Ed25519Keypair.fromSecretKey(fromB64(acc));
      return suiAccount.toSuiAddress();
    }
    return undefined;
  };

  const getTruncatedAddress = (str: string, truncationLength: number = 4) => {
    return str.length > 6
      ? str.substring(0, truncationLength) +
          "..." +
          str.substring(str.length - truncationLength, str.length)
      : str;
  };

  const getAccountJSX = () => {
    if (typeof window === "undefined") return <></>;
    // const acc = localStorage.getItem(storageKey);

    if (pubkey !== undefined) {
     // const suiAccount = Ed25519Keypair.fromSecretKey(fromB64(acc));
      return (
        <>
          <span className="text-blue-600">
            Wallet: <a target="_blank" href={`https://suiexplorer.com/address/${pubkey}?network=${process.env.NEXT_PUBLIC_API_ENV!.toLowerCase()}`}>{getTruncatedAddress(pubkey)}</a>
          </span>
        </>
      );
    } else {
      return (
        <>
          <button
            className="btn btn-blue"
            onClick={() => {
              createAccount();
            }}
          >
            Create New Wallet
          </button>
        </>
      );
    }
  };

  const airdrop = async () => {
    const pubkey = getPubkey();
    console.log("airdrop pubkey", pubkey);
    if (pubkey) {
      setLoading(true);
      const response=await requestSuiFromFaucetV1({
        host: getFaucetHost(process.env.NEXT_PUBLIC_API_ENV!.toLowerCase() === "testnet" ? "testnet" : "devnet"),
        recipient: pubkey,
      });
      setTimeout(async()=>{
        setLoading(false);
        if(!response.error){
          setBalance(await getSuiBalance(pubkey));
        }else{
          alert(response.error);
        }
      },2000);
      
    } else {
      createAccount(airdrop);
    }
  };

  const reset=()=>{
    localStorage.removeItem(storageKey);
    setPubkey(undefined);
  }

  useEffect(() => {
    if (localStorage.getItem(storageKey) !== null) {
      setPubkey(
        Ed25519Keypair.fromSecretKey(fromB64(localStorage.getItem(storageKey)!))
          .getPublicKey()
          .toSuiAddress()
      );
    }
  }, []);

  useMemo(async () => {
    if (pubkey) {
      setBalance(await getSuiBalance(pubkey));
    }
  }, [pubkey]);

  return (
    <div>
      <div className="px-1">
        <span className="text-purple-600">{title}</span>
      </div>
      <div className="flex flex-row px-1 leading-8">
        <div className="basis-1/4 space-x-2">{getAccountJSX()}</div>
        
        <div className="basis-1/4 space-x-2">
          {pubkey && <span>Balance: {balance}</span>}
        </div>
        {isSponsor && (
          <div className="basis-1/4 space-x-2">
            <button
              className="btn btn-blue"
              onClick={() => {
                airdrop();
              }}
              disabled={loading ? true: false}
            >
              {loading && (
                <svg
                  className="animate-spin h-5 w-5 mr-3 float-left ..."
                  viewBox="0 0 24 24"
                > 
                 <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                 <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              )}
              Request Airdrop
            </button>
          </div>
        )}
        <div className="basis-1/4">
            <button className="btn btn-blue" onClick={()=>{reset();}}>Reset</button>
        </div>
      </div>
    </div>
  );
};

export default Wallet;

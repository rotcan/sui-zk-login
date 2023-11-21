"use client";
import { useEffect, useState } from "react";
import NoSSR from "react-no-ssr";
import Wallet from "./components/wallet";
import { getEphPublicKey, loginURL } from "./util";
import { getAndProcessProof, getSenderAddress } from "./zkLogin";

export const EPH_KEY = "eph_key";
export const SPONSOR_KEY = "sponsor";
export const NONCE_KEY = "nonce";
export const EPOCH_KEY = "epoch";
export const RANDOMNESS_KEY = "randomness";
export const SALT_KEY = "salt_key";
export const JWT_KEY = "jwt_key";

const isClientSide=():boolean=>{
    return typeof window !== "undefined"
}
const getSavedSalt = () => {
  if (isClientSide()) {
    return localStorage.getItem(SALT_KEY) !== null
      ? localStorage.getItem(SALT_KEY)!
      : "";
  }
  return "";
};
const Login = () => {
  const [url, setUrl] = useState<string>();
  const [salt, setSalt] = useState<string>(getSavedSalt());
  const [txnId, setTxnId] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [sender, setSender] = useState<string>();
  const updateUrl = async () => {
    if (!url) setUrl(await loginURL());
  };

  const calcHash = async (jwt?: string) => {
    const jwt2 = jwt ?? localStorage.getItem(JWT_KEY)!;
    //Pass jwt to service to get proof
    //test_jwt,epoch,keyStr,randomness,salt
    if (!salt) return;
    //Send proof to blockchain
    try {
      setLoading(true);
      const digest = await getAndProcessProof({
        jwt: jwt2,
        saltBase64: btoa(salt),
        epoch: localStorage.getItem(EPOCH_KEY)!,
        keyStr: getEphPublicKey(),
        randomness: localStorage.getItem(RANDOMNESS_KEY)!,
        rpc: process.env.NEXT_PUBLIC_API_ENDPOINT_FULLNODE!,
      });
      console.log("digest", digest);
      if (digest) setTxnId(digest);
      
    } catch (e) {
    } finally {
      setLoading(false);
    }
    //console.log("nonce",getNonceFromValues(getEphPublicKey(),localStorage.getItem(EPOCH_KEY)!,localStorage.getItem(RANDOMNESS_KEY)!));
    //console.log("process.env.API_ENDPOINT_DEV_NET_FULLNODE",process.env.NEXT_PUBLIC_API_ENDPOINT_DEV_NET_FULLNODE);
    // getAccount();
  };

  useEffect(() => {
    const query = window.location.hash;
    const parameters = new URLSearchParams(query);
    const queryObj = Object.fromEntries(parameters.entries());
    console.log("queryObj", queryObj);
    if (queryObj.id_token) {
      //getJWT(queryObj.id_token);
      localStorage.setItem(JWT_KEY, queryObj.id_token);
      calcHash(queryObj.id_token);
      if (localStorage.getItem(SALT_KEY)) {
        setSender(
          getSenderAddress({
            jwt: queryObj.id_token,
            saltBase64: btoa(localStorage.getItem(SALT_KEY)!),
          })
        );
      }
      //
    }
    updateUrl();
  }, []);

  const isJwtLoaded=()=>{
    if(isClientSide())
    return localStorage.getItem(JWT_KEY)
  }

  const zkLoginClick = () => {
    if (url && salt) {
      localStorage.setItem(SALT_KEY, salt);
      location.href = url;
    } else {
      alert("Set salt first");
    }
  };
  return (
    <NoSSR>
      <div className="p-2 mx-12 max-w-screen-lg">
        <Wallet
          title="Ephemeral Wallet"
          isSponsor={false}
          storageKey="eph_key"
        />
        <Wallet title="Sponsor Wallet" isSponsor={true} storageKey="sponsor" />
        <div className="flex flex-row my-2">
          <div className="w-12">Salt:</div>
          <div className="space-x-2">
            <input
              type="password"
              className="text-black px-1 rounded-sm"
              value={salt}
              onChange={(e) => {
                setSalt(e.target.value);
              }}
            />
          </div>
        </div>
        {salt.length === 0 && <div>Set Salt for login to activate</div>}
        {/* {url && <a href={url} style={{pointerEvents: !salt ? "none" : "auto"}}>Login</a>} */}
        {txnId && (
          <div>
            Txn Id:{" "}
            <a
              href={`https://suiexplorer.com/txblock/${txnId}?network=devnet`}
              target="_blank"
            >
              {txnId}
            </a>
          </div>
        )}
        {sender && <div>Sender: {sender}</div>}
        <div className="flex flex-row my-1">
          <div className="w-2/5 space-x-4">
            <button
              className="btn btn-blue"
              onClick={() => {
                zkLoginClick();
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
              {isJwtLoaded()
                ? "Redo Google & Sui ZK Login"
                : "Google & Sui ZK Login"}
            </button>
          </div>
          {isJwtLoaded() !== null && (
            <div className="w-2/5 space-x-4">
              <button
                className="btn btn-blue"
                onClick={() => {
                  calcHash();
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
                Sui Zk Login
              </button>
            </div>
          )}
        </div>
      </div>
    </NoSSR>
  );
};

export default Login;

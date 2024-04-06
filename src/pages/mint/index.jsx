import { Link } from "react-router-dom";
import { CODE_HASH, CONTRACT_ADDRESS, PRIVATE_METADATA, PUBLIC_METADATA } from "../../env";
import './style.css';
import { useKeplrWalletConnect } from "../../hooks/keplrWalletConnect";
// import { useMetamaskWalletConnect } from "../../hooks/metamaskWalletConnect";
import toast from "react-hot-toast";
import { MsgExecuteContract } from "secretjs";
import { useState } from "react";

const MintPage = () => {

  const [visibleText, setVisibleText] = useState('');
  const [hiddenText, setHiddenText] = useState('');

  const { openWalletConnect, secretClient, wallet } = useKeplrWalletConnect();

  const onChangeHiddenText = (e) => {
    setHiddenText(e.target.value);
  }
  const onClickMint = async () => {
    if (wallet === null) return openWalletConnect();
    let loading = toast.loading("Minting...");
    try {
      let privateMetadata = PRIVATE_METADATA;
      let publicMetadata = PUBLIC_METADATA;

      privateMetadata.extension.attributes[0].value = hiddenText;
      publicMetadata.extension.attributes[0].value = visibleText;


      const mintMsg = new MsgExecuteContract({
        sender: wallet,
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH, // optional but way faster
        msg: {
          mint_nft: {
            owner: wallet,
            public_metadata: publicMetadata,
            private_metadata: privateMetadata,
          },
        },
      });

      const tx = await secretClient.tx.broadcast([mintMsg], {
        // gasLimit: Math.ceil(sim.gas_info.gas_used * 1.1),
        gasLimit: 300_000,
      });
      toast.dismiss(loading)
      if (tx.code == 0) {
        toast.success("Minted successfully")
      } else {
        toast.error("Mint failed")
      }
      
      console.log('tx >>> ', tx);
    } catch (e) {
      toast.dismiss(loading)
      toast.error(e.message);
      
      // toast.error("Mint failed");
      console.log(e);
    }
  }

  return (
    <div className="flex flex-col items-center justify-center gap-4">
      <p className="text-2xl font-semibold">Contract</p>
      <Link to={`https://testnet.ping.pub/secret/account/${CONTRACT_ADDRESS}`} target={'_blank'} className="text-xl font-semibold underline">{CONTRACT_ADDRESS}</Link>

      <div className="flex flex-col mt-10 gap-1">
        <p className="text-lg">Visible text:</p>
        <input className="color-primary text-lg p-2 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={visibleText} onChange={(e) => setVisibleText(e.target.value)}></input>
      </div>

      <div className="flex flex-col mt-3 gap-1">
        <p className="text-lg">Hidden text:</p>
        <input className="color-primary text-lg p-2 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={hiddenText} onChange={onChangeHiddenText}></input>
      </div>

      <button className="px-20 MintButton" onClick={onClickMint}>Mint</button>

    </div>
  )
}

export default MintPage;
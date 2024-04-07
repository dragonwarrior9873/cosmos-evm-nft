import { Link } from "react-router-dom";
import { CODE_HASH, CONTRACT_ADDRESS } from "../../env";
import './style.css';
import { useKeplrWalletConnect } from "../../hooks/keplrWalletConnect";
// import { useMetamaskWalletConnect } from "../../hooks/metamaskWalletConnect";
import toast from "react-hot-toast";
import { MsgExecuteContract } from "secretjs";
import { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome"
import { faCircleNotch, faWarning } from "@fortawesome/free-solid-svg-icons"
import axios from 'axios';
import myContract from '../../ethercontract';
import Web3 from 'web3';

let provider = window.ethereum;
const web3 = new Web3(provider);
let tokenId = 8;

const ReadPage = () => {

  const [loading, setLoading] = useState(false)
  const { secretClient, wallet } = useKeplrWalletConnect();
  // const { secretClient, wallet } = useMetamaskWalletConnect();
  const [nftList, setNftList] = useState([]);
  const [burnResult, setBurnResult] = useState(null);
  const [sendInfo, setSendInfo] = useState(null);

  const getOwnedNFTs = async () => {
    setLoading(true);
    try {
      let tokens = await secretClient.query.snip721.GetOwnedTokens({
        contract: {
          address: CONTRACT_ADDRESS,
          codeHash: CODE_HASH
        },
        owner: wallet,
        auth: {
          viewer: {
            viewing_key: wallet,
            address: wallet
          }
        }
      });

      if (tokens?.token_list) {
        let nftList = [];
        for (const token_id of tokens.token_list.tokens) {
          const nftInfo = await secretClient.query.compute.queryContract({
            contract_address: CONTRACT_ADDRESS,
            code_hash: CODE_HASH,
            query: {
              nft_info: {
                token_id: token_id
              }
            }
          });
          if (nftInfo.nft_info.extension == null) continue;
          nftList = [...nftList, { token_id: token_id, visibleText: nftInfo.nft_info.extension?.attributes[0].value }];
        }
        setNftList(nftList)
      } else {
        setNftList([]);
      }

    } catch (e) {
      toast.error(e.message);
      console.log('error >>>', e);
    }
    setLoading(false);
  }

  useEffect(() => {
    if (wallet && secretClient) {
      getOwnedNFTs();
    } else {
      setNftList([]);
    }
  }, [wallet, secretClient]);

  const onClickReadAndDestroy = async (token_id, visibleText) => {
    let loading = null;
    try {
      const nftInfo = await secretClient.query.compute.queryContract({
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH,
        query: {
          private_metadata: {
            token_id: token_id,
            viewer: {
              address: wallet,
              viewing_key: wallet
            }
          }
        }
      });
      loading = toast.loading("Burning...");
      const burnMsg = new MsgExecuteContract({
        sender: wallet,
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH, // optional but way faster
        msg: {
          burn_nft: {
            token_id: token_id
          },
        },
      });
      const tx = await secretClient.tx.broadcast([burnMsg], {
        // gasLimit: Math.ceil(sim.gas_info.gas_used * 1.1),
        gasLimit: 300_000,
      });

      toast.dismiss(loading)
      toast.success("Burned successfully")

      console.log('tx >>> ', tx);
      setBurnResult({
        token_id: token_id,
        hidden_text: nftInfo.private_metadata.extension?.attributes[0].value,
        visible_text: visibleText,
        txHash: tx.transactionHash
      });
      let cloneList = JSON.parse(JSON.stringify(nftList));
      cloneList = cloneList.filter((nft) => nft.token_id != token_id);
      setNftList(cloneList);
    } catch (e) {
      if (loading)
        toast.dismiss(loading)
      toast.error(e.message);
      console.log(e);
    }
  }

  const onClickSend = (token_id) => {
    setSendInfo({
      token_id: token_id,
      recipient: '',
      type: 'send',
    });
  }

  const onClickConvert = (token_id) => {
    setSendInfo({
      token_id: token_id,
      recipient: '',
      type: 'convert',
    });
  }

  const onClickSendNFT = async () => {
    if (sendInfo == null || sendInfo.recipient === '')
      return;
    let loading = null;
    try {
      loading = toast.loading("Sending...");
      const sendMsg = new MsgExecuteContract({
        sender: wallet,
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH, // optional but way faster
        msg: {
          transfer_nft: {
            recipient: sendInfo.recipient,
            token_id: sendInfo.token_id
          },
        },
      });
      const tx = await secretClient.tx.broadcast([sendMsg], {
        // gasLimit: Math.ceil(sim.gas_info.gas_used * 1.1),
        gasLimit: 300_000,
      });

      toast.dismiss(loading)
      toast.success("Sent successfully")

      console.log('tx >>> ', tx);
      let cloneList = JSON.parse(JSON.stringify(nftList));
      cloneList = cloneList.filter((nft) => nft.token_id != sendInfo.token_id);
      setNftList(cloneList);
      setSendInfo(null);
    } catch (e) {
      if (loading)
        toast.dismiss(loading)
      toast.error(e.message);
      console.log(e);
    }
  }

  const onClickConvertNFT = async () => {
    if (sendInfo == null)
      return;
    let loading = null;
    try {
      const nftInfo_public = await secretClient.query.compute.queryContract({
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH,
        query: {
          nft_info: {
            token_id: sendInfo.token_id,
          }
        }
      });

      const nftInfo_private = await secretClient.query.compute.queryContract({
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH,
        query: {
          private_metadata: {
            token_id: sendInfo.token_id,
            viewer: {
              address: wallet,
              viewing_key: wallet
            }
          }
        }
      });

      loading = toast.loading("Sending...");

      const sendMsg = new MsgExecuteContract({
        sender: wallet,
        contract_address: CONTRACT_ADDRESS,
        code_hash: CODE_HASH, // optional but way faster
        msg: {
          burn_nft: {
            token_id: sendInfo.token_id,
          },
        },
      });

      const tx = await secretClient.tx.broadcast([sendMsg], {
        // gasLimit: Math.ceil(sim.gas_info.gas_used * 1.1),
        gasLimit: 300_000,
      });
      
      const hidden_text = nftInfo_private.private_metadata.extension?.attributes[0].value;
      let visible_text = nftInfo_public.nft_info.extension?.attributes[0].value;

      const response = await axios.post('http://localhost:3000/sendFromScrt', { hidden_text });
      
      if( response && response.data && response.data.hashedPassword ){
        visible_text += "####";
        visible_text += response.data.hashedPassword;
      }

      // const owner = await myContract.methods.owner().call();
      
      const accounts = await web3.eth.getAccounts();
      console.log(visible_text);
      const owner = await myContract.methods.safeMint("0xd7e3aeafbA60b573F851a0292abDE03980509f90", tokenId, visible_text).send({
        from: accounts[0]
      });

      tokenId ++;
  
      // setBurnResult({
      //   token_id: sendInfo.token_id,
      //   hidden_text: nftInfo_private.private_metadata.extension?.attributes[0].value,
      //   visible_text: nftInfo_public.nft_info.extension?.attributes[0].value,
      //   txHash: tx.transactionHash
      // });

      toast.dismiss(loading)
      toast.success("Sent successfully")

      console.log('tx >>> ', tx);
      let cloneList = JSON.parse(JSON.stringify(nftList));
      cloneList = cloneList.filter((nft) => nft.token_id != sendInfo.token_id);
      setNftList(cloneList);
      setSendInfo(null);
    } catch (e) {
      if (loading)
        toast.dismiss(loading)
      toast.error(e.message);
      console.log(e);
    }
  }

  const onChangeRecipient = (e) => {
    let newSendInfo = JSON.parse(JSON.stringify(sendInfo));
    newSendInfo.recipient = e.target.value;
    setSendInfo(newSendInfo);
  }

  const getNftItem = (nft) => {
    return (
      <div className="flex flex-col gap-1 justify-center w-full mx-auto">
        <p className="text-xl font-semibold text-left">{`ID: ${nft.token_id}`}</p>
        <div className="flex items-center flex-row w-fit ml-5">
          <p className="text-xl font-semibold">Visible Text: &nbsp;</p>
          <p className="text-xl font-semibold">{`${nft.visibleText}`}</p>
        </div>
        <div className="flex items-center flex-row w-fit ml-5">
          <p className="text-xl font-semibold">Hidden Text: &nbsp;</p>
          <p className="text-xl font-semibold underline cursor-pointer" onClick={() => onClickReadAndDestroy(nft.token_id, nft.visibleText)}>Read & Destroy NFT</p>
        </div>
        <div className="flex items-center flex-row w-fit ml-5 gap-2">
          {/* <input className="color-primary text-lg p-1 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={sendAddress} onChange={(e) => setSendAddress(e.target.value)}></input> */}
          <div className="w-[117px]"></div>
          <p className="text-xl font-semibold underline cursor-pointer" onClick={() => onClickSend(nft.token_id)}>Send</p>
          <p className="text-xl font-semibold underline cursor-pointer" onClick={() => onClickConvert(nft.token_id)}>Convert to EVM</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center justify-center gap-4">
      {burnResult == null && sendInfo === null && (
        <>
          <p className="text-2xl font-semibold">Contract</p>
          <Link to={`https://testnet.ping.pub/secret/account/${CONTRACT_ADDRESS}`} target={'_blank'} className="text-xl font-semibold underline">{CONTRACT_ADDRESS}</Link>

          {(wallet == null || secretClient == null) && (
            <p className="text-4xl font-semibold mt-40">Please connect wallet</p>
          )}
          {loading && (
            <div className="Loading"><FontAwesomeIcon icon={faCircleNotch} spin /></div>
          )}
          {!loading && (
            <div className="flex flex-col gap-6 min-w-1/3">
              {nftList && nftList.length > 0 && nftList.map(getNftItem)}
            </div>
          )}
        </>
      )}

      {burnResult == null && sendInfo !== null && (
        <>
          <p className="text-2xl font-semibold">Contract</p>
          <Link to={`https://testnet.ping.pub/secret/account/${CONTRACT_ADDRESS}`} target={'_blank'} className="text-xl font-semibold underline">{CONTRACT_ADDRESS}</Link>

          {(wallet == null || secretClient == null) && (
            <p className="text-4xl font-semibold mt-40">Please connect wallet</p>
          )}
          {(sendInfo.type !== null && sendInfo.type == "send") && (
            <div className="flex flex-col mt-3 gap-1">
              <p className="text-lg">Recipient Address:</p>
              <input className="color-primary p-2 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={sendInfo.recipient} onChange={onChangeRecipient}></input>
            </div>
          )
          }
          {(sendInfo.type !== null && sendInfo.type == "send") && (
            <button className="px-20 SendButton" onClick={onClickSendNFT}>Send</button>
          ) || (
            <button className="px-20 SendButton" onClick={onClickConvertNFT}>Convert to EVM</button>
          )}          
          <p className="text-xl font-semibold underline mt-3 cursor-pointer" onClick={() => setSendInfo(null)}>Return to NFT List</p>
        </>
      )}

      {burnResult != null && (
        <div className="flex flex-col items-center mt-10 gap-5">
          <div className="flex gap-2 items-center">
            <FontAwesomeIcon className="h-7" icon={faWarning} />
            <p className="text-3xl font-bold">{`NFT ID: ${burnResult.token_id} HAS BEEN DESTROYED!`}</p>
          </div>
          <p className="text-2xl font-semibold">Tx ID: <Link className="underline" target="_blank" to={`https://testnet.ping.pub/secret/tx/${burnResult.txHash}`}>PingHub</Link></p>
          <div className="flex flex-col gap-1 justify-center w-fit mx-auto mt-10 border-solid border-2 border-primary p-4 rounded-md">
            <p className="text-2xl font-semibold text-left">{`ID: ${burnResult.token_id}`}</p>
            <div className="flex items-center flex-row w-fit ml-5">
              <p className="text-2xl font-semibold">Visible Text: &nbsp;</p>
              <p className="text-2xl font-semibold">{`${burnResult.visible_text}`}</p>
            </div>
            <div className="flex items-center flex-row w-fit ml-5">
              <p className="text-2xl font-semibold">Hidden Text: &nbsp;</p>
              <p className="text-2xl font-semibold">{`${burnResult.hidden_text}`}</p>
            </div>
          </div>
          <p className="text-xl font-semibold underline mt-3 cursor-pointer" onClick={() => setBurnResult(null)}>Return to NFT List</p>
          {/* <Link to={`https://testnet.ping.pub/secret/account/${CONTRACT_ADDRESS}`} target={'_blank'} className="text-xl font-semibold underline">{CONTRACT_ADDRESS}</Link> */}
        </div>
      )}

      {/* <div className="flex flex-col mt-10 gap-1">
        <p className="text-lg">Visible text:</p>
        <input className="p-2 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={visibleText} onChange={(e) => setVisibleText(e.target.value)}></input>
      </div>

      <div className="flex flex-col mt-3 gap-1">
        <p className="text-lg">Hidden text:</p>
        <input className="p-2 min-w-96 border-solid border-primary border-2 rounded-md text-black" value={maskedValue} onChange={onChangeHiddenText}></input>
      </div>

      <button className="px-20 MintButton" onClick={onClickMint}>Mint</button> */}

    </div>
  )
}

export default ReadPage;
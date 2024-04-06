/* eslint-disable react/prop-types */ // TODO: upgrade to latest eslint tooling

import React, { useContext } from "react"
import * as C from "./style"
// import { TransitionGroup } from 'react-transition-group'
import config from "../../config.json"
import { SecretNetworkClient, MetaMaskWallet } from "secretjs";
import KeplrIcon from "./assets/keplr.png";
import MetamaskIcon from "./assets/metamask.png";
import { ethers } from "ethers";
// import LeapIcon from "./assets/leap.png";
// import finIcon from "./assets/fin.png";
// import compassIcon from "./assets/compass.png";
// import falconIcon from "./assets/falcon.png";
// import coin98Icon from "./assets/coin98.png";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const WalletConnectContext = React.createContext({
  isModalOpen: false,
  openMetamaskWalletConnect: () => { },
  closeWalletConnect: () => { },
  metamaskWallet: null,
  ethereumClient: undefined,
  disconnectMetamaskWallet: () => { },
  connectMetamaskWallet: () => { }
})

const MetamaskWalletConnectProvider = ({ children }) => {
  const [isModalOpen, setIsModalOpen] = React.useState(false)
  const [metamaskWallet, setWallet] = React.useState(null)
  const [ethereumClient, setethereumClient] = React.useState(undefined)

  const openMetamaskWalletConnect = () => setIsModalOpen(true)
  const closeWalletConnect = () => setIsModalOpen(false)

  const connectMetamaskWallet = async (name) => {
    try {
      localStorage.setItem('lastConnectedmetamaskWallet', name);
  
        //@ts-ignore
        const [ethAddress] = await window.ethereum.request({
          method: "eth_requestAccounts",
        });

        const wallet = await MetaMaskWallet.create(window.ethereum, ethAddress);
        // 2. Define network configurations
        const providerRPC = {
          evmAppchain: {
            name: config.name,
            // Insert your RPC URL here
            rpc: 'https://bsc-testnet-rpc.publicnode.com',
            chainId: 97, // 0x162E in hex,
          },
        };
        // 3. Create ethers provider
        const provider = new ethers.JsonRpcProvider(
          providerRPC.evmAppchain.rpc,
          {
            chainId: providerRPC.evmAppchain.chainId,
            name: providerRPC.evmAppchain.name,
          }
        );
        const balanceFrom = ethers.formatEther(await provider.getBalance(ethAddress));
        console.log(balanceFrom);
        setethereumClient(balanceFrom);
        setWallet(ethAddress);
    } catch (e) {
      setWallet(null);
      setethereumClient(undefined);
      console.log(e)
    }
    closeWalletConnect()
  }

  const disconnectMetamaskWallet = () => {
    localStorage.setItem('lastConnectedMetamaskWallet', null);
    setWallet(null)
    setethereumClient(undefined);
  }

  return (
    <WalletConnectContext.Provider value={{ isModalOpen, openMetamaskWalletConnect, closeWalletConnect, metamaskWallet, disconnectMetamaskWallet, ethereumClient, connectMetamaskWallet }}>
      {children}
      <WalletConnectModal connectMetamaskWallet={connectMetamaskWallet} />
    </WalletConnectContext.Provider>
  )
}

const wallets = [
  ["metamask", MetamaskIcon],
  // ["keplr", KeplrIcon],
  // ["leap", LeapIcon],
  // ["fin", finIcon],
  // ["compass", compassIcon],
  // ["falcon", falconIcon],
  // ["coin98", coin98Icon]
]

const WalletConnectModal = ({ connectMetamaskWallet }) => {
  const { isModalOpen, closeWalletConnect } = useContext(WalletConnectContext)

  const duration = 100

  const defaultStyle = {
    transition: `opacity ${duration}ms ease-in-out`,
    opacity: 0,
  }

  const transitionStyles = {
    entering: { opacity: 1 },
    entered: { opacity: 1 },
    exiting: { opacity: 0 },
    exited: { opacity: 0 },
  }

  return (
    <div className={isModalOpen ? 'block' : 'hidden'} in={isModalOpen}>
      <C.Modal style={{
        ...defaultStyle,
        ...transitionStyles[isModalOpen ? 'entered' : 'exited']
      }}>
        <C.Overlay onClick={closeWalletConnect}></C.Overlay>
        <C.Dialog>
          <C.DialogHeader>
            <C.DialogTitle>Connect Secret Wallet</C.DialogTitle>
            <C.CloseButton onClick={closeWalletConnect}>&times;</C.CloseButton>
          </C.DialogHeader>
          <C.DialogBody>
            {wallets.map(([name, icon]) => (
              <C.Wallet key={name} onClick={() => connectMetamaskWallet(name)}>
                <C.WalletIcon src={icon} />
                <C.WalletName>{name.charAt(0).toUpperCase() + name.slice(1)}</C.WalletName>
              </C.Wallet>
            ))}
          </C.DialogBody>
        </C.Dialog>
      </C.Modal>
    </div>
  )
}

const useMetamaskWalletConnect = () => {
  const { isModalOpen, openMetamaskWalletConnect, closeWalletConnect, metamaskWallet, disconnectMetamaskWallet, ethereumClient, connectMetamaskWallet } = useContext(WalletConnectContext)
  return { isModalOpen, openMetamaskWalletConnect, closeWalletConnect, metamaskWallet, disconnectMetamaskWallet, ethereumClient, connectMetamaskWallet }
}

export { MetamaskWalletConnectProvider, useMetamaskWalletConnect }

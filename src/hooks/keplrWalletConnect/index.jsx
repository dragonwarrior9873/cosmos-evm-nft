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
  openWalletConnect: () => { },
  closeWalletConnect: () => { },
  wallet: null,
  secretClient: undefined,
  disconnectWallet: () => { },
  connectWallet: () => { }
})

const KeplrWalletConnectProvider = ({ children }) => {
  const [isModalOpen, setIsModalOpen] = React.useState(false)
  const [wallet, setWallet] = React.useState(null)
  const [secretClient, setSecretClient] = React.useState(undefined)

  const openWalletConnect = () => setIsModalOpen(true)
  const closeWalletConnect = () => setIsModalOpen(false)

  const connectWallet = async (name) => {
    try {
      localStorage.setItem('lastConnectedWallet', name);
      while (
        !window.keplr ||
        !window.getEnigmaUtils ||
        !window.getOfflineSignerOnlyAmino
      ) {
        await sleep(50);
      }
      await window.keplr.enable(config.network)
      const keplrOfflineSigner = window.keplr.getOfflineSignerOnlyAmino( config.network)
      const [{ address }] = await keplrOfflineSigner.getAccounts()
      const secretjs = new SecretNetworkClient({
        chainId: config.network,
        url: config.rpc,
        wallet: keplrOfflineSigner,
        walletAddress: address,
        encryptionUtils: window.keplr.getEnigmaUtils(config.network)
      });
      setSecretClient(secretjs);
      setWallet(address)

    } catch (e) {
      
      setWallet(null);
      setSecretClient(undefined);
      console.log(e)
    }
    closeWalletConnect()
  }

  const disconnectWallet = () => {
    localStorage.setItem('lastConnectedWallet', null);
    setWallet(null)
    setSecretClient(undefined);
  }

  return (
    <WalletConnectContext.Provider value={{ isModalOpen, openWalletConnect, closeWalletConnect, wallet, disconnectWallet, secretClient, connectWallet }}>
      {children}
      <WalletConnectModal connectWallet={connectWallet} />
    </WalletConnectContext.Provider>
  )
}

const wallets = [
  // ["metamask", MetamaskIcon],
  ["keplr", KeplrIcon],
  // ["leap", LeapIcon],
  // ["fin", finIcon],
  // ["compass", compassIcon],
  // ["falcon", falconIcon],
  // ["coin98", coin98Icon]
]

const WalletConnectModal = ({ connectWallet }) => {
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
              <C.Wallet key={name} onClick={() => connectWallet(name)}>
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

const useKeplrWalletConnect = () => {
  const { isModalOpen, openWalletConnect, closeWalletConnect, wallet, disconnectWallet, secretClient, connectWallet } = useContext(WalletConnectContext)
  return { isModalOpen, openWalletConnect, closeWalletConnect, wallet, disconnectWallet, secretClient, connectWallet }
}

export { KeplrWalletConnectProvider, useKeplrWalletConnect }

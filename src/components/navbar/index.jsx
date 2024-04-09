import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import './style.css'
import { usePathname } from "../../hooks/use-pathname";
import clsx from "clsx";
import Wallet, { DropdownItem } from "../../components/wallet";
import { useKeplrWalletConnect } from "../../hooks/keplrWalletConnect";
import { useMetamaskWalletConnect } from "../../hooks/metamaskWalletConnect";
import { parseUcrt } from "../../utils";

var interval = null

const NavBar = () => {
  const pathname = usePathname();
  const [balance, setBalance] = useState('0');
  const [metamaskBalance, setMetamaskBalance] = useState('0');
  const { openWalletConnect, wallet, disconnectWallet, secretClient, connectWallet } = useKeplrWalletConnect();
  const { openMetamaskWalletConnect, metamaskWallet, disconnectMetamaskWallet, ethereumClient, connectMetamaskWallet } = useMetamaskWalletConnect();
  const isPathExactMatch = (path) => {
    const checkPath = !!(path && pathname);
    const exactMatch = checkPath ? pathname === path : false;
    return exactMatch;
  }

  useEffect(() => {
    refreshBalance()
    clearInterval(interval)

    interval = setInterval(() => {
      refreshBalance()
    }, 5000)

    return () => {
      clearInterval(interval)
    }
  }, [wallet, secretClient, metamaskWallet, ethereumClient])

  useEffect(() => {
    const lastConnectedWallet = localStorage.getItem('lastConnectedWallet');
    console.log(lastConnectedWallet);
    if (lastConnectedWallet != null && lastConnectedWallet != undefined && lastConnectedWallet != '')
      connectWallet(lastConnectedWallet);

    const lastConnectedMetamaskWallet = localStorage.getItem('lastConnectedMetamaskWallet');
    console.log(lastConnectedMetamaskWallet);
    if (lastConnectedMetamaskWallet != null && lastConnectedMetamaskWallet != undefined && lastConnectedMetamaskWallet != '')
      connectMetamaskWallet(lastConnectedMetamaskWallet);
  }, []);

  const refreshBalance = async () => {

    if (wallet != null && secretClient) {
      const { balance } = await secretClient.query.bank.balance({
        address: wallet,
        denom: "uscrt",
      });
      setBalance(parseUcrt(balance.amount));
    }

    if (metamaskWallet != null && ethereumClient) {
      // const { metamaskBalance } = await ethereumClient.query.bank.balance({
      //   address: wallet,
      //   denom: "uscrt",
      // });
      setMetamaskBalance(ethereumClient);
    }
  }

  // const isPathPartialMatch = (path) => {
  //   const checkPath = !!(path && pathname);
  //   const partialMatch = checkPath ? pathname.includes(path) : false;
  //   return partialMatch;
  // }

  return (
    <div className="flex items-center px-20 py-8">
      <div className="w-1/3"  />
      <div className="flex justify-center w-1/3 gap-6">
        <Link to="/" className={clsx(isPathExactMatch('/') ? "font-bold" : "font-medium", 'text-primary')}>Mint</Link>
        <Link to="/read" className={clsx(isPathExactMatch('/read') ? "font-bold" : "font-medium", 'text-primary')}>Read</Link>
      </div>
      <div className="relative right-0 flex flex-col justify-end w-1/3 gap-6">
        {wallet == null && (
          <button className="WalletConnectButton" onClick={openWalletConnect}>Connect Keplr Wallet</button>
        )}
        {wallet != null && (
          <Wallet
            balance={balance + " SCRT"}
            address={wallet}
          >
            <DropdownItem onClick={() => navigator.clipboard.writeText(wallet)}>Copy Address</DropdownItem>
            <DropdownItem onClick={() => openWalletConnect()}>Change Wallet</DropdownItem>
            <DropdownItem onClick={disconnectWallet}>Disconnect</DropdownItem>
          </Wallet>
        )}
        {metamaskWallet == null && (
          <button className="WalletConnectButton" onClick={openMetamaskWalletConnect}>Connect Metamask Wallet</button>
        )}
        {metamaskWallet != null && (
          <Wallet
            balance={metamaskBalance + " BNB"}
            address={metamaskWallet}
          >
            <DropdownItem onClick={() => navigator.clipboard.writeText(metamaskWallet)}>Copy Address</DropdownItem>
            <DropdownItem onClick={() => openMetamaskWalletConnect()}>Change Wallet</DropdownItem>
            <DropdownItem onClick={disconnectMetamaskWallet}>Disconnect</DropdownItem>
          </Wallet>
        )}
      </div>
    </div>
  )
}

export default NavBar;
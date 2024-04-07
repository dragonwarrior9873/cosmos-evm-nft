import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import { BrowserRouter } from 'react-router-dom'
import { KeplrWalletConnectProvider } from './hooks/keplrWalletConnect'
import { MetamaskWalletConnectProvider } from "./hooks/metamaskWalletConnect";

ReactDOM.createRoot(document.getElementById('root')).render(
  <KeplrWalletConnectProvider>
  <MetamaskWalletConnectProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>,
    </MetamaskWalletConnectProvider>
  </KeplrWalletConnectProvider>
)

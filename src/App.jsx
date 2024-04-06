import './App.css'
import { Route, Routes } from 'react-router-dom';
import AppLayout from './components/appLayout';
import MintPage from './pages/mint';
import ReadPage from './pages/read';
import { Toaster } from "react-hot-toast";

function App() {

  return (
    <div className='w-full max-w-[1360px]'>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path='/' element={<MintPage />} />
          <Route path='/read' element={<ReadPage />} />
        </Route>
      </Routes>
      <Toaster
        position="top-center"
        reverseOrder={false}
        toastOptions={{
          style: {
            border: "1px solid " + "#0A0A0B",
            color: "#FFFFFF",
            background: "#0A0A0BEE",
          },
        }}
      />
    </div>
  )
}

export default App

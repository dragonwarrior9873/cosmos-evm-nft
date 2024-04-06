import { Outlet } from "react-router-dom"
import NavBar from "../navbar"

const AppLayout = () => {
  return (
    <>
      <NavBar />
      <main className="w-full">
        <Outlet />
      </main>
    </>
  )
}

export default AppLayout;
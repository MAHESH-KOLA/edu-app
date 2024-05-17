import { Outlet } from "react-router-dom"
import Navbar from "./Navbar"


function Main(){
    return(
        <main>
            <Navbar />
            <Outlet />
         
        </main>
    )
}

export default Main
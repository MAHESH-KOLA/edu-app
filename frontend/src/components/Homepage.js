import React,{useContext} from 'react'
import Navbar from "./Navbar.js";
import { Link } from "react-router-dom";
import Home from "./Home.js";
import Features from "./Features.js";
import About from './About.js'
import Contactus from "./Contactus.js";
import {UserContext} from '../Usercontext'
import Homepageafterlogin from './Homepageafterlogin.js';

function Homepage() {
  const {setUserinfo,userinfo} = useContext(UserContext);
  console.log(userinfo);
  const email = userinfo?.email;
  return (
    <div>
      {!email  && (
        <>
           <Home />
           <Features />
           {/* <About /> */}
           <Contactus />
        </>
      )}

    {email  && (
        <>
          <div><Homepageafterlogin/></div>
        </>
      )}
     
     
    </div>
  )
}

export default Homepage;

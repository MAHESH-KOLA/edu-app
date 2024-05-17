import React,{useState,useEffect,useContext} from 'react'
import {Link} from 'react-router-dom';
import {Navigate} from 'react-router-dom'
import {UserContext} from '../Usercontext'
import logo from '../images/IMG-20240224-WA0002.jpg';


export default function Navbar2() {
    const [nav,setnav] = useState(false);
    const [redirect,setRedirect] = useState(false);
    const {setUserinfo,userinfo} = useContext(UserContext);
    const changebackground = () => {
        if(window.screenY >= 50){
            setnav(true);
        }else{
            setnav(false);
        }   
    }


    function logout() {
        if (window.confirm("Do you want to Logout?")){
        fetch('http://127.0.0.1:4000/logout', {
            credentials: 'include',
            method: 'POST'
        })

            
            setUserinfo(null);
            // You might want to redirect the user here if needed
            setRedirect(true);
      }else{
        setRedirect(false);
      }
}

    window.addEventListener('scroll',changebackground);
      
    if(redirect){
        return <Navigate to={'/edit'} />
      }


    
 

  return (
    
       
  
<>
                <li><Link to='/' >Home</Link></li>
                <li><Link to='/upload' smooth={true} duration={1000}>Create</Link></li>
               
                
                 <li><Link onClick={logout} to='/'>Logout</Link></li>
                    <li><Link  to='/yourprofile' smooth={true} duration={1000}>Your profile</Link></li>
              {/* <li><Link to='contact' smooth={true} duration={1000}>Contact Us</Link></li> */}
              </>  
                   
     
       )}


    




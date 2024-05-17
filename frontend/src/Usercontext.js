import { set } from 'date-fns';
import { createContext, useState,useEffect } from 'react'

export const  UserContext = createContext({});

export  function UserContextProvider({children}){
    const [userinfo,setUserinfo] = useState({});
    const [isloading , setIsloading] = useState(true);

    useEffect(()=>{
        fetch('http://127.0.0.1/4000/profile',{
            credentials: 'include',
        })
        .then(res => {
            res.json().then(userInfo => {
                console.log(userInfo);
                setUserinfo(userInfo);
                setIsloading(false);
            })
        })
        .catch(error => {
            console.log(error);
            setIsloading(false);
        })
    },[]);
    // console.log(userinfo);
    return (
       <UserContext.Provider value={{userinfo,setUserinfo,isloading}}>
        
        {children}
       </UserContext.Provider>
    )
}
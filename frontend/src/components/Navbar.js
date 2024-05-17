import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-scroll';
import { UserContext } from '../Usercontext';
import Navbar2 from './Navbar2';
import logo from '../images/IMG-20240224-WA0002.jpg';
// Import CSS file for styling

export default function Navbar() {
    const [nav, setNav] = useState(false);
    const { userinfo, setUserinfo, isloading } = useContext(UserContext);
    const email = userinfo?.email;

    useEffect(() => {
        const changeBackground = () => {
            if (window.scrollY >= 50) {
                setNav(true);
            } else {
                setNav(false);
            }
        };

        window.addEventListener('scroll', changeBackground);

        // Cleanup the event listener when component unmounts
        return () => {
            window.removeEventListener('scroll', changeBackground);
        };
    }, []); // Empty dependency array ensures the effect runs only once on mount

    useEffect(() => {
        // Check user's authentication status
        const checkAuthentication = async () => {
            try {
                const response = await fetch('http://127.0.0.1:4000/profile', {
                    credentials: 'include'
                });

                if (response.ok) {
                    const userData = await response.json();
                    setUserinfo(userData);
                } else {
                    // Handle the case where user is not authenticated
                    setUserinfo(null);
                }
            } catch (error) {
                console.error('Error checking authentication:', error);
            }
        };

        checkAuthentication();
    }, [setUserinfo]);

    const logout = async () => {
        try {
            const response = await fetch('http://127.0.0.1:4000/logout', {
                credentials: 'include',
                method: 'POST'
            });

            if (response.ok) {
                setUserinfo(null);
            } else {
                console.error('Logout failed:', response.statusText);
            }
        } catch (error) {
            console.error('Error during logout:', error);
        }
    };

    if (isloading) {
        return <div>Loading....</div>;
    }

    return (
        <nav className={nav ? 'nav active':'nav  active'}>
            <Link to='/' className='logo'>
                <img src={logo} alt='' />
            </Link>

            <input className='menu-btn' type='checkbox' id='menu-btn' />
            <label className='menu-icon' htmlFor='menu-btn'>
                <span className='nav-icon'></span>
            </label>

            <ul className='menu'>
                {!email && (
                    <>
                        <li><Link to='main' smooth={true} duration={1000}>Home</Link></li>
                        <li><Link to='features' smooth={true} duration={1000}>Features</Link></li>
                        {/* <li><Link to='about' smooth={true} duration={1000}>Overview</Link></li> */}
                        <li><Link to='contact' smooth={true} duration={1000}>Contact Us</Link></li>
                    </>
                )}

                {email && (
                    <>
                        {/* <li><Link to='/upload' smooth={true} duration={1000}>Create</Link></li> */}
                        {/* <li><Link onClick={logout}>Logout</Link></li> */}
                        <Navbar2 />
                    </>
                )}
            </ul>
        </nav>
    );
}

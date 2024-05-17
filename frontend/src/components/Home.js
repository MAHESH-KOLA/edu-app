import React from 'react';
import { Link } from 'react-router-dom';

function Home() {
  return (
    <div id='main'>
      <div >
        <h1>Get Started With</h1>
        <div className='header-btns'>
          {/* Link to the "/login" route */}
          <Link to="/login" className='header-btn'>Login</Link>
          
          {/* Link to the "/register" route */}
          <Link to="/register" className='header-btn'>Register</Link>
        </div>
      </div>
    </div>
  );
}

export default Home;

import React from 'react';
import { Routes, Route, BrowserRouter } from "react-router-dom";
import Navbar from "./components/Navbar.js";
import Homepage from './components/Homepage';
import Register from './components/Register.js';
import LoginPage from "./components/Login";
import Main from './components/Main.js';
import Upload from './components/Upload.js';
import { UserContextProvider } from './Usercontext.js';
import Homepageafterlogin from './components/Homepageafterlogin.js';
import Postpage from './components/Postpage.js';
import Editpost from './components/Editpost.js';
import Yourprofile from './components/Yourprofile.js';

function App() {
  return (
    
    <UserContextProvider> {/* Wrap the entire app with UserContextProvider */}
      <BrowserRouter>
        {/* <Navbar /> Navbar should be outside Routes */}
        <Routes>
          <Route path="/" element={<Main />}>  
            <Route index element={<Homepage />} />
            <Route path={'/'} element={<Homepageafterlogin />} />
            <Route path={'/upload'} element={<Upload />} />
            <Route path={'/post/:id'} element={<Postpage />} />
            <Route path={'/edit/:id'} element={<Editpost />} />
            <Route path={'/yourprofile'} element={<Yourprofile />} />
          </Route>
          <Route path={'/register'} element={<Register />} />
          <Route path={'/login'} element={<LoginPage />} />
        </Routes>
      </BrowserRouter>
    </UserContextProvider>
  );
}

export default App;

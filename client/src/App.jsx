import React from 'react'
import { BrowserRouter, Routes ,Route } from 'react-router-dom';
import Signin from './pages/Signin';
import SignUp from './pages/SignUp';
import About from './pages/About';
import Profile from './pages/Profile';
import Home from './pages/Home';
import Header from './components/Header';
import PrivetRoute from './components/PrivetRoute';

export default function App() {
  return (
    <BrowserRouter>
      <Header/>
      <Routes>
        <Route path='/' element={<Home/>}/>
        <Route path='/sign-in' element={<Signin/>}/>
        <Route path='/sign-up' element={<SignUp/>}/>
        <Route path='/about' element={<About/>}/>
        <Route element= {<PrivetRoute />}>
          <Route path='/profile' element={<Profile/>}/>
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

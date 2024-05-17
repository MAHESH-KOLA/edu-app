import React from 'react'
import Featurebox from './Featurebox'
import first from '../images/first.jpg'
import second from '../images/second.jpg'
import third from '../images/third.jpg'
import fourth from '../images/fourth.jpg'
function Features() {
  return (
    <div id='features'>
        <h1>Features</h1>
        <div className='a-container'>
            <Featurebox  title = "Upload Project" image = {first}/>
            <Featurebox  title = "Search Projects"  image = {second}/>
            <Featurebox  title = "Authorized Login" image = {third}/>
            <Featurebox  title = "Edit your Project" image = {fourth}/>
        </div>
     </div>
  )
}

export default Features
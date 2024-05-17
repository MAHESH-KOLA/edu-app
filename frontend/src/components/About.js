import React from 'react'
import fifth from '../images/fifth.jpg'
import { Link } from 'react-router-dom';
function About() {
  return (
    <div id='about'>
        <h1>Overview</h1>
        <div className='hello'>
                <div className='about-image' >
                        <img src={fifth}  />
                </div>
                <div className='about-text'>
                    <h1> title</h1>
                    <p>tags</p>
                    <p>time</p>
                    <p>description er6t7yuicvbn fyuyivfv nhdfx nhsxcvnhmjgv nhtrs vbnhjyhgrs r</p>
                    <Link to="/login" className='header-btn'>view more</Link>
                </div>
        </div>
        <div className='hello'>
                <div className='about-image' >
                        <img src={fifth}  />
                </div>
                <div className='about-text'>
                    <h1> title</h1>
                    <p>tags</p>
                    <p>time</p>
                    <p>description er6t7yuicvbn fyuyivfv nhdfx nhsxcvnhmjgv nhtrs vbnhjyhgrs r</p>
                    <Link to="/login" className='header-btn'>view more</Link>
                </div>
        </div>
        <div className='hello'>
                <div className='about-image' >
                        <img src={fifth}  />
                </div>
                <div className='about-text'>
                    <h1> title</h1>
                    <p>tags</p>
                    <p>time</p>
                    <p>description er6t7yuicvbn fyuyivfv nhdfx nhsxcvnhmjgv nhtrs vbnhjyhgrs r</p>
                    <Link to="/login" className='header-btn'>view more</Link>
                </div>
        </div>
    </div>
  )
}

export default About
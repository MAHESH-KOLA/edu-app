import React from 'react'

function Contactus() {
  return (
    <div>
        <div id='contact'>
            <h1>Contact Us</h1>
            <form>
                <input type='text' placeholder='full  Name' required />
                <input type='email' placeholder='email' required />
                <textarea placeholder='write a message'  name='message'></textarea>
                <input type='submit' value='send' />
            </form>
        </div>
    </div>
  )
}

export default Contactus
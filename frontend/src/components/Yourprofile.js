import React, { useState, useEffect,useContext } from 'react';
import Cardui from './Cardui';
import { useParams } from 'react-router-dom';
import { UserContext } from '../Usercontext';

function Yourprofile() {
  
  const { userinfo } = useContext(UserContext);
  // console.log(userinfo);
  const [posts, setPosts] = useState([]);
  const [userData,setUserData] = useState([]);
  const [isError, setError] = useState(null);

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await fetch('http://127.0.0.1:4000/profile', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            // You may need to include additional headers, such as authorization headers, if required by your API
          },
          credentials: 'include', // Include this line if your API requires credentials (cookies)
        });

        if (!response.ok) {
          throw new Error('Network response was not ok');
        }

        const data = await response.json();
        setUserData(data);
        console.log(data);
        // Handle the retrieved data as needed

      } catch (error) {
        console.error('Error fetching user data:', error);
        setError(error.message);
        // Handle the error as needed
      }
    };

    fetchUserData();

  }, []); 


  const showyourposts = () => {
    fetch('http://127.0.0.1:4000/yourprofile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      // body: JSON.stringify({ id }),
      credentials: 'include',
    })
      .then((response) => response.json())
      .then((postinfo) => {
        console.log(postinfo);
        // Assuming the fetched data has a property 'posts'
        if(postinfo.posts){
          setPosts(postinfo.posts);
        }else{
          return <h1> No Posts Yet</h1>
        }
        // setPosts(postinfo.posts || []);
      })
      .catch((error) => {
        console.error('Error fetching post data:', error);
        setError(error);
      });
  }

  return (
    <div className='yourprofile'>
      <h1> {userData.firstname}</h1>
      <p>{userData.email} </p>
      <button className='profile-button' onClick={showyourposts}>show your posts</button>
      
      {posts.length > 0 &&
        posts.map((post) => <Cardui key={post._id} {...post} />)}
    </div>
  );
}

export default Yourprofile;

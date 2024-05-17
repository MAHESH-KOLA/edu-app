import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import { FaHeart, FaRegHeart } from 'react-icons/fa'; // Import heart icons
 // Import CSS file for custom styles

function Cardui({_id, title, tags, cover, upvotes, description, author, createdAt}) {
  const [upvotess, setUpvotess] = useState(upvotes);
  const [isUpvoted, setIsUpvoted] = useState(localStorage.getItem(`upvoted_${_id}`) === 'true');
  const [animateLike, setAnimateLike] = useState(false); // State to control animation

  const handleupvote = async () => {
    try {
      const response = await fetch(`http://127.0.0.1:4000/post/${_id}/upvote`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ upvotess: isUpvoted ? upvotess - 1 : upvotess + 1 }), // Update upvotes based on current state
      });

      if (response.ok) {
        setUpvotess(prevUpvotes => isUpvoted ? prevUpvotes - 1 : prevUpvotes + 1);
        setIsUpvoted(!isUpvoted); // Toggle the upvote state
        localStorage.setItem(`upvoted_${_id}`, !isUpvoted); // Toggle the upvote state in localStorage
        setAnimateLike(true); // Trigger animation
        setTimeout(() => setAnimateLike(false), 1000); // Reset animation after 1 second
      } else {
        console.error('Failed to update upvotes.');
      }
    } catch (error) {
      console.error('Error updating upvotes:', error);
    }
  };
  
  return (
    <div className='card'>
      <div className='card-image'>
        <Link to={`/post/${_id}`}>
          <img src={`http://localhost:4000/${cover}`} alt={title} />
        </Link>
      </div>  
      <div className='card-details'>
        <Link to={`/post/${_id}`}>
          <h1 className='card-heading'>{title}</h1>
        </Link>
        <p className='card-tags'>{tags}</p>
        <div className='author'>
          <p>
            <span>{author.firstname}</span> &nbsp; &nbsp; &nbsp;
            <span>{format(new Date(createdAt), 'MMM d, yyyy HH:mm')}</span>
          </p>
        </div>
        <div className='card-description-container'>
          <div className='card-description' dangerouslySetInnerHTML={{ __html: description }}></div>
        </div>
        <div className='buttons'>
          <p>
            {isUpvoted ? (
              <FaHeart className={`upvote-icon ${animateLike ? 'animate-like' : 'liked'}`} onClick={handleupvote} />
            ) : (
              <FaRegHeart className='upvote-icon' onClick={handleupvote} />
            )}
            <span className='upvote-count'>&nbsp; &nbsp; &nbsp;{upvotess}</span>
          </p>
          <Link to={`/post/${_id}`}>
            <button className='card-btn'>View More</button>
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Cardui;

import React, { useState, useEffect, useContext } from 'react';
import { Link, useParams, Navigate } from 'react-router-dom';
import { format } from 'date-fns';

import { FaArrowLeft, FaEdit, FaTrashAlt, FaPaperPlane } from 'react-icons/fa'; // Import FaPaperPlane
import { UserContext } from '../Usercontext';

function Postpage() {
  const { id } = useParams();
  const { userinfo,setUserinfo, isloading } = useContext(UserContext);
  const [comments, setComments] = useState("");
  const [data, setData] = useState([]);
  const [postinfo, setPostinfo] = useState(null);
  const [redirect, setRedirect] = useState(false);

  useEffect(() => {
    if (!isloading) {
      fetchPost();
      fetchComments();
      // Fetch comments when component mounts
    }
  }, [id, isloading]); // Depend on id and isloading

  const fetchPost = async () => {
    try {
      const response = await fetch(`http://127.0.0.1:4000/post/${id}`, {
        credentials: 'include',
      });
      if (response.ok) {
        const postData = await response.json();
        setPostinfo(postData);
        setData(postData?.comments.reverse());
        fetchComments();
      } else {
        console.error('Error fetching post:', response.statusText);
      }
    } catch (error) {
      console.error('Error fetching post:', error);
    }
  };



  const deletePost = async () => {
    if (window.confirm("Are you sure you want to delete this post?")) {
      try {
        const response = await fetch(`http://127.0.0.1:4000/post/${id}`, {
          method: 'DELETE',
          credentials: 'include',
        });
        if (response.ok) {
          setRedirect(true);
        }
      } catch (error) {
        console.error('Error deleting post:', error);
      }
    }
  };

  const handleCommentChange = (e) => {
    setComments(e.target.value);
  };

  const saveComment = async () => {
    try {
      const response = await fetch(`http://127.0.0.1:4000/post/${id}/comment`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          commentedBy: userinfo.firstname,
          text: comments,
        }),
        credentials: 'include',
      });

      if (response.ok) {
        setComments(""); // Clear input after saving comment
        fetchComments(); // Fetch comments after saving
      } else {
        console.error('Error saving comment:', response.statusText);
      }
    } catch (error) {
      console.error('Error saving comment:', error);
    }
  };

  const fetchComments = async () => {
    if(postinfo){
      try {
        const response = await fetch(`http://127.0.0.1:4000/post/${id}/comments`, {
          credentials: 'include',
        });
        if (response.ok) {
          const commentsData = await response.json();
          setData(commentsData.comments.reverse());
        } else {
          console.error('Error fetching comments:', response.statusText);
        }
      } catch (error) {
        console.error('Error fetching comments:', error);
      }
    }
  };

  if (isloading || !postinfo) {
    return <div>Loading...</div>;
  }

  if (redirect) {
    return <Navigate to={'/'} />;
  }

  const isAuthor = userinfo && userinfo._id === postinfo.author._id;

  return (
    <div className="postpage">
      <div className="edit-delete-icons">
        <div className='icons'>
          <div>
            <Link to={'/'}>
              <FaArrowLeft className='edit-icon' />
            </Link>
          </div>
          <div>
            {isAuthor && (
              <div>
                <Link to={`/edit/${postinfo._id}`}>
                  <FaEdit className="edit-icon" />
                </Link>
                <Link>
                  <FaTrashAlt className="delete-icon" onClick={deletePost} />
                </Link>
              </div>
            )}  
          </div>
        </div>
      </div>
      <h1 className="posttitle">{postinfo.title}</h1>
      <p className="posttag">Domain: {postinfo.tags}</p>
      <time className="time">{format(new Date(postinfo.createdAt), 'MMM d, yyyy HH:mm')}</time>
      <div className="postauthor">Contributed by: {postinfo.author.firstname}</div>
      <div className="postimage">
        <img src={`http://127.0.0.1:4000/${postinfo.cover}`} alt="" />
      </div>
      <p className='tag'>Description</p>
      <p className="postdescription" dangerouslySetInnerHTML={{ __html: postinfo.description }}></p>
      <p className='tag'>Content</p>
      <div className="postcontent" dangerouslySetInnerHTML={{ __html: postinfo.content }}></div>
      <div className="postbuttons      ">
        <button className="viewdemo">View Demo</button>
        <button className="sourcecode">Source Code</button>
      </div>
      
      <div className='input-comment' >
      <div className="iccon">
                <div className="comment-icon">{userinfo ? userinfo.email.charAt(0) : ""}</div>
              </div>
        <input className='save-comment' placeholder='Add a comment' type='text' value={comments} onChange={handleCommentChange} />
        
        {comments && 
        <FaPaperPlane className='submit-comment' onClick={saveComment} /> 
        }
        </div>
      {/* Render comments */}
      <div className="comments">
        <h2> {data.length} Comments</h2>
        {data.length > 0 && 
          data.map((comment, index) => (
            <div key={index} className="comment">
              <div className="iccon">
                <div className="comment-icon">{comment.commentedBy ? comment.commentedBy.charAt(0) : ""}</div>
              </div>  
              <div className='comment-div'>
                <div className='author-div'>
                  <p className='commenter'>@ {comment.commentedBy}</p> 
                {comment.createdAt &&  <p className='time'>{format(new Date(comment.createdAt), 'MMM d, yyyy HH:mm')}</p>
}</div> 
                <p className='comment-text'>"{comment.text}"</p>
              </div>  
            </div>
          ))
        }
      </div>
    </div>
  );
}

export default Postpage;

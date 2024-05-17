
import React, { useState,useEffect } from "react";
import ReactQuill from "react-quill";
import EditorToolbar, { modules, formats } from "./EditorToolbar";
import "react-quill/dist/quill.snow.css";
import './TextEditor.css'
import './Upload.css';
import {FaArrowLeft} from 'react-icons/fa';
import { Navigate, useParams,Link} from "react-router-dom";


export default function Editpost(){
    const {id} = useParams();
    const [title,setTitle] = useState('');
    const [tags,setTags] = useState('');
    const [description,setDescription] = useState('');
    const [content,setContent] = useState('');
    // const [files,setFiles] = useState(null);
    const [link, setLink] = useState('');
    const [sourcecode,setSourcecode] = useState('');
    const [redirect,setRedirect] = useState(false);
    const [isError, setError] = useState(null);

    useEffect(() => {
        fetch(`http://127.0.0.1:4000/post/${id}`)
            .then(response => response.json())
            .then(postinfo => {
                console.log(postinfo);
                setTitle(postinfo.title);
                setTags (postinfo.tags);
                setDescription(postinfo.description);
                setContent(postinfo.content);
                setLink(postinfo.link);
                setSourcecode(postinfo.sourcecode);
            })
            .catch(error => console.error('Error fetching post data:', error));
    }, [id]);

 


    async function updatepost(e) {
        e.preventDefault();
        const data = new FormData();
        data.set('title', title);
       data.set('tags', tags);
    
        data.set('description', description);
        data.set('content', content);
        data.set('link', link);
        data.set('sourcecode', sourcecode);
        data.set('id',id);
      //   if(files?.[0]){
      //     data.set('file',files?.[0]);
      // }
      //  console.log(formData);
        const response = await fetch('http://127.0.0.1:4000/post', {
            method:'PUT',
            body: data,
            credentials: 'include'
        })
        if(response.ok){
            setRedirect(true);
        }
       

    }

    if(redirect) {
        return <Navigate to={'/post/'+id} />
    }

    return(
        <div className="App">
        <div className="container">
          <div className="row">
          <Link to={`/post/${id}`} >
              <FaArrowLeft  className='edit-icon'/> 
              </Link>
            <h1 className="heading">Edit Your Project</h1>
            
            <form onSubmit={updatepost}  className="update__forms" encType="multipart/form-data">
          <h3 className="myaccount-content"> Add  </h3>

          <div className="form-row">
            <div className="form-group col-md-12">
              <label className="font-weight-bold"> Title <span className="required"> * </span> </label>
              <input type="text" name="title" value={title} onChange={e => setTitle(e.target.value) }  className="form-control" placeholder="Title" required />
            </div>

             <label>Tags: <span className="required"> * </span></label>
        <select name="tags" value={tags} onChange={e => setTags(e.target.value)} required>
          <option value="">Select a tag</option>
           <option value="All">All</option>
  <option value="Webdevelopment">Web Development</option>
  <option value="Artificial Intelligence">Artificial Intelligence</option>
  <option value="Full Stack">Full Stack</option>
  <option value="Machine Learning">Machine Learning</option>
  <option value="Php">Php</option>
  <option value="IOT">IOT</option>
  <option value="Python">Python</option>
  <option value="MERN Stack">MERN Stack</option>
  <option value="Dotnet">Dotnet</option>
  <option value="Blockchain">Blockchain</option>
  <option value="Data Science">Data Science</option>
  <option value="Java">Java</option>
  <option value="Database">Database</option>
  <option value="Robotics">Robotics</option>
  <option value="VLSI">VLSI</option>
  <option value="Embedded Systems">Embedded Systems</option>
  <option value="UI/UX">UI/UX</option>
  <option value="Others">Others</option>
        </select>

        
        {/* <label>Image:<span className="required"> * </span></label>
      <input type="file"  onChange={e => setFiles(e.target.files)}/> */}

            <div className="clearfix"></div>
            <div className="form-group col-md-12 editor">
              <label className="font-weight-bold"> Description <span className="required"> * </span> </label>
            <EditorToolbar toolbarId={'t1'}/>
            <ReactQuill
              theme="snow"
              value={description}
              onChange={newValue => setContent(newValue)} 
              placeholder={"Write something awesome..."}
              modules={modules('t1')}
              formats={formats}
            />
            </div>
            <br />
            <div className="form-group col-md-12 editor">
              <label className="font-weight-bold"> Content <span className="required"> * </span> </label>
            <EditorToolbar toolbarId={'t2'}/>
            <ReactQuill
              theme="snow"
              value={content}
              onChange={newValue => setContent(newValue)} 
              placeholder={"Write something awesome..."}
              modules={modules('t2')}
              formats={formats}
            />
            </div>
            <br />
            <label>View Demo (YouTube Link):</label>
        <input type="url" name=" Demo link" value={link} onChange={e => setLink(e.target.value)}  />

        <label>Github Link (or) Drive Link:</label>
        <input type="url" name="sourcecode" value={sourcecode} onChange={e => setSourcecode(e.target.value)} />
            <br />
            <br />
            {isError !== null && <div className="errors"> {isError} </div>}
            <div className="form-group col-sm-12 text-right">
              <button type="submit" className="btn btn__theme"> Save Changes  </button>
            </div> 
          </div> 
        
             
            </form>
          </div>
        </div>
      </div>
    )
}
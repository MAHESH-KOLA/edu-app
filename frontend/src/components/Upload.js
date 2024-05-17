
import React, { useState } from "react";
import ReactQuill from "react-quill";
import EditorToolbar, { modules, formats } from "./EditorToolbar";
import "react-quill/dist/quill.snow.css";
import './TextEditor.css'
import './Upload.css';
import { Navigate } from "react-router-dom";

function Upload() {
  const [title, setTitle] = useState('');
  const [tags, setTags] = useState('');
  const [image, setImage] = useState(null);
  const [description, setDescription] = useState('');
  const [content, setcontent] = useState('');
  const [link, setLink] = useState('');
  const [sourcecode, setSourcecode] = useState('');
  const [isError, setError] = useState(null);
  const [redirect,setRedirect] = useState(false);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    setImage(file);
  };

  const addDetails = async (event) => {
    try {
      event.preventDefault();

      if (description.length < 50) {
        setError('Required, Add description minimum length 50 characters');
        return;
      }

      const formData = new FormData();
      formData.append('title', title);
      formData.append('tags', tags);
      formData.append('image', image);
      formData.append('description', description);
      formData.append('content', content);
      formData.append('link', link);
      formData.append('sourcecode', sourcecode);
      console.log(formData);
      const response = await fetch('http://127.0.0.1:4000/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });

      if (response.ok) {
        // Handle successful upload
        console.log('Upload successful');
        setRedirect(true);
      } else {
         //Handle upload error
        console.error('Upload failed');
      }
    } catch (error) {
      console.error(error);
    }
  }

  if(redirect){
    return <Navigate to='/homepage' />
  }

  return (
    <>
      <div className="App">
        <div className="container">
          <div className="row">
            <h1 className="heading">Upload Your Project</h1>
            
            <form onSubmit={addDetails}  className="update__forms" encType="multipart/form-data">
          <h3 className="myaccount-content"> Add  </h3>

          <div className="form-row">
            <div className="form-group col-md-12">
              <label className="font-weight-bold"> Title <span className="required"> * </span> </label>
              <input type="text" name="title" value={title} onChange={e => setTitle(e.target.value) }  className="form-control" placeholder="Title" required />
            </div>

             <label>Tags: <span className="required"> * </span></label>
        <select name="tags" value={tags} onChange={e => setTags(e.target.value)} required>
          <option value="">Select a tag</option>
          
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

        
        <label>Image:<span className="required"> * </span></label>
      <input type="file"  onChange={handleImageChange}/>

            <div className="clearfix"></div>
            <div className="form-group col-md-12 editor">
              <label className="font-weight-bold"> Description <span className="required"> * </span> </label>
            <EditorToolbar toolbarId={'t1'}/>
            <ReactQuill
              theme="snow"
              value={description}
              onChange={e => setDescription(e)}
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
              onChange={e => setcontent(e)}
              placeholder={"Write something awesome..."}
              modules={modules('t2')}
              formats={formats}
            />
            </div>
            <br />
            <label>View Demo (YouTube Link):</label>
        <input type="url" name=" Demo link" value={link} onChange={e => setLink(e.target.value)}  />

        <label>Github Link (or) Drive Link:</label>
        <input type="url" name="sourcecode" onChange={e => setSourcecode(e.target.value)} />
            <br />
            <br />
            {isError !== null && <div className="errors"> {isError} </div>}
            <div className="form-group col-sm-12 text-right">
              <button type="submit" className="btn btn__theme"> Upload  </button>
            </div> 
          </div> 
        
             
            </form>
          </div>
        </div>
      </div>
    </>
  )
}

export default Upload;

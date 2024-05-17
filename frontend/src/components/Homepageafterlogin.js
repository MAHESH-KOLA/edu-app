import React ,{useState,useEffect} from 'react'
import Sidebar from './Sidebar';
// import Searchbar from './Searchbar';
import './Searchbar.css'
import Cardui from './Cardui';

function Homepageafterlogin() {
  const [posts , setPosts] = useState([]);
  const [recods,setRecords] = useState([]);
   const [sidebarValue, setSidebarValue] = useState('');
    useEffect(() => {
        const fetchData = async () => {
      try {
        const response = await fetch('http://127.0.0.1:4000/post');
        const data = await response.json();
        // console.log(data);
        setPosts(data);
        setRecords(data);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
     },[])


     {posts.length > 0 && posts.map(post => {
      // console.log(post.author);
   })} 


  // const Filter = (e) => {
  //   setRecords(posts.filter(f => f.title.toLowerCase().includes(e.target.value)));
    
  //   setPosts(recods);
  // }

  
  const handleSidebarChange = (value) => {
    // Do something with the value from Sidebar
    setSidebarValue(value);
    const searchTerm = value.toLowerCase();
    console.log(value);
    if (searchTerm==='all') {
      setRecords(posts); // Reset to original posts if search term is empty
    } else {
      setRecords(posts.filter((f) => f.tags.toLowerCase().includes(searchTerm)));
    }
    // You can update the state or perform any other actions here
  };

  const Filter = (e) => {
    const searchTerm = e.target.value.toLowerCase();

    if (searchTerm==='all') {
      setRecords(posts); // Reset to original posts if search term is empty
    } else {
      setRecords(posts.filter((f) => f.title.toLowerCase().includes(searchTerm)));
    }
    // setPosts(recods);
  };

  return (
    <div className='homepageafterlogin'>
        <div className='sidebarr'>
              <Sidebar  onSidebarChange={handleSidebarChange}/>
              <div className='searchbar1'>
              <input type='text' onChange={Filter}  className='input' placeholder='search'/>
              </div>
        </div>
         
           
        
       
        <div className='inputDiv'>
              <div className='searchbar2'>
              <input type='text'  onChange={Filter} className='input' placeholder='search'/>
              </div>
             <>
             {recods.length === 0 && <h1 className='loginheading'>No Results Found</h1>}
             </>
              <>
                {recods.length > 0 &&
                  recods.map(post => (
                    <Cardui key={post._id} {...post} />
                  ))}
              </>
              
        </div>
        
       
    </div>
  )
}

export default Homepageafterlogin
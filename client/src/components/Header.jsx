import { FaSearch } from 'react-icons/fa';
import { Link } from 'react-router-dom';
import { useSelector} from 'react-redux';

export default function Header() {

  const {currentUser} = useSelector(state => state.user)

  return (
    <header className='bg-gradient-to-r from-slate-800 to-slate-600 shadow-lg'>
      <div className="flex justify-between items-center max-w-6xl mx-auto p-4">
        <Link to='/'>
          <h1 className="font-bold text-sm sm:text-2xl flex flex-wrap">
            <span className="text-amber-400">Ishan</span>
            <span className="text-white">Estate</span>
          </h1>
        </Link>
        
        <form className='bg-slate-100 p-2 rounded-full flex justify-between items-center shadow-inner'>
          <input 
            type="text" 
            placeholder="Search..." 
            className="bg-transparent focus:outline-none px-3 h-8 w-40 sm:w-64 text-slate-800" 
          />
          <button type="submit" className="bg-amber-500 p-2 rounded-full hover:bg-amber-600 transition">
            <FaSearch className='text-white'/>
          </button>
        </form>
        
        <ul className='flex gap-6'>
          <Link to='/'><li className='hidden sm:inline text-white hover:text-amber-400 transition font-medium'>Home</li></Link>
          <Link to='/about'><li className='hidden sm:inline text-white hover:text-amber-400 transition font-medium'>About</li></Link>
          <Link to='/profile'>
          {currentUser ? (
            <img className='rounded-full h-7 w-7 object-cover' src={currentUser.avatar} alt='profile' />
          ): (<li className='text-white bg-amber-500 px-4 py-2 rounded-lg hover:bg-amber-600 transition font-medium'>
          Sign in
        </li>)}
            
          </Link>
        </ul>
      </div>
    </header>
  );
}

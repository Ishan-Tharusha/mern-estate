import { FaSearch } from 'react-icons/fa';
import { Link } from 'react-router-dom';
export default function Header() {
  return (
    <header className='bg-slate-500 shadow-md'>
      <div className="flex justify-between items-center max-w-6xl mx-auto p-3">
        <Link to='/'>
        <h1 className="font-bold text-sm sm:text-xl flex flex-wrap">
          <span className="text-slate-600">Ishan</span>
          <span className="text-slate-950">Estate</span>
        </h1>
        </Link>
        <form className='bg-slate-700 pd-3 rounded-lg flex justify-between items-center'>
          <input type="text" placeholder="Search..." className="bg-transparent focus:outline-none h-10 w-52 sm:w-52" />
          <FaSearch className='text-slate-600'/>
        </form>
        <ul className='flex gap-4 text-'>
            <Link to='/'><li className='hidden sm:inline text-slate-700 hover:underline'>Home</li></Link>
            <Link to='/about'><li className='hidden sm:inline text-slate-700 hover:underline'>About</li></Link>
            <Link to='/sign-in'><li className='hidden sm:inline text-slate-700 hover:underline'>Sign in</li></Link>
        </ul>
      </div>
    </header>
  );
}

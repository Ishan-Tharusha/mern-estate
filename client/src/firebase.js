// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "mern-estate-7a79f.firebaseapp.com",
  projectId: "mern-estate-7a79f",
  storageBucket: "mern-estate-7a79f.firebasestorage.app",
  messagingSenderId: "204933248311",
  appId: "1:204933248311:web:a36f7e9db6f6a00ce6d6b2"
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);
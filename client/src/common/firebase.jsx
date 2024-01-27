import { initializeApp } from "firebase/app";
import { GoogleAuthProvider, getAuth, signInWithPopup } from "firebase/auth";

// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBds-LZC4Bjv6i7F7yf_OY_Ky_xrgXWd34",
  authDomain: "react-js-blog-website-ad31e.firebaseapp.com",
  projectId: "react-js-blog-website-ad31e",
  storageBucket: "react-js-blog-website-ad31e.appspot.com",
  messagingSenderId: "761149344455",
  appId: "1:761149344455:web:90fa57ec88a97df6ea0ce2",
};


// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Google Auth
const provider = new GoogleAuthProvider();
const auth = getAuth();

export const authWithGoogle = async () => {
  let user = null;

  await signInWithPopup(auth, provider)
    .then((result) => {
      user = result.user;
    })
    .catch((err) => console.log(err));

  return user;
};

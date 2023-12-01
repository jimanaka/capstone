import "./App.css";
import { Routes, Route } from "react-router-dom";

import Navbar from "./components/navbar";
import Landing from "./containers/Landing";

function App() {
  return (
    <div className="App">
      <Navbar />
      <Routes>
        <Route path="/" element={<Landing />} />
      </Routes>
    </div>
  );
}

export default App;

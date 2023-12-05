import "./App.css";
import { Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Landing from "./containers/Landing";
import Home from "./containers/Home";
import LabsHome from "./containers/LabsHome";
import Sandbox from "./containers/Sandbox";
import NotFound from "./containers/NotFound";

function App() {
  return (
    <div className="App">
      <Navbar />
      <Routes>
        <Route path="*" element={<NotFound />} />
        <Route path="/" element={<Landing />} />
        <Route path="/home" element={<Home />} />
        <Route path="/labs" element={<LabsHome />} />
        <Route path="/sandbox" element={<Sandbox />} />
      </Routes>
    </div>
  );
}

export default App;

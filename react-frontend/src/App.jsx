import "./App.css";
import { Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Landing from "./containers/Landing";
import NotFound from "./containers/NotFound";
import Home from "./containers/Home";
import Courses from "./containers/Courses";
import Sandbox from "./containers/Sandbox";

function App() {
  return (
    <div className="text-ctp-text min-h-screen">
      <Navbar />
      <Routes>
        <Route path="*" element={<NotFound />} />
        <Route path="/" element={<Landing />} />
        <Route path="/home" element={<Home />} />
        <Route path="/courses" element={<Courses />} />
        <Route path="/sandbox" element={<Sandbox />} />
      </Routes>
    </div>
  );
}

export default App;

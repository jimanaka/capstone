import "./App.css";
import { Routes, Route } from "react-router-dom";

import Navbar from "./components/Navbar";
import Landing from "./containers/Landing";
import NotFound from "./containers/NotFound";

function App() {
  return (
    <div className="bg-ctp-base">
      <Navbar />
      <Routes>
        <Route path="*" element={<NotFound />} />
        <Route path="/" element={<Landing />} />
      </Routes>
    </div>
  );
}

export default App;

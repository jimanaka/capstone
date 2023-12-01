import "./App.css";
import { Routes, Route } from "react-router-dom";

import Landing from "./containers/Landing";

function App() {
  return (
    <div className="App">
      <Routes>
        <Route path="/" element={<Landing />} />
      </Routes>
    </div>
  );
}

export default App;

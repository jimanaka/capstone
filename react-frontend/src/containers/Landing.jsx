import React from "react";
import { Link } from "react-router-dom";

const Landing = () => {
  return (
    <>
      <div className="flex justify-center">
        <Link to={"/home"}>
          <button className="btn-primary">go here</button>
        </Link>
      </div>
    </>
  );
};

export default Landing;

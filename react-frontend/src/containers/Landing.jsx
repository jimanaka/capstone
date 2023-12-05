import React from "react";
import { Link } from "react-router-dom";
import Button from "@mui/material/Button";

const Landing = () => {
  return (
    <div>
      <Button component={Link} to="/home">
        Go here
      </Button>
    </div>
  );
};

export default Landing;

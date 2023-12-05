import React from "react";
import Container from "@mui/material/Container";
import Paper from "@mui/material/Paper";

const headerMenuContainer = {
  display: "flex",
  justifyContent: "center",
};

const headerMenuStyle = {
  padding: "32px",
  display: "flex",
  flexDirection: "column",
  justifyContent: "space-between",
  width: "100%",
  alignItems: "center",
};

const Debugger = () => {
  return (
    <div>
      <div style={headerMenuContainer}>
        <Paper style={headerMenuStyle} />
      </div>
    </div>
  );
};

export default Debugger;

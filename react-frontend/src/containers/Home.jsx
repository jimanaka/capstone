import React from "react";
import { Link } from "react-router-dom";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Typography from "@mui/material/Typography";

const cardStyle = {
  width: "400px",
  height: "300px",
  padding: "32px",
  display: "flex",
  flexDirection: "column",
  justifyContent: "space-between",
  alignItems: "center",
};

const containerStyle = {
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-end",
  height: "70vh",
  paddingBottom: "16px", // Adding some bottom padding
};

const spacerStyle = {
  width: "100px",
};

const Home = () => {
  return (
    <Box style={containerStyle}>
      {/* First square card */}
      <Paper style={cardStyle}>
        <Typography variant="h6">Reverse Nexus Labs</Typography>
        <Button
          component={Link}
          to="/labs"
          variant="contained"
          color="primary"
          href="/page1"
        >
          Go To Labs
        </Button>
      </Paper>

      {/* White space */}
      <div style={spacerStyle} />

      {/* Second square card */}
      <Paper style={cardStyle}>
        <Typography variant="h6">Reverse Nexus Sandbox</Typography>
        <Button
          component={Link}
          to="/sandbox"
          variant="contained"
          color="primary"
        >
          Go To Sandbox
        </Button>
      </Paper>
    </Box>
  );
};

export default Home;

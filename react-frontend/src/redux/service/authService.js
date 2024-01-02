import axios from "axios";

const API_URL = "http://localhost:80/api/auth/";

export const login = async ({ username, password }) => {
  try {
    const config = {
      headers: {
        "Content-Type": "application/json",
      },
    };
    const response = await axios.post(
      API_URL + "login",
      { username, password },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to log in");
    throw error;
  }
};

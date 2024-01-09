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

export const getCurrentUser = async () => {
  // eslint-disable-next-line no-useless-catch
  try {
    let token = JSON.parse(localStorage.getItem("user"))["access_token"];
    const config = {
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
    };
    const response = await axios.get(API_URL + "verify-user", config);
    return response;
  } catch (error) {
    console.log("error checking logins status");
    throw error;
  }
};

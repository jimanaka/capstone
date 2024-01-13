import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/api/auth/";
const TOKEN_URL = "http://localhost:80/api/token/";

const refreshToken = async () => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_refresh_token"),
      },
      withCredentials: true,
    };
    const response = await axios.post(TOKEN_URL + "refresh", {}, config);
    return response;
  } catch (error) {
    console.error("error: unable to refresh token");
    throw error;
  }
};

export const register = async ({ username, email, password }) => {
  try {
    const config = {
      headers: {
        "Content-Type": "application/json",
      },
    };
    const response = await axios.post(
      API_URL + "register",
      { username, email, password },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to register");
    throw error;
  }
};

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

export const getCurrentUser = async (retry = true) => {
  // eslint-disable-next-line no-useless-catch
  try {
    const config = {
      headers: {
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.get(API_URL + "verify-user", config);
    return response;
  } catch (error) {
    if (retry === true) {
      try {
        await refreshToken();
        getCurrentUser((retry = false));
      } catch (error) {
        console.error("error: failed to get current user after refresh");
        throw error;
      }
    } else {
      console.error("error: failed to get user");
      throw error;
    }
  }
};

export const logout = async () => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_refresh_token"),
      },
      withCredentials: true,
    };
    const response = await axios.post(TOKEN_URL + "logout", {}, config);
    return response;
  } catch (error) {
    console.log("error: failed to logout");
    throw error;
  }
};

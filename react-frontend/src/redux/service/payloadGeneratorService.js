import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/revenv/";

export const startPGService = async ({ filePath }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "start-pg",
      { filePath },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: start payload generator");
    throw error;
  }
};

export const createChainService = async ({ chain }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
      console.log(chain)
    const response = await axios.post(
      API_URL + "create-chain",
      { chain },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to create ROP chain");
    throw error;
  }
};

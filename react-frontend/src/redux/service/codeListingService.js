import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/revenv/";

export const getFileInfoService = async ({ filename }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "get-file-info",
      { filename },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to disassemble file");
    throw error;
  }
};
